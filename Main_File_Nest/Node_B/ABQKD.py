"""
ABQKD.py - Complete BB84 Quantum Key Distribution between Node A (Alice) and Node B (Bob)
========================================================================================

Implements the end-to-end BB84 protocol using Qiskit:
  1. State preparation (Alice: random bits & bases -> qubits)
  2. Quantum channel simulation (attenuation / photon loss & noise)
  3. Measurement (Bob: random bases -> outcomes)
  4. Sifting (public basis reconciliation)
  5. Error estimation (sample disclosure & QBER calculation)
  6. Error correction (Cascade protocol with parity verification)
  7. Verification (hash comparison)
  8. Privacy amplification (Toeplitz matrix hashing)
  9. Key mapping & metrics storage directly in secretQKD.json
"""

import argparse
import hashlib
import hmac
import json
import math
import os
import random
import secrets
import sys
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path

from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator

# Protocol Settings & Thresholds
QBER_THRESHOLD = 0.11        # Maximum tolerable QBER before aborting (11%)
SAMPLE_FRACTION = 0.25       # Fraction of sifted key revealed for error estimation
CASCADE_PASSES = 4           # Standard Cascade error correction passes
EXTRA_PASSES = 12            # Maximum extra passes
EXTRA_CLEAN = 2              # Extra passes with 0 errors required to stop
EXTRA_BLOCK_DIV = 1          # Block divisor for extra passes
VERIFY_BITS = 32             # Bits used for verification hash
SECURITY_BITS = 40           # Safety margin for privacy amplification
MIN_SIFTED = 100             # Minimum required sifted bits
MIN_KEY_BITS = 64            # Minimum key bits after privacy amplification
POLL = 0.05                  # Seconds between message polling checks

# Pre-shared secret for public channel authentication
AUTH_KEY = os.environ.get("QKD_AUTH_KEY", "CSDQKD-Preshared-Auth-Key-2026").encode()

SIMULATOR = AerSimulator()
rng = random.SystemRandom()

DEFAULT_FOLDER = Path(__file__).resolve().parent


class AuthError(Exception):
    pass


class AbortError(Exception):
    pass


# =====================================================================
#  1. Quantum Simulation (Qiskit)
# =====================================================================
def encode_qubit(bit: int, basis: str) -> QuantumCircuit:
    """Encode a classical bit in Z ('Z') or X ('X') basis."""
    qc = QuantumCircuit(1, 1)
    if bit == 1:
        qc.x(0)
    if basis == "X":
        qc.h(0)
    return qc


def measure_qubits(circuits: list[QuantumCircuit], bases: list[str]) -> list[int]:
    """Measure qubits in specified bases using AerSimulator."""
    prepared = []
    for qc, basis in zip(circuits, bases):
        qc = qc.copy()
        if basis == "X":
            qc.h(0)
        qc.measure(0, 0)
        prepared.append(qc)

    if not prepared:
        return []

    try:
        result = SIMULATOR.run(prepared, shots=1, memory=True).result()
        return [int(result.get_memory(i)[0]) for i in range(len(prepared))]
    except Exception:
        out = []
        for qc in prepared:
            out.append(int(SIMULATOR.run(qc, shots=1, memory=True).result().get_memory()[0]))
        return out


def circuit_to_ops(qc: QuantumCircuit) -> list[str]:
    """Serialize circuit gates to list of strings."""
    return [inst.operation.name for inst in qc.data]


def circuit_from_ops(ops: list[str]) -> QuantumCircuit:
    """Reconstruct quantum circuit from serialized gate names."""
    qc = QuantumCircuit(1, 1)
    for name in ops:
        if name not in ("x", "h", "y", "z"):
            raise ValueError(f"Unexpected gate in received qubit: {name!r}")
        getattr(qc, name)(0)
    return qc


def channel_effects(
    qubits: list[QuantumCircuit], loss: float, noise: float
) -> tuple[list[QuantumCircuit | None], int, int]:
    """Simulate lossy and noisy optical fibre channel."""
    out, lost, flipped = [], 0, 0
    for q in qubits:
        if rng.random() < loss:
            out.append(None)
            lost += 1
            continue
        if rng.random() < noise:
            q = q.copy()
            getattr(q, rng.choice(["x", "y", "z"]))(0)
            flipped += 1
        out.append(q)
    return out, lost, flipped


# =====================================================================
#  2. Authenticated Classical Channel
# =====================================================================
class Channel:
    """Message passing channel backed by JSON files with HMAC-SHA256 authentication."""

    def __init__(self, folder: str | Path, timeout: int = 120):
        self.folder = str(folder)
        self.timeout = timeout
        self.session = ""
        os.makedirs(self.folder, exist_ok=True)

    def _path(self, name: str) -> str:
        return os.path.join(self.folder, f"{name}.json")

    def _tag(self, name: str, body: dict) -> str:
        text = f"{self.session}|{name}|" + json.dumps(body, sort_keys=True, separators=(",", ":"))
        return hmac.new(AUTH_KEY, text.encode(), hashlib.sha256).hexdigest()

    def send(self, name: str, obj: dict, auth: bool = True) -> None:
        record = {"body": obj}
        if auth:
            record["tag"] = self._tag(name, obj)
        tmp = self._path(name) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(record, f)
        os.replace(tmp, self._path(name))

    def receive(self, name: str, auth: bool = True) -> dict:
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            self._check_abort()
            try:
                with open(self._path(name), "r", encoding="utf-8") as f:
                    record = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError, PermissionError):
                time.sleep(POLL)
                continue

            if auth and not hmac.compare_digest(record.get("tag", ""), self._tag(name, record["body"])):
                self.abort(f"authentication failed on '{name}'")
                raise AuthError(f"Message '{name}' failed HMAC authentication.")
            return record["body"]

        raise TimeoutError(
            f"Timed out after {self.timeout}s waiting for '{name}.json' in {self.folder}."
        )

    def abort(self, reason: str) -> None:
        self.send("99_abort", {"reason": reason})

    def _check_abort(self) -> None:
        path = self._path("99_abort")
        if not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                record = json.load(f)
            if hmac.compare_digest(record.get("tag", ""), self._tag("99_abort", record["body"])):
                raise AbortError(f"Peer node aborted: {record['body']['reason']}")
        except (json.JSONDecodeError, PermissionError, KeyError, OSError):
            pass

    def clear(self) -> None:
        for f in os.listdir(self.folder):
            if f.endswith(".json") or f.endswith(".tmp"):
                try:
                    os.remove(os.path.join(self.folder, f))
                except OSError:
                    pass


# =====================================================================
#  3. Error Correction: Cascade
# =====================================================================
def parity(bits: list[int], indices: list[int]) -> int:
    return sum(bits[i] for i in indices) & 1


class ParityOracle:
    def __init__(self, chan: Channel):
        self.chan, self.n, self.leaked = chan, 0, 0

    def ask(self, subsets: list[list[int]]) -> list[int]:
        self.chan.send(f"ec_q{self.n:03d}", {"subsets": subsets})
        answers = self.chan.receive(f"ec_a{self.n:03d}")["parities"]
        self.n += 1
        self.leaked += len(answers)
        return answers

    def done(self) -> None:
        self.chan.send(f"ec_q{self.n:03d}", {"done": True})


def serve_parities(chan: Channel, key: list[int]) -> None:
    n = 0
    while True:
        q = chan.receive(f"ec_q{n:03d}")
        if q.get("done"):
            return
        chan.send(f"ec_a{n:03d}", {"parities": [parity(key, s) for s in q["subsets"]]})
        n += 1


def cascade(bob_key: list[int], oracle: ParityOracle, qber: float) -> tuple[list[int], int]:
    n = len(bob_key)
    b = list(bob_key)
    k = min(n, max(4, int(0.73 / max(qber, 0.005))))
    k0 = k
    clean_run = 0
    blocks, alice_par = [], []
    member = [[] for _ in range(n)]
    fixed = 0

    def find_error(block: list[int]) -> int:
        while len(block) > 1:
            left = block[: len(block) // 2]
            if parity(b, left) != oracle.ask([left])[0]:
                block = left
            else:
                block = block[len(block) // 2 :]
        return block[0]

    for p in range(CASCADE_PASSES + EXTRA_PASSES):
        if p >= CASCADE_PASSES:
            if clean_run >= EXTRA_CLEAN:
                break
            k = max(4, k0 // EXTRA_BLOCK_DIV)
        fixed_before = fixed
        order = list(range(n))
        if p > 0:
            rng.shuffle(order)
        ids = []
        for s in range(0, n, k):
            blk = order[s : s + k]
            bid = len(blocks)
            blocks.append(blk)
            for i in blk:
                member[i].append(bid)
            ids.append(bid)
        alice_par.extend(oracle.ask([blocks[bid] for bid in ids]))

        work = [bid for bid in ids if parity(b, blocks[bid]) != alice_par[bid]]
        while work:
            bid = work.pop()
            if parity(b, blocks[bid]) == alice_par[bid]:
                continue
            i = find_error(blocks[bid])
            b[i] ^= 1
            fixed += 1
            for other in member[i]:
                if parity(b, blocks[other]) != alice_par[other]:
                    work.append(other)
        if p >= CASCADE_PASSES:
            clean_run = clean_run + 1 if fixed == fixed_before else 0
        if p < CASCADE_PASSES - 1:
            k = min(n, k * 2)

    return b, fixed


# =====================================================================
#  4. Verification & Privacy Amplification
# =====================================================================
def verify_tag(bits: list[int], session: str) -> str:
    return hashlib.sha256((session + "".join(map(str, bits))).encode()).hexdigest()[: VERIFY_BITS // 4]


def h2(x: float) -> float:
    return 0.0 if x <= 0 or x >= 1 else -x * math.log2(x) - (1 - x) * math.log2(1 - x)


def secure_length(n_key: int, qber: float, sample_size: int, leaked_bits: int) -> tuple[int, float]:
    e_upper = min(0.5, qber + math.sqrt(math.log(1e6) / (2 * sample_size)))
    length = int(n_key * (1 - h2(e_upper)) - leaked_bits - VERIFY_BITS - SECURITY_BITS)
    return length, e_upper


def toeplitz_hash(key: list[int], seed_bits: list[int], out_len: int) -> list[int]:
    n = len(key)
    out = []
    for j in range(out_len):
        row = seed_bits[j : j + n][::-1]
        out.append(sum(k & r for k, r in zip(key, row)) & 1)
    return out


def fingerprint(bits: list[int]) -> str:
    return hashlib.sha256("".join(map(str, bits)).encode()).hexdigest()[:12]


def bits_to_hex(bits: list[int]) -> str:
    """Convert list of bits into a big-endian hex string padded to full bytes."""
    bitstring = "".join(map(str, bits))
    num_bytes = (len(bits) + 7) // 8
    val = int(bitstring, 2) if bitstring else 0
    return val.to_bytes(num_bytes, byteorder="big").hex()


# =====================================================================
#  5. Timing & JSON Mapping
# =====================================================================
class Stopwatch:
    def __init__(self):
        self.started_at = datetime.now()
        self._t0 = self._last = time.perf_counter()
        self.stages = {}

    def lap(self, stage: str):
        now = time.perf_counter()
        self.stages[stage] = round(now - self._last, 4)
        self._last = now

    def report(self) -> dict:
        return {"total": round(time.perf_counter() - self._t0, 4), **self.stages}


def read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def get_default_qkd_data(node_name: str, role_name: str) -> dict:
    return {
        "node": node_name,
        "protocol": "BB84",
        "role": role_name,
        "status": "IDLE",
        "timestamp": None,
        "session_id": None,
        "quantum_parameters": {
            "num_qubits": 10000,
            "attenuation_db_km": 0.2,
            "distance_km": 50,
            "detector_efficiency": 0.1,
            "dark_count_rate": 0.00001,
            "decoy_state_enabled": True,
            "mean_photon_number_mu": 0.5,
            "decoy_intensity_nu": 0.1,
            "vacuum_intensity_omega": 0.0,
        },
        "raw_key_length": 0,
        "sifted_key_length": 0,
        "secret_key_length_bits": 256,
        "secret_key_hex": None,
        "pipeline_metrics": {
            "measured_qber": 0.0,
            "qber_threshold": 0.11,
            "leak_error_correction_bits": 0,
            "leak_privacy_amplification_bits": 0,
            "secret_key_fraction_r": 0.0,
            "key_generation_rate_bps": 0.0,
            "latency_ms": 0.0,
            "aborted": False,
            "abort_reason": None,
        },
    }


def save_secret_qkd(
    bits: list[int],
    role: str,
    folder: Path,
    watch: Stopwatch,
    session_id: str,
    raw_len: int,
    sifted_len: int,
    qber: float,
    leaked_ec_bits: int,
    num_qubits: int,
    aborted: bool = False,
    abort_reason: str | None = None,
) -> dict:
    """Save key, parameters, and comprehensive pipeline metrics into secretQKD.json."""
    secret_file = folder / "secretQKD.json"
    data = read_json(secret_file)
    node_name = folder.name
    template = get_default_qkd_data(node_name, role.capitalize())

    for k, v in template.items():
        if k not in data:
            data[k] = v
        elif isinstance(v, dict) and isinstance(data[k], dict):
            for sub_k, sub_v in v.items():
                if sub_k not in data[k]:
                    data[k][sub_k] = sub_v

    finish_timestamp = datetime.now().isoformat()
    total_time = watch.report().get("total", 0.0)
    latency_ms = round(total_time * 1000, 3)

    data["node"] = node_name
    data["protocol"] = "BB84"
    data["role"] = role.capitalize()
    data["timestamp"] = finish_timestamp
    data["session_id"] = session_id

    if aborted:
        data["status"] = "ABORTED"
        data["pipeline_metrics"]["aborted"] = True
        data["pipeline_metrics"]["abort_reason"] = abort_reason
        write_json(secret_file, data)
        return data

    secret_key_hex = bits_to_hex(bits)
    bitstring = "".join(map(str, bits))

    data["status"] = "SUCCESS"
    data["raw_key_length"] = raw_len
    data["sifted_key_length"] = sifted_len
    data["secret_key_length_bits"] = len(bits)
    data["secret_key_hex"] = secret_key_hex
    data["secret_key"] = secret_key_hex
    data["secret"] = bitstring
    data["started_at"] = watch.started_at.isoformat()
    data["finished_at"] = finish_timestamp

    if "quantum_parameters" in data:
        data["quantum_parameters"]["num_qubits"] = num_qubits

    pa_leaked = max(0, (sifted_len - int(sifted_len * SAMPLE_FRACTION)) - len(bits))
    sec_fraction = round(len(bits) / sifted_len, 4) if sifted_len else 0.0
    key_rate = round(len(bits) / total_time, 2) if total_time > 0 else 0.0

    data["pipeline_metrics"]["measured_qber"] = round(qber, 4)
    data["pipeline_metrics"]["qber_threshold"] = QBER_THRESHOLD
    data["pipeline_metrics"]["leak_error_correction_bits"] = leaked_ec_bits
    data["pipeline_metrics"]["leak_privacy_amplification_bits"] = pa_leaked
    data["pipeline_metrics"]["secret_key_fraction_r"] = sec_fraction
    data["pipeline_metrics"]["key_generation_rate_bps"] = key_rate
    data["pipeline_metrics"]["latency_ms"] = latency_ms
    data["pipeline_metrics"]["aborted"] = False
    data["pipeline_metrics"]["abort_reason"] = None
    data["pipeline_metrics"]["time_seconds"] = watch.report()

    write_json(secret_file, data)
    print(f"[ ok  ] Successfully saved secret and metrics to {secret_file}")
    print(f"[time ] Distribution took {total_time:.3f}s ({latency_ms} ms)")
    return data


# =====================================================================
#  6. Alice Pipeline
# =====================================================================
def run_alice(
    chan: Channel,
    n_qubits: int = 6000,
    loss: float = 0.10,
    noise: float = 0.03,
    key_bits: int = 256,
    folder: Path | None = None,
) -> dict:
    folder = folder or DEFAULT_FOLDER
    print("[Alice] Waiting for Bob to be ready ...")
    chan.session = chan.receive("00_bob_ready")["nonce"]
    watch = Stopwatch()

    # Step 1: Encode Qubits
    bits = [rng.randint(0, 1) for _ in range(n_qubits)]
    bases = [rng.choice(["Z", "X"]) for _ in range(n_qubits)]
    qubits = [encode_qubit(b, base) for b, base in zip(bits, bases)]
    qubits, lost, flipped = channel_effects(qubits, loss, noise)
    print(f"[Chan ] {lost} qubits lost, {flipped} hit by noise, {n_qubits - lost} delivered")
    chan.send(
        "01_qubits",
        {"qubits": [None if q is None else circuit_to_ops(q) for q in qubits]},
        auth=False,
    )
    print(f"[Alice] Sent {n_qubits} qubits.")

    # Step 2: Sifting
    det = chan.receive("02_bob_detect")
    chan.send("03_alice_bases", {"bases": bases})
    kept = [i for i in range(n_qubits) if det["detected"][i] and bases[i] == det["bases"][i]]
    key = [bits[i] for i in kept]
    sifted_len = len(key)
    raw_len = sum(det["detected"])
    print(f"[Alice] {raw_len} qubits arrived, {sifted_len} matched bases (sifted key).")
    watch.lap("qubit_exchange")

    if sifted_len < MIN_SIFTED:
        chan.abort(f"Only {sifted_len} sifted bits; increase qubits or reduce loss.")
        save_secret_qkd([], "alice", folder, watch, chan.session, raw_len, sifted_len, 0.0, 0, n_qubits, True, "Insufficient sifted bits")
        raise AbortError("Not enough sifted key bits.")

    # Step 3: Error Estimation
    n_sample = max(1, int(sifted_len * SAMPLE_FRACTION))
    positions = sorted(rng.sample(range(sifted_len), n_sample))
    chan.send(
        "04_sample",
        {"positions": positions, "bits": [key[i] for i in positions], "key_bits": key_bits},
    )
    verdict = chan.receive("05_verdict")
    qber = verdict["qber"]
    print(
        f"[Alice] Error check: {verdict['errors']} errors in {verdict['sample_size']} bits -> QBER {qber:.1%} -> {'ACCEPTED' if verdict['secure'] else 'REJECTED'}"
    )

    if not verdict["secure"]:
        print("[Alice] Key discarded: QBER exceeded threshold.")
        save_secret_qkd([], "alice", folder, watch, chan.session, raw_len, sifted_len, qber, 0, n_qubits, True, "QBER exceeded threshold")
        chan.send("11_done", {})
        return {}

    drop = set(positions)
    key = [b for i, b in enumerate(key) if i not in drop]
    watch.lap("sifting_and_error_check")

    # Step 4: Error Correction (Cascade)
    print(f"[Alice] Answering Bob's Cascade parity questions ({len(key)} bits) ...")
    serve_parities(chan, key)
    watch.lap("error_correction")

    # Step 5: Verification
    ok = chan.receive("07_verify")["tag"] == verify_tag(key, chan.session)
    chan.send("08_verify_result", {"ok": ok})
    if not ok:
        print("[Alice] Verification FAILED.")
        save_secret_qkd([], "alice", folder, watch, chan.session, raw_len, sifted_len, qber, 0, n_qubits, True, "Verification failed")
        chan.send("11_done", {})
        return {}

    # Step 6: Privacy Amplification
    pa = chan.receive("09_pa")
    final = toeplitz_hash(key, [int(c) for c in pa["seed"]], pa["out_len"])
    watch.lap("verification_and_privacy_amplification")
    print(f"[Alice] Privacy amplification: {len(key)} -> {len(final)} secret bits.")
    print(f"[Alice] Key fingerprint: {fingerprint(final)}")

    record = save_secret_qkd(
        final, "alice", folder, watch, chan.session, raw_len, sifted_len, qber, 0, n_qubits
    )
    chan.send("11_done", {})
    return record


# =====================================================================
#  7. Bob Pipeline
# =====================================================================
def run_bob(
    chan: Channel,
    folder: Path | None = None,
) -> dict:
    folder = folder or DEFAULT_FOLDER
    chan.clear()
    nonce = secrets.token_hex(8)
    chan.session = ""
    chan.send("00_bob_ready", {"nonce": nonce})
    chan.session = nonce
    print("[Bob  ] Ready, waiting for Alice's qubits ...")

    # Step 1: Measure Arriving Qubits
    raw = chan.receive("01_qubits", auth=False)["qubits"]
    watch = Stopwatch()
    n = len(raw)
    bases = [rng.choice(["Z", "X"]) for _ in range(n)]
    detected = [0 if q is None else 1 for q in raw]
    arrived = [i for i in range(n) if raw[i] is not None]
    outcomes = measure_qubits(
        [circuit_from_ops(raw[i]) for i in arrived], [bases[i] for i in arrived]
    )
    results = {i: r for i, r in zip(arrived, outcomes)}
    raw_len = len(arrived)
    print(f"[Bob  ] {raw_len} of {n} qubits arrived and were measured.")
    chan.send("02_bob_detect", {"bases": bases, "detected": detected})

    # Step 2: Sifting
    alice_bases = chan.receive("03_alice_bases")["bases"]
    kept = [i for i in range(n) if detected[i] and bases[i] == alice_bases[i]]
    key = [results[i] for i in kept]
    sifted_len = len(key)
    print(f"[Bob  ] {sifted_len} positions matched bases (sifted key).")
    watch.lap("qubit_exchange")

    # Step 3: Error Estimation
    sample = chan.receive("04_sample")
    pos = sample["positions"]
    errors = sum(1 for p, b in zip(pos, sample["bits"]) if key[p] != b)
    qber = errors / len(pos) if pos else 0.0
    secure = bool(pos) and qber <= QBER_THRESHOLD
    print(
        f"[Bob  ] Error check: {errors} errors in {len(pos)} bits -> QBER {qber:.1%} (limit {QBER_THRESHOLD:.0%}) -> {'ACCEPTED' if secure else 'REJECTED'}"
    )
    chan.send(
        "05_verdict",
        {"qber": qber, "errors": errors, "sample_size": len(pos), "secure": secure},
    )

    if not secure:
        print("[Bob  ] Key discarded.")
        save_secret_qkd([], "bob", folder, watch, chan.session, raw_len, sifted_len, qber, 0, n, True, "QBER threshold exceeded")
        chan.receive("11_done")
        chan.clear()
        return {}

    drop = set(pos)
    key = [b for i, b in enumerate(key) if i not in drop]
    watch.lap("sifting_and_error_check")

    # Step 4: Error Correction (Cascade)
    oracle = ParityOracle(chan)
    corrected, fixed = cascade(key, oracle, qber)
    oracle.done()
    print(f"[Bob  ] Cascade fixed {fixed} errors; {oracle.leaked} parity bits revealed.")
    watch.lap("error_correction")

    # Step 5: Verification
    chan.send("07_verify", {"tag": verify_tag(corrected, chan.session)})
    if not chan.receive("08_verify_result")["ok"]:
        print("[Bob  ] Verification FAILED.")
        save_secret_qkd([], "bob", folder, watch, chan.session, raw_len, sifted_len, qber, oracle.leaked, n, True, "Verification failed")
        chan.receive("11_done")
        chan.clear()
        return {}
    print(f"[Bob  ] Verification passed: keys match ({len(corrected)} bits).")

    # Step 6: Privacy Amplification
    length, e_upper = secure_length(len(corrected), qber, len(pos), oracle.leaked)
    out_len = min(sample["key_bits"], length)
    print(
        f"[Bob  ] Secure length bound: {length} bits (error bound {e_upper:.1%}); target: {out_len} bits."
    )

    if out_len < MIN_KEY_BITS:
        chan.abort("Not enough secure key bits after privacy amplification.")
        save_secret_qkd([], "bob", folder, watch, chan.session, raw_len, sifted_len, qber, oracle.leaked, n, True, "Insufficient secure key length")
        raise AbortError("Insufficient key bits after privacy amplification.")

    seed = "".join(str(secrets.randbits(1)) for _ in range(out_len + len(corrected) - 1))
    chan.send("09_pa", {"seed": seed, "out_len": out_len})
    final = toeplitz_hash(corrected, [int(c) for c in seed], out_len)
    watch.lap("verification_and_privacy_amplification")
    print(f"[Bob  ] Final key fingerprint: {fingerprint(final)}")

    record = save_secret_qkd(
        final, "bob", folder, watch, chan.session, raw_len, sifted_len, qber, oracle.leaked, n
    )

    # Update Shared_Files/ABshared.json if present
    shared_file = folder.parent / "Shared_Files" / "ABshared.json"
    if shared_file.exists():
        try:
            shared_data = read_json(shared_file)
            if "qkd_exchange" in shared_data and isinstance(shared_data["qkd_exchange"], dict):
                shared_data["qkd_exchange"]["toeplitz_seed_hex"] = bits_to_hex([int(c) for c in seed])
                shared_data["session_id"] = chan.session
                shared_data["timestamp"] = datetime.now().isoformat()
                write_json(shared_file, shared_data)
        except Exception:
            pass

    chan.receive("11_done")
    chan.clear()
    return record


# =====================================================================
#  8. High-level Execution Functions
# =====================================================================
def detect_role(folder: Path) -> str:
    name = folder.name.lower()
    if name.endswith("_a"):
        return "alice"
    if name.endswith("_b"):
        return "bob"
    return "bob"


def get_default_channel_dir(folder: Path) -> Path:
    shared_chan = folder.parent / "Shared_Files" / "qkd_channel"
    if shared_chan.parent.exists():
        shared_chan.mkdir(parents=True, exist_ok=True)
        return shared_chan
    return Path(tempfile.gettempdir()) / "qkd_channel"


def run_qkd_exchange(
    n_qubits: int = 6000,
    loss: float = 0.10,
    noise: float = 0.03,
    key_bits: int = 256,
    channel_dir: Path | str | None = None,
    node_a_dir: Path | None = None,
    node_b_dir: Path | None = None,
) -> tuple[dict, dict]:
    """Execute complete simulated QKD exchange between Node A and Node B concurrently."""
    base = DEFAULT_FOLDER.parent if DEFAULT_FOLDER.name in ("Node_A", "Node_B") else DEFAULT_FOLDER
    node_a_dir = node_a_dir or (base / "Node_A")
    node_b_dir = node_b_dir or (base / "Node_B")

    if not channel_dir:
        channel_dir = get_default_channel_dir(node_a_dir)
    channel_dir = Path(channel_dir)
    channel_dir.mkdir(parents=True, exist_ok=True)

    bob_results = {}
    alice_results = {}
    errors = []

    chan_bob = Channel(channel_dir, timeout=60)
    chan_alice = Channel(channel_dir, timeout=60)

    def bob_worker():
        try:
            bob_results.update(run_bob(chan_bob, folder=node_b_dir))
        except Exception as e:
            errors.append(("Bob", e))

    def alice_worker():
        try:
            time.sleep(0.3)
            alice_results.update(
                run_alice(
                    chan_alice,
                    n_qubits=n_qubits,
                    loss=loss,
                    noise=noise,
                    key_bits=key_bits,
                    folder=node_a_dir,
                )
            )
        except Exception as e:
            errors.append(("Alice", e))

    t_bob = threading.Thread(target=bob_worker, daemon=True)
    t_alice = threading.Thread(target=alice_worker, daemon=True)

    t_bob.start()
    t_alice.start()

    t_bob.join(timeout=90)
    t_alice.join(timeout=90)

    if errors:
        raise RuntimeError(f"QKD exchange error: {errors}")

    return alice_results, bob_results


def run_qkd(
    role: str | None = None,
    folder: Path | None = None,
    n_qubits: int = 6000,
    loss: float = 0.10,
    noise: float = 0.03,
    key_bits: int = 256,
    channel_dir: Path | str | None = None,
    timeout: int = 120,
) -> dict:
    """Run QKD pipeline for the individual node (Alice or Bob)."""
    folder = folder or DEFAULT_FOLDER
    role = (role or detect_role(folder)).lower()

    if not channel_dir:
        channel_dir = get_default_channel_dir(folder)

    chan = Channel(channel_dir, timeout=timeout)
    print(f"[{role.upper()}] Channel directory: {channel_dir}")

    if role == "alice":
        return run_alice(chan, n_qubits=n_qubits, loss=loss, noise=noise, key_bits=key_bits, folder=folder)
    else:
        return run_bob(chan, folder=folder)


def main():
    p = argparse.ArgumentParser(description="BB84 QKD Protocol for Node_A and Node_B")
    p.add_argument("--role", choices=["alice", "bob"], help="Specify node role (default: auto)")
    p.add_argument("--both", action="store_true", help="Run full Alice + Bob exchange in one command")
    p.add_argument("--qubits", type=int, default=6000, help="Number of qubits to generate (default: 6000)")
    p.add_argument("--key-bits", type=int, default=256, help="Target key length (default: 256)")
    p.add_argument("--loss", type=float, default=0.10, help="Channel loss probability (default: 0.10)")
    p.add_argument("--noise", type=float, default=0.03, help="Channel noise probability (default: 0.03)")
    p.add_argument("--channel", default="", help="Custom channel directory")
    p.add_argument("--timeout", type=int, default=120, help="Timeout in seconds")
    args = p.parse_args()

    chan_dir = Path(args.channel) if args.channel else None

    if args.both:
        print("[CSDQKD] Executing concurrent Alice & Bob QKD exchange...")
        a_res, b_res = run_qkd_exchange(
            n_qubits=args.qubits,
            loss=args.loss,
            noise=args.noise,
            key_bits=args.key_bits,
            channel_dir=chan_dir,
        )
        print("[CSDQKD] Exchange complete! Both nodes updated.")
    else:
        run_qkd(
            role=args.role,
            folder=DEFAULT_FOLDER,
            n_qubits=args.qubits,
            loss=args.loss,
            noise=args.noise,
            key_bits=args.key_bits,
            channel_dir=chan_dir,
            timeout=args.timeout,
        )


if __name__ == "__main__":
    main()
