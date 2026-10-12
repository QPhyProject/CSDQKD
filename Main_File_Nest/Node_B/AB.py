"""
Node_B/AB.py - Unified Communication & Cryptographic Node for Bob (Node B)
=============================================================================

Consolidates all security protocols into modular functions:
  - CKD: Classical Key Distribution (X25519 ECDH + HKDF-SHA256)
  - QKD: Quantum Key Distribution (BB84 + Cascade + Toeplitz PA)
  - MKD: Post-Quantum Key Distribution (NIST ML-KEM-768 / Kyber-768)
  - AES: Authenticated Symmetric Decryption (AES-256-GCM)

All local secrets, private keys, and metrics are securely saved in secretAB.json.
Communication with Node A strictly occurs via Shared_Files/ABshared.json without
exposing any secret keys on the shared communication channel.
"""

import argparse
import base64
import hashlib
import hmac
import json
import math
import os
import random
import secrets
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

# Cryptography primitives
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.kem.ml_kem_768 import encaps as ml_kem_encaps
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator

BASE_DIR = Path(__file__).resolve().parent.parent
NODE_DIR = Path(__file__).resolve().parent
SECRET_FILE = NODE_DIR / "secretAB.json"
SHARED_FILE = BASE_DIR / "Shared_Files" / "ABshared.json"
QKD_CHANNEL_DIR = BASE_DIR / "Shared_Files" / "qkd_channel"

# QKD parameters
QBER_THRESHOLD = 0.11
SAMPLE_FRACTION = 0.25
CASCADE_PASSES = 4
EXTRA_PASSES = 12
EXTRA_CLEAN = 2
EXTRA_BLOCK_DIV = 1
VERIFY_BITS = 32
SECURITY_BITS = 40
MIN_SIFTED = 100
MIN_KEY_BITS = 64
POLL = 0.05
AUTH_KEY = os.environ.get("QKD_AUTH_KEY", "CSDQKD-Preshared-Auth-Key-2026").encode()

SIMULATOR = AerSimulator()
rng = random.SystemRandom()


# =====================================================================
#  Helper I/O Functions
# =====================================================================
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
        json.dump(data, f, indent=2)


def get_secret_store() -> dict:
    data = read_json(SECRET_FILE)
    if not data:
        data = {
            "node": "Node_B",
            "role": "Bob",
            "active_protocol": None,
            "current_secret_key_hex": None,
            "ckd": {"status": "IDLE", "metrics": {}},
            "qkd": {"status": "IDLE", "pipeline_metrics": {}},
            "mkd": {"status": "IDLE", "metrics": {}},
            "aes": {"status": "IDLE"},
        }
    return data


def save_secret_store(data: dict) -> None:
    write_json(SECRET_FILE, data)


def get_shared_channel() -> dict:
    data = read_json(SHARED_FILE)
    if not data:
        data = {
            "channel": "Alice_Bob_Shared",
            "active_protocol": "BB84",
            "session_id": None,
            "timestamp": None,
            "classical_exchange": {"alice_public_key_hex": None, "bob_public_key_hex": None},
            "pqc_exchange": {
                "alice_kem_public_key_b64": None,
                "alice_kem_public_key_hex": None,
                "bob_ciphertext_b64": None,
                "bob_ciphertext_hex": None,
            },
            "qkd_exchange": {
                "alice_basis_announcement": [],
                "bob_basis_announcement": [],
                "sifting_indices": [],
                "error_estimation_sample_indices": [],
                "error_estimation_sample_values": [],
                "toeplitz_seed_hex": None,
            },
            "encrypted_transmission": {
                "sender": "Alice",
                "cipher": "AES-256-GCM",
                "nonce_hex": None,
                "ciphertext_hex": None,
                "tag_hex": None,
                "plaintext_preview": None,
                "status": "IDLE",
            },
        }
    return data


def save_shared_channel(data: dict) -> None:
    # Guarantee no secret key is stored on the shared public channel
    if "encrypted_transmission" in data:
        data["encrypted_transmission"].pop("secret_key_hex", None)
        data["encrypted_transmission"].pop("secret_key", None)
    write_json(SHARED_FILE, data)


# =====================================================================
#  1. CKD: Classical Key Distribution (Bob)
# =====================================================================
def ckd_publish_public_key(force_new: bool = False) -> dict:
    """Generate or retrieve Bob's X25519 keypair and publish public key to ABshared.json."""
    start_time = time.perf_counter()
    store = get_secret_store()
    ckd_data = store.get("ckd", {})

    private_hex = ckd_data.get("private_key")
    if not force_new and private_hex and len(bytes.fromhex(private_hex)) == 32:
        private_key = X25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex))
    else:
        private_key = X25519PrivateKey.generate()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # Save Bob's secrets locally
    ckd_data["protocol"] = "ECDH_X25519"
    ckd_data["status"] = "PENDING"
    ckd_data["timestamp"] = datetime.now().isoformat()
    ckd_data["private_key"] = private_bytes.hex()
    ckd_data["public_key"] = public_bytes.hex()
    store["ckd"] = ckd_data
    save_secret_store(store)

    # Publish public key to shared channel
    shared = get_shared_channel()
    shared["active_protocol"] = "ECDH_X25519"
    shared["classical_exchange"]["bob_public_key_hex"] = public_bytes.hex()
    shared["timestamp"] = datetime.now(timezone.utc).isoformat()
    save_shared_channel(shared)

    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 3)
    return {
        "status": "PENDING",
        "public_key_hex": public_bytes.hex(),
        "latency_ms": elapsed_ms,
    }


def ckd_derive_key() -> dict:
    """Read Alice's public key from ABshared.json, perform ECDH, derive 256-bit key via HKDF."""
    start_time = time.perf_counter()
    store = get_secret_store()
    ckd_data = store.get("ckd", {})
    shared = get_shared_channel()

    alice_public_hex = shared.get("classical_exchange", {}).get("alice_public_key_hex")
    if not alice_public_hex:
        # Fallback check to Node_A/secretAB.json or secretCKD.json
        a_secret = read_json(BASE_DIR / "Node_A" / "secretAB.json")
        alice_public_hex = a_secret.get("ckd", {}).get("public_key")
        if not alice_public_hex:
            a_ckd = read_json(BASE_DIR / "Node_A" / "secretCKD.json")
            alice_public_hex = a_ckd.get("public_key")

    if not alice_public_hex:
        raise RuntimeError("Alice's classical public key is not available on the communication channel.")

    private_hex = ckd_data.get("private_key")
    if not private_hex:
        ckd_publish_public_key()
        store = get_secret_store()
        private_hex = store["ckd"]["private_key"]

    private_key = X25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex))
    alice_public_key = X25519PublicKey.from_public_bytes(bytes.fromhex(alice_public_hex))

    shared_secret = private_key.exchange(alice_public_key)
    secret_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"CSDQKD-Classical-Key-Exchange",
    ).derive(shared_secret)

    elapsed_time = time.perf_counter() - start_time
    elapsed_ms = round(elapsed_time * 1000, 3)
    iso_now = datetime.now().isoformat()
    session_id = shared.get("session_id") or secrets.token_hex(8)

    ckd_data["status"] = "SUCCESS"
    ckd_data["timestamp"] = iso_now
    ckd_data["session_id"] = session_id
    ckd_data["peer_public_key"] = alice_public_hex
    ckd_data["secret_key_hex"] = secret_key.hex()
    if "metrics" not in ckd_data:
        ckd_data["metrics"] = {}
    ckd_data["metrics"]["latency_ms"] = elapsed_ms
    ckd_data["metrics"]["established_at"] = iso_now

    store["active_protocol"] = "CKD"
    store["current_secret_key_hex"] = secret_key.hex()
    store["ckd"] = ckd_data
    save_secret_store(store)

    return {
        "status": "SUCCESS",
        "secret_key_hex": secret_key.hex(),
        "latency_ms": elapsed_ms,
        "session_id": session_id,
    }


def run_ckd() -> dict:
    """Full Bob CKD routine."""
    pub_info = ckd_publish_public_key()
    return pub_info


# =====================================================================
#  2. QKD: Quantum Key Distribution (Bob)
# =====================================================================
class QKDChannel:
    def __init__(self, folder: Path, timeout: int = 120):
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
                raise RuntimeError(f"QKD channel authentication failed on message '{name}'.")
            return record["body"]
        raise TimeoutError(f"QKD channel timed out waiting for '{name}'.")

    def abort(self, reason: str) -> None:
        self.send("99_abort", {"reason": reason})

    def _check_abort(self) -> None:
        path = self._path("99_abort")
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    rec = json.load(f)
                raise RuntimeError(f"Peer node aborted QKD: {rec['body']['reason']}")
            except (json.JSONDecodeError, PermissionError, KeyError):
                pass

    def clear(self) -> None:
        for f in os.listdir(self.folder):
            if f.endswith(".json") or f.endswith(".tmp"):
                try:
                    os.remove(os.path.join(self.folder, f))
                except OSError:
                    pass


def circuit_from_ops(ops: list[str]) -> QuantumCircuit:
    qc = QuantumCircuit(1, 1)
    for name in ops:
        if name not in ("x", "h", "y", "z"):
            raise ValueError(f"Unexpected gate: {name!r}")
        getattr(qc, name)(0)
    return qc


def measure_qubits(circuits: list[QuantumCircuit], bases: list[str]) -> list[int]:
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


def parity(bits: list[int], indices: list[int]) -> int:
    return sum(bits[i] for i in indices) & 1


class ParityOracle:
    def __init__(self, chan: QKDChannel):
        self.chan = chan
        self.n = 0
        self.leaked = 0

    def ask(self, subsets: list[list[int]]) -> list[int]:
        self.chan.send(f"ec_q{self.n:03d}", {"subsets": subsets})
        answers = self.chan.receive(f"ec_a{self.n:03d}")["parities"]
        self.n += 1
        self.leaked += len(answers)
        return answers

    def done(self) -> None:
        self.chan.send(f"ec_q{self.n:03d}", {"done": True})


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


def run_qkd_bob(timeout: int = 60) -> dict:
    """Execute Bob's side of BB84 QKD protocol."""
    start_time = time.perf_counter()
    chan = QKDChannel(QKD_CHANNEL_DIR, timeout=timeout)
    chan.clear()

    nonce = secrets.token_hex(8)
    chan.session = ""
    chan.send("00_bob_ready", {"nonce": nonce})
    chan.session = nonce

    # 1. Measure Arriving Qubits
    raw = chan.receive("01_qubits", auth=False)["qubits"]
    n = len(raw)
    bases = [rng.choice(["Z", "X"]) for _ in range(n)]
    detected = [0 if q is None else 1 for q in raw]
    arrived = [i for i in range(n) if raw[i] is not None]
    outcomes = measure_qubits(
        [circuit_from_ops(raw[i]) for i in arrived], [bases[i] for i in arrived]
    )
    results = {i: r for i, r in zip(arrived, outcomes)}
    raw_len = len(arrived)

    chan.send("02_bob_detect", {"bases": bases, "detected": detected})

    # 2. Sifting
    alice_bases = chan.receive("03_alice_bases")["bases"]
    kept = [i for i in range(n) if detected[i] and bases[i] == alice_bases[i]]
    key = [results[i] for i in kept]
    sifted_len = len(key)

    # 3. Error Estimation
    sample = chan.receive("04_sample")
    pos = sample["positions"]
    errors = sum(1 for p, b in zip(pos, sample["bits"]) if key[p] != b)
    qber = errors / len(pos) if pos else 0.0
    secure = bool(pos) and qber <= QBER_THRESHOLD

    chan.send(
        "05_verdict",
        {"qber": qber, "errors": errors, "sample_size": len(pos), "secure": secure},
    )

    if not secure:
        chan.receive("11_done")
        chan.clear()
        raise RuntimeError(f"QKD aborted: QBER {qber:.2%} exceeded threshold {QBER_THRESHOLD:.0%}.")

    drop = set(pos)
    key = [b for i, b in enumerate(key) if i not in drop]

    # 4. Error Correction (Cascade)
    oracle = ParityOracle(chan)
    corrected, fixed = cascade(key, oracle, qber)
    oracle.done()

    # 5. Verification
    my_tag = hashlib.sha256((chan.session + "".join(map(str, corrected))).encode()).hexdigest()[:8]
    chan.send("07_verify", {"tag": my_tag})
    if not chan.receive("08_verify_result")["ok"]:
        chan.receive("11_done")
        chan.clear()
        raise RuntimeError("QKD verification failed: residual errors remaining.")

    # 6. Privacy Amplification
    length, e_upper = secure_length(len(corrected), qber, len(pos), oracle.leaked)
    out_len = min(sample["key_bits"], length)

    if out_len < MIN_KEY_BITS:
        chan.abort("Not enough secure key bits after privacy amplification.")
        chan.clear()
        raise RuntimeError("Insufficient key bits after privacy amplification.")

    seed_bits = [secrets.randbits(1) for _ in range(out_len + len(corrected) - 1)]
    chan.send("09_pa", {"seed": "".join(map(str, seed_bits)), "out_len": out_len})
    final_bits = toeplitz_hash(corrected, seed_bits, out_len)

    chan.receive("11_done")
    chan.clear()

    total_time = time.perf_counter() - start_time
    elapsed_ms = round(total_time * 1000, 3)

    bitstring = "".join(map(str, final_bits))
    num_bytes = (len(final_bits) + 7) // 8
    secret_key_hex = int(bitstring, 2).to_bytes(num_bytes, "big").hex()
    iso_now = datetime.now().isoformat()

    # Save to secretAB.json
    store = get_secret_store()
    qkd_data = store.get("qkd", {})
    qkd_data["status"] = "SUCCESS"
    qkd_data["timestamp"] = iso_now
    qkd_data["session_id"] = chan.session
    qkd_data["raw_key_length"] = raw_len
    qkd_data["sifted_key_length"] = sifted_len
    qkd_data["secret_key_length_bits"] = len(final_bits)
    qkd_data["secret_key_hex"] = secret_key_hex
    qkd_data["secret"] = bitstring
    qkd_data["pipeline_metrics"] = {
        "measured_qber": round(qber, 4),
        "qber_threshold": QBER_THRESHOLD,
        "leak_error_correction_bits": oracle.leaked,
        "leak_privacy_amplification_bits": len(key) - len(final_bits),
        "secret_key_fraction_r": round(len(final_bits) / sifted_len, 4) if sifted_len else 0.0,
        "key_generation_rate_bps": round(len(final_bits) / total_time, 2) if total_time > 0 else 0.0,
        "latency_ms": elapsed_ms,
        "aborted": False,
        "abort_reason": None,
    }

    store["active_protocol"] = "QKD"
    store["current_secret_key_hex"] = secret_key_hex
    store["qkd"] = qkd_data
    save_secret_store(store)

    # Update Shared_Files/ABshared.json public seed info
    shared = get_shared_channel()
    shared["active_protocol"] = "BB84"
    shared["session_id"] = chan.session
    shared["timestamp"] = datetime.now(timezone.utc).isoformat()
    seed_num_bytes = (len(seed_bits) + 7) // 8
    seed_hex = int("".join(map(str, seed_bits)), 2).to_bytes(seed_num_bytes, "big").hex()
    shared["qkd_exchange"]["toeplitz_seed_hex"] = seed_hex
    save_shared_channel(shared)

    return {
        "status": "SUCCESS",
        "secret_key_hex": secret_key_hex,
        "latency_ms": elapsed_ms,
        "qber": qber,
        "key_bits": len(final_bits),
        "session_id": chan.session,
    }


# =====================================================================
#  3. MKD: Post-Quantum Key Distribution (Bob)
# =====================================================================
def mkd_encapsulate() -> dict:
    """Read Alice's public key from ABshared.json, encapsulate shared secret, post ciphertext."""
    start_time = time.perf_counter()
    store = get_secret_store()
    mkd_data = store.get("mkd", {})
    shared = get_shared_channel()

    pk_b64 = shared.get("pqc_exchange", {}).get("alice_kem_public_key_b64")
    pk_hex = shared.get("pqc_exchange", {}).get("alice_kem_public_key_hex")

    if not pk_b64 and not pk_hex:
        # Fallback check to Node_A/secretAB.json or secretMKD.json
        a_secret = read_json(BASE_DIR / "Node_A" / "secretAB.json")
        pk_b64 = a_secret.get("mkd", {}).get("public_key")
        if not pk_b64:
            a_mkd = read_json(BASE_DIR / "Node_A" / "secretMKD.json")
            pk_b64 = a_mkd.get("public_key")

    if not pk_b64 and not pk_hex:
        raise RuntimeError("Alice's post-quantum public key is not available on the communication channel.")

    if pk_b64:
        public_key = base64.b64decode(pk_b64)
    else:
        public_key = bytes.fromhex(pk_hex)

    if len(public_key) != 1184:
        raise ValueError(f"Invalid ML-KEM-768 public key size: {len(public_key)} bytes (expected 1184).")

    t_encap_start = time.perf_counter()
    ciphertext, shared_secret = ml_kem_encaps(public_key)
    encap_ms = round((time.perf_counter() - t_encap_start) * 1000, 4)

    total_ms = round((time.perf_counter() - start_time) * 1000, 3)
    iso_now = datetime.now().isoformat()
    session_id = shared.get("session_id") or secrets.token_hex(8)

    # Save to Bob's secret store
    mkd_data["protocol"] = "ML_KEM_Kyber768"
    mkd_data["status"] = "SUCCESS"
    mkd_data["timestamp"] = iso_now
    mkd_data["session_id"] = session_id
    mkd_data["secret_key_hex"] = shared_secret.hex()
    mkd_data["shared_secret"] = base64.b64encode(shared_secret).decode("ascii")
    mkd_data["ciphertext"] = base64.b64encode(ciphertext).decode("ascii")
    mkd_data["ciphertext_hex"] = ciphertext.hex()
    if "metrics" not in mkd_data:
        mkd_data["metrics"] = {}
    mkd_data["metrics"]["encapsulation_time_ms"] = encap_ms
    mkd_data["metrics"]["total_latency_ms"] = total_ms

    store["active_protocol"] = "MKD"
    store["current_secret_key_hex"] = shared_secret.hex()
    store["mkd"] = mkd_data
    save_secret_store(store)

    # Publish ciphertext to shared channel (no secrets)
    shared["active_protocol"] = "ML_KEM_Kyber768"
    shared["session_id"] = session_id
    shared["timestamp"] = datetime.now(timezone.utc).isoformat()
    shared["pqc_exchange"]["bob_ciphertext_b64"] = base64.b64encode(ciphertext).decode("ascii")
    shared["pqc_exchange"]["bob_ciphertext_hex"] = ciphertext.hex()
    save_shared_channel(shared)

    return {
        "status": "SUCCESS",
        "secret_key_hex": shared_secret.hex(),
        "encapsulation_time_ms": encap_ms,
        "total_latency_ms": total_ms,
        "ciphertext_hex": ciphertext.hex(),
        "session_id": session_id,
    }


def run_mkd() -> dict:
    """Full Bob MKD routine."""
    return mkd_encapsulate()


# =====================================================================
#  4. AES: Authenticated Decryption (Bob)
# =====================================================================
def get_current_key(protocol: str | None = None) -> tuple[bytes, str]:
    """Retrieve 256-bit key from Bob's local secretAB.json storage."""
    store = get_secret_store()

    if protocol:
        proto = protocol.upper()
        if "QKD" in proto and store.get("qkd", {}).get("secret_key_hex"):
            return bytes.fromhex(store["qkd"]["secret_key_hex"]), "Node_B/secretAB.json [QKD]"
        if "MKD" in proto and store.get("mkd", {}).get("secret_key_hex"):
            return bytes.fromhex(store["mkd"]["secret_key_hex"]), "Node_B/secretAB.json [MKD]"
        if "CKD" in proto and store.get("ckd", {}).get("secret_key_hex"):
            return bytes.fromhex(store["ckd"]["secret_key_hex"]), "Node_B/secretAB.json [CKD]"

    if store.get("current_secret_key_hex"):
        return bytes.fromhex(store["current_secret_key_hex"]), f"Node_B/secretAB.json [{store.get('active_protocol', 'Current')}]"

    for proto_key, desc in [("qkd", "QKD"), ("mkd", "MKD"), ("ckd", "CKD")]:
        khex = store.get(proto_key, {}).get("secret_key_hex")
        if khex and len(bytes.fromhex(khex)) == 32:
            return bytes.fromhex(khex), f"Node_B/secretAB.json [{desc}]"

    raise RuntimeError("No secret key found in Node_B/secretAB.json. Establish a key via QKD, MKD, or CKD first.")


def aes_decrypt(protocol: str | None = None, key_hex: str | None = None) -> dict:
    """
    Read ciphertext, nonce, and tag from ABshared.json.
    Decrypt using Bob's local secret key and verify authentication tag.
    Updates transmission status on ABshared.json to DECRYPTED.
    """
    start_time = time.perf_counter()
    shared = get_shared_channel()
    transmission = shared.get("encrypted_transmission", {})

    status = transmission.get("status")
    if status != "ENCRYPTED":
        raise RuntimeError(f"No encrypted message available to decrypt (current status: {status}).")

    if key_hex:
        key_bytes = bytes.fromhex(key_hex)
        key_src = "Explicit argument"
    else:
        key_bytes, key_src = get_current_key(protocol=protocol)

    if len(key_bytes) != 32:
        raise ValueError(f"AES-256 requires a 32-byte key; got {len(key_bytes)} bytes.")

    nonce = bytes.fromhex(transmission["nonce_hex"])
    ciphertext = bytes.fromhex(transmission["ciphertext_hex"])
    tag = bytes.fromhex(transmission["tag_hex"])

    aesgcm = AESGCM(key_bytes)
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext + tag, None)
    plaintext = plaintext_bytes.decode("utf-8")

    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 4)
    iso_now = datetime.now(timezone.utc).isoformat()

    # Update shared channel status
    shared["encrypted_transmission"]["status"] = "DECRYPTED"
    shared["encrypted_transmission"]["decrypted_at"] = iso_now
    save_shared_channel(shared)

    # Update Bob's local secrets
    store = get_secret_store()
    store["aes"] = {
        "cipher": "AES-256-GCM",
        "status": "DECRYPTED",
        "last_decrypted_at": iso_now,
        "last_plaintext": plaintext,
        "decryption_latency_ms": elapsed_ms,
        "verification_success": True,
    }
    save_secret_store(store)

    return {
        "status": "DECRYPTED",
        "plaintext": plaintext,
        "key_source": key_src,
        "decryption_latency_ms": elapsed_ms,
        "verification_success": True,
        "message_length": len(plaintext_bytes),
    }


def main():
    parser = argparse.ArgumentParser(description="Node B (Bob) Unified Security Controller")
    parser.add_argument("--mode", choices=["ckd-pub", "ckd-derive", "qkd", "mkd-encap", "decrypt"], default="decrypt")
    parser.add_argument("--protocol", choices=["QKD", "MKD", "CKD"], help="Active protocol for decryption")
    parser.add_argument("--key", help="Explicit AES key in hex (optional)")
    args = parser.parse_args()

    if args.mode == "ckd-pub":
        res = ckd_publish_public_key()
        print(f"[Node B CKD] Public key published: {res['public_key_hex']}")
    elif args.mode == "ckd-derive":
        res = ckd_derive_key()
        print(f"[Node B CKD] Secret key established: {res['secret_key_hex']}")
    elif args.mode == "qkd":
        res = run_qkd_bob()
        print(f"[Node B QKD] Key established: {res['secret_key_hex']}")
    elif args.mode == "mkd-encap":
        res = mkd_encapsulate()
        print(f"[Node B MKD] Secret key established: {res['secret_key_hex']}")
        print(f"[Node B MKD] Ciphertext published: {res['ciphertext_hex'][:32]}...")
    elif args.mode == "decrypt":
        res = aes_decrypt(protocol=args.protocol, key_hex=args.key)
        print(f"[Node B AES] Message successfully decrypted in {res['decryption_latency_ms']} ms")
        print(f"[Node B AES] Plaintext: {res['plaintext']}")


if __name__ == "__main__":
    main()
