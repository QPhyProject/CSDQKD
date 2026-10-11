"""
ABQKD.py  -  complete BB84 QKD between Node A (Alice) and Node B (Bob)
=======================================================================

The SAME file lives in Node_A/ and Node_B/. Its role comes from the folder name
(Node_A -> Alice, Node_B -> Bob), or force it with --role.

WHAT THIS FILE DOES (the whole QKD pipeline)
--------------------------------------------
  1. BB84 on Qiskit ........ Alice encodes random bits in random bases as qubits,
                             Bob measures them in random bases.
  2. Noise + photon loss ... the simulated channel LOSES some qubits and corrupts others.
                             Bob reports which qubits arrived ("detected"); only those count.
  3. Sifting ............... keep the positions that arrived AND had matching bases.
  4. Error estimation ...... reveal a random sample, count errors (QBER). Too many -> abort
                             (that is how an eavesdropper is caught).
  5. Error correction ...... CASCADE: Bob fixes the remaining errors by comparing block
                             parities with Alice (Alice only answers parity questions).
  6. Verification .......... a short hash proves both sides now hold the identical key.
  7. Privacy amplification . a random Toeplitz hash squeezes the key down to a shorter one
                             that Eve (who may know part of the old one) knows nothing about.
  8. Authentication ........ EVERY public message carries an HMAC-SHA256 tag made with a
                             pre-shared secret, so nobody can alter or forge messages.
  9. Save + timing ......... each node writes the final key AND how long the whole key
                             distribution took into ITS OWN secretQKD.json.

HOW THE NODES TALK
------------------
Only through small JSON message files in a shared "channel" folder (default:
<temp folder>/qkd_channel; for two computers use a shared folder via --channel or the
QKD_CHANNEL_DIR environment variable). Each file looks like {"body": ..., "tag": ...}.
Messages are numbered in the order they are used:
    00_bob_ready  01_qubits  02_bob_detect  03_alice_bases  04_sample  05_verdict
    ec_q000/ec_a000 ... (error-correction questions and answers)
    07_verify  08_verify_result  09_pa  11_done        (99_abort if something goes wrong)

HONEST LIMITS
-------------
  * "Real photons" can't be done in software: the quantum channel is SIMULATED with Qiskit.
    The loss/noise model only mimics a real fibre link.
  * Authentication uses HMAC-SHA256 with a pre-shared key (computationally secure). Real QKD
    uses an information-theoretic MAC and refreshes that key from each session's output.
    The demo key below must be replaced (set QKD_AUTH_KEY) for anything real.
  * The privacy-amplification length is a standard textbook estimate, not a formal proof.

RUN (Bob first, then Alice, one terminal each)
    cd Node_B ; python ABQKD.py
    cd Node_A ; python ABQKD.py
Options (Alice side): --qubits 8000  --key-bits 256  --loss 0.10  --noise 0.03
Needs: pip install qiskit qiskit-aer

THE secretQKD.json FORMAT (fixed: every run writes exactly these fields)
    {
      "node": "Node_A",  "role": "alice",
      "secret": "0101...",  "key_length_bits": 256,
      "started_at": "...",  "finished_at": "...",
      "time_seconds": {"total": ..., "qubit_exchange": ..., "sifting_and_error_check": ...,
                       "error_correction": ..., "verification_and_privacy_amplification": ...}
    }
A rejected run (too many errors, failed authentication, ...) saves nothing.
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
import time
from datetime import datetime

from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator

# ----------------------------------------------------------------- settings
QBER_THRESHOLD = 0.11        # above 11% errors in the sample -> assume an eavesdropper
SAMPLE_FRACTION = 0.25       # share of the sifted key revealed for error estimation
CASCADE_PASSES = 4           # standard rounds of error correction
EXTRA_PASSES = 12            # up to this many extra rounds
EXTRA_CLEAN = 2              # ...stopping after this many clean rounds in a row
EXTRA_BLOCK_DIV = 1          # extra rounds use blocks of (starting size / this)
VERIFY_BITS = 32             # size of the verification hash (counted as leaked)
SECURITY_BITS = 40           # safety margin removed in privacy amplification
MIN_SIFTED = 100             # need at least this many sifted bits to continue
MIN_KEY_BITS = 64            # smaller final keys are refused
POLL = 0.05                  # seconds between checks for a new message file

# Pre-shared secret used to authenticate the public channel. DEMO VALUE: replace it by
# setting the QKD_AUTH_KEY environment variable to the same secret on both nodes.
AUTH_KEY = os.environ.get("QKD_AUTH_KEY", "demo-preshared-key-change-me").encode()

SIMULATOR = AerSimulator()             # the simulated "quantum computer"
rng = random.SystemRandom()            # OS-grade randomness for bits and bases

HERE = os.path.dirname(os.path.abspath(__file__))
SECRET_FILE = os.path.join(HERE, "secretQKD.json")   # this node's OWN secret file


class AuthError(Exception):
    pass


class AbortError(Exception):
    pass


# =====================================================================
#  1. Quantum part (Qiskit)
# =====================================================================
def encode_qubit(bit, basis):
    """Alice: (bit, basis) -> qubit. Start |0>; bit 1 -> X gate; basis X -> H gate."""
    qc = QuantumCircuit(1, 1)
    if bit == 1:
        qc.x(0)
    if basis == "X":
        qc.h(0)
    return qc


def measure_qubits(circuits, bases):
    """
    Measure many qubits, each in its own basis (right basis -> true bit, wrong basis -> random).
    To measure in the X basis we first apply H, then do a normal measurement.
    All circuits go to the simulator in one batch (fast); falls back to one-by-one if needed.
    """
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


def circuit_to_ops(qc):
    """A qubit travels as the list of gates that prepared it, e.g. ['x', 'h']."""
    return [inst.operation.name for inst in qc.data]


def circuit_from_ops(ops):
    """Rebuild a qubit on the receiving side from its gate list (only known gates allowed)."""
    qc = QuantumCircuit(1, 1)
    for name in ops:
        if name not in ("x", "h", "y", "z"):
            raise ValueError(f"unexpected gate in received qubit: {name!r}")
        getattr(qc, name)(0)
    return qc


def channel_effects(qubits, loss, noise):
    """
    The simulated fibre link.
      loss  - chance a qubit never arrives (photon absorbed). It is replaced by None.
      noise - chance a surviving qubit gets a random error (an X, Y or Z gate).
    """
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
    print(f"[Chan ] {lost} qubits lost, {flipped} hit by noise, {len(qubits) - lost} delivered")
    return out


# =====================================================================
#  2. The "wire": authenticated JSON message files in a shared folder
# =====================================================================
class Channel:
    def __init__(self, folder, timeout):
        self.folder = folder
        self.timeout = timeout
        self.session = ""            # random session id set by Bob (stops replaying old messages)
        os.makedirs(folder, exist_ok=True)

    def _path(self, name):
        return os.path.join(self.folder, name + ".json")

    def _tag(self, name, body):
        """HMAC-SHA256 over: session + message name + message content."""
        text = f"{self.session}|{name}|" + json.dumps(body, sort_keys=True, separators=(",", ":"))
        return hmac.new(AUTH_KEY, text.encode(), hashlib.sha256).hexdigest()

    def send(self, name, obj, auth=True):
        """
        Write a message file (temp file then rename, so it's never half-written).
        auth=False is used only for the QUANTUM channel (the qubits), which can't carry a MAC.
        """
        record = {"body": obj}
        if auth:
            record["tag"] = self._tag(name, obj)
        tmp = self._path(name) + ".tmp"
        with open(tmp, "w") as f:
            json.dump(record, f)
        os.replace(tmp, self._path(name))

    def receive(self, name, auth=True):
        """Wait for a message file, check its tag, return its content."""
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            self._check_abort()
            try:
                with open(self._path(name)) as f:
                    record = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError, PermissionError):
                time.sleep(POLL)
                continue
            if auth and not hmac.compare_digest(record.get("tag", ""), self._tag(name, record["body"])):
                self.abort(f"authentication failed on '{name}'")
                raise AuthError(f"message '{name}' failed authentication (altered or forged). Aborting.")
            return record["body"]
        raise TimeoutError(f"waited {self.timeout}s for '{name}.json' in {self.folder}. "
                           "Is the other node running (Bob must start first)?")

    def abort(self, reason):
        self.send("99_abort", {"reason": reason})

    def _check_abort(self):
        path = self._path("99_abort")
        if not os.path.exists(path):
            return
        try:
            with open(path) as f:
                record = json.load(f)
            if hmac.compare_digest(record.get("tag", ""), self._tag("99_abort", record["body"])):
                raise AbortError(f"the other node aborted: {record['body']['reason']}")
        except (json.JSONDecodeError, PermissionError, KeyError, OSError):
            pass

    def clear(self):
        for f in os.listdir(self.folder):
            if f.endswith(".json") or f.endswith(".tmp"):
                try:
                    os.remove(os.path.join(self.folder, f))
                except OSError:
                    pass


# =====================================================================
#  3. Error correction: CASCADE
# =====================================================================
def parity(bits, indices):
    return sum(bits[i] for i in indices) & 1


class ParityOracle:
    """Bob's side: asks Alice 'what is the parity of these bits of your key?'. Counts what leaks."""

    def __init__(self, chan):
        self.chan, self.n, self.leaked = chan, 0, 0

    def ask(self, subsets):
        self.chan.send(f"ec_q{self.n:03d}", {"subsets": subsets})
        answers = self.chan.receive(f"ec_a{self.n:03d}")["parities"]
        self.n += 1
        self.leaked += len(answers)          # every parity bit told to the public is leaked info
        return answers

    def done(self):
        self.chan.send(f"ec_q{self.n:03d}", {"done": True})


def serve_parities(chan, key):
    """Alice's side: answer parity questions until Bob says he is done. Alice's key never changes."""
    n = 0
    while True:
        q = chan.receive(f"ec_q{n:03d}")
        if q.get("done"):
            return
        chan.send(f"ec_a{n:03d}", {"parities": [parity(key, s) for s in q["subsets"]]})
        n += 1


def cascade(bob_key, oracle, qber):
    """
    Fix Bob's errors so his key equals Alice's.
      Pass 1: cut the key into blocks, compare each block's parity with Alice's.
              A block with different parity holds an odd number of errors -> binary-search it
              (ask about the left half, then a quarter ...) until the wrong bit is found; flip it.
      Pass 2..4: shuffle the bits, use blocks twice as big, repeat. Each fix is also checked
              against the blocks of earlier passes (that is the 'cascade'), which uncovers errors
              hidden in blocks that had an even number of them.
      Extra passes: more shuffled rounds with small blocks (the starting size), until two
              rounds in a row find nothing left to fix. This catches pairs of errors that kept
              landing in the same block.
    """
    n = len(bob_key)
    b = list(bob_key)
    k = min(n, max(4, int(0.73 / max(qber, 0.005))))      # starting block size
    k0 = k
    clean_run = 0                                         # extra rounds in a row that fixed nothing
    blocks, alice_par = [], []
    member = [[] for _ in range(n)]                       # bit -> ids of the blocks containing it
    fixed = 0

    def find_error(block):
        while len(block) > 1:
            left = block[:len(block) // 2]
            if parity(b, left) != oracle.ask([left])[0]:
                block = left
            else:
                block = block[len(block) // 2:]
        return block[0]

    for p in range(CASCADE_PASSES + EXTRA_PASSES):
        if p >= CASCADE_PASSES:
            if clean_run >= EXTRA_CLEAN:
                break                                     # two clean rounds in a row: done
            k = max(4, k0 // EXTRA_BLOCK_DIV)
        fixed_before = fixed
        order = list(range(n))
        if p > 0:
            rng.shuffle(order)
        ids = []
        for s in range(0, n, k):
            blk = order[s:s + k]
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
            for other in member[i]:                       # the cascade step
                if parity(b, blocks[other]) != alice_par[other]:
                    work.append(other)
        if p >= CASCADE_PASSES:
            clean_run = clean_run + 1 if fixed == fixed_before else 0
        if p < CASCADE_PASSES - 1:
            k = min(n, k * 2)
    return b, fixed


# =====================================================================
#  4. Verification and privacy amplification
# =====================================================================
def verify_tag(bits, session):
    """32-bit hash of the corrected key. Equal tags -> keys are identical."""
    return hashlib.sha256((session + "".join(map(str, bits))).encode()).hexdigest()[:VERIFY_BITS // 4]


def h2(x):
    """Binary entropy: how many bits of uncertainty an error rate x represents."""
    return 0.0 if x <= 0 or x >= 1 else -x * math.log2(x) - (1 - x) * math.log2(1 - x)


def secure_length(n_key, qber, sample_size, leaked_bits):
    """
    How many bits of the key are still secret after Eve's possible knowledge?
        - Eve may know about  n_key * h2(e)  bits, where e is the error rate (plus a safety
          margin because the sample is finite)
        - error correction told the public  leaked_bits  parity bits
        - the verification hash told the public another VERIFY_BITS
        - SECURITY_BITS is kept as a safety margin
    """
    e_upper = min(0.5, qber + math.sqrt(math.log(1e6) / (2 * sample_size)))
    length = int(n_key * (1 - h2(e_upper)) - leaked_bits - VERIFY_BITS - SECURITY_BITS)
    return length, e_upper


def toeplitz_hash(key, seed_bits, out_len):
    """
    Privacy amplification: multiply the key by a random Toeplitz matrix (mod 2).
    Both nodes use the same public random seed, so both get the same shorter key.
    Even if Eve knows part of the input key, the output is (almost) uniformly random to her.
    """
    n = len(key)
    out = []
    for j in range(out_len):
        row = seed_bits[j:j + n][::-1]
        out.append(sum(k & r for k, r in zip(key, row)) & 1)
    return out


# =====================================================================
#  5. Saving the secret in this node's own secretQKD.json
# =====================================================================
class Stopwatch:
    """Times the key distribution, in total and stage by stage."""

    def __init__(self):
        self.started_at = datetime.now()
        self._t0 = self._last = time.perf_counter()
        self.stages = {}

    def lap(self, stage):
        """Close the current stage: record how long it took since the previous lap."""
        now = time.perf_counter()
        self.stages[stage] = round(now - self._last, 3)
        self._last = now

    def report(self):
        return {"total": round(time.perf_counter() - self._t0, 3), **self.stages}


def save_secret(bits, role, watch):
    """
    Save the key AND the timing into this node's own secretQKD.json (created if missing).
    The format never changes: every run writes exactly the same fields (see the top of this file).
    """
    record = {
        "node": os.path.basename(HERE),
        "role": role,
        "secret": "".join(map(str, bits)),
        "key_length_bits": len(bits),
        "started_at": watch.started_at.isoformat(timespec="seconds"),
        "finished_at": datetime.now().isoformat(timespec="seconds"),
        "time_seconds": watch.report(),
    }
    with open(SECRET_FILE, "w") as f:
        json.dump(record, f, indent=2)
    t = record["time_seconds"]
    print(f"[ ok  ] saved the key and timing to {SECRET_FILE}")
    print(f"[time ] key distribution took {t['total']} s  "
          + "  ".join(f"{k}={v}s" for k, v in t.items() if k != "total"))


def fingerprint(bits):
    """Short hash printed on screen so you can compare both nodes by eye. NOT sent anywhere."""
    return hashlib.sha256("".join(map(str, bits)).encode()).hexdigest()[:12]


# =====================================================================
#  6. Alice
# =====================================================================
def run_alice(chan, n_qubits, loss, noise, key_bits):
    print("[Alice] waiting for Bob to be ready ...")
    chan.session = chan.receive("00_bob_ready")["nonce"]      # session id, used in every tag
    watch = Stopwatch()                                        # start timing

    # BB84 steps 1-3: random bits + bases -> qubits -> through the (noisy, lossy) channel
    bits = [rng.randint(0, 1) for _ in range(n_qubits)]
    bases = [rng.choice(["Z", "X"]) for _ in range(n_qubits)]
    qubits = [encode_qubit(b, base) for b, base in zip(bits, bases)]
    qubits = channel_effects(qubits, loss, noise)
    chan.send("01_qubits", {"qubits": [None if q is None else circuit_to_ops(q) for q in qubits]},
              auth=False)                                      # quantum channel: no MAC possible
    print(f"[Alice] sent {n_qubits} qubits")

    # Sifting: keep qubits that ARRIVED and whose bases match
    det = chan.receive("02_bob_detect")
    chan.send("03_alice_bases", {"bases": bases})
    kept = [i for i in range(n_qubits) if det["detected"][i] and bases[i] == det["bases"][i]]
    key = [bits[i] for i in kept]
    print(f"[Alice] {sum(det['detected'])} qubits arrived, {len(key)} had matching bases (sifted key)")
    watch.lap("qubit_exchange")
    if len(key) < MIN_SIFTED:
        chan.abort(f"only {len(key)} sifted bits, use more qubits or less loss")
        raise AbortError("not enough sifted key bits. Increase --qubits or reduce --loss.")

    # Error estimation: reveal a random sample
    n_sample = max(1, int(len(key) * SAMPLE_FRACTION))
    positions = sorted(rng.sample(range(len(key)), n_sample))
    chan.send("04_sample", {"positions": positions, "bits": [key[i] for i in positions],
                            "key_bits": key_bits})
    verdict = chan.receive("05_verdict")
    print(f"[Alice] error check: {verdict['errors']} errors in {verdict['sample_size']} bits "
          f"-> QBER {verdict['qber']:.1%} -> {'ACCEPTED' if verdict['secure'] else 'REJECTED'}")
    if not verdict["secure"]:
        print("[Alice] key discarded: too many errors, someone may be listening.")
        chan.send("11_done", {})
        return

    drop = set(positions)
    key = [b for i, b in enumerate(key) if i not in drop]      # sample bits are public now
    watch.lap("sifting_and_error_check")

    # Error correction: just answer Bob's parity questions
    print(f"[Alice] error correction: answering Bob's parity questions ({len(key)} bits) ...")
    serve_parities(chan, key)
    watch.lap("error_correction")

    # Verification
    ok = chan.receive("07_verify")["tag"] == verify_tag(key, chan.session)
    chan.send("08_verify_result", {"ok": ok})
    if not ok:
        print("[Alice] verification FAILED: keys still differ, discarded.")
        chan.send("11_done", {})
        return

    # Privacy amplification
    pa = chan.receive("09_pa")
    final = toeplitz_hash(key, [int(c) for c in pa["seed"]], pa["out_len"])
    watch.lap("verification_and_privacy_amplification")
    print(f"[Alice] privacy amplification: {len(key)} bits -> {len(final)} secret bits")
    print(f"[Alice] final key fingerprint {fingerprint(final)}  (compare with Bob's by eye)")
    save_secret(final, "alice", watch)
    chan.send("11_done", {})


# =====================================================================
#  7. Bob
# =====================================================================
def run_bob(chan):
    chan.clear()                                               # start from a clean wire
    nonce = secrets.token_hex(8)
    chan.session = ""
    chan.send("00_bob_ready", {"nonce": nonce})
    chan.session = nonce
    print("[Bob  ] ready, waiting for Alice's qubits ...")

    # BB84 step 4: measure whatever arrived, in random bases
    raw = chan.receive("01_qubits", auth=False)["qubits"]
    watch = Stopwatch()                                        # start timing when the qubits arrive
    n = len(raw)
    bases = [rng.choice(["Z", "X"]) for _ in range(n)]
    detected = [0 if q is None else 1 for q in raw]
    arrived = [i for i in range(n) if raw[i] is not None]
    outcomes = measure_qubits([circuit_from_ops(raw[i]) for i in arrived], [bases[i] for i in arrived])
    results = {i: r for i, r in zip(arrived, outcomes)}
    print(f"[Bob  ] {len(arrived)} of {n} qubits arrived and were measured")
    chan.send("02_bob_detect", {"bases": bases, "detected": detected})

    # Sifting
    alice_bases = chan.receive("03_alice_bases")["bases"]
    kept = [i for i in range(n) if detected[i] and bases[i] == alice_bases[i]]
    key = [results[i] for i in kept]
    print(f"[Bob  ] {len(key)} positions with matching bases (sifted key)")
    watch.lap("qubit_exchange")

    # Error estimation
    sample = chan.receive("04_sample")
    pos = sample["positions"]
    errors = sum(1 for p, b in zip(pos, sample["bits"]) if key[p] != b)
    qber = errors / len(pos) if pos else 0.0
    secure = bool(pos) and qber <= QBER_THRESHOLD
    print(f"[Bob  ] error check: {errors} errors in {len(pos)} bits -> QBER {qber:.1%} "
          f"(limit {QBER_THRESHOLD:.0%}) -> {'ACCEPTED' if secure else 'REJECTED'}")
    chan.send("05_verdict", {"qber": qber, "errors": errors, "sample_size": len(pos), "secure": secure})
    if not secure:
        print("[Bob  ] key discarded.")
        chan.receive("11_done")
        chan.clear()
        return

    drop = set(pos)
    key = [b for i, b in enumerate(key) if i not in drop]
    watch.lap("sifting_and_error_check")

    # Error correction (Bob fixes his key to match Alice's)
    oracle = ParityOracle(chan)
    corrected, fixed = cascade(key, oracle, qber)
    oracle.done()
    print(f"[Bob  ] error correction (Cascade): fixed {fixed} errors, "
          f"{oracle.leaked} parity bits revealed to the public")
    watch.lap("error_correction")

    # Verification
    chan.send("07_verify", {"tag": verify_tag(corrected, chan.session)})
    if not chan.receive("08_verify_result")["ok"]:
        print("[Bob  ] verification FAILED: keys still differ, discarded.")
        chan.receive("11_done")
        chan.clear()
        return
    print(f"[Bob  ] verification passed: both nodes hold the same {len(corrected)}-bit key")

    # Privacy amplification
    length, e_upper = secure_length(len(corrected), qber, len(pos), oracle.leaked)
    out_len = min(sample["key_bits"], length)
    print(f"[Bob  ] secure length estimate: {length} bits (error rate bound {e_upper:.1%}); "
          f"final key will be {max(out_len, 0)} bits")
    if out_len < MIN_KEY_BITS:
        chan.abort("not enough secure key after privacy amplification")
        raise AbortError("not enough secure key after privacy amplification. Increase --qubits.")
    seed = "".join(str(secrets.randbits(1)) for _ in range(out_len + len(corrected) - 1))
    chan.send("09_pa", {"seed": seed, "out_len": out_len})
    final = toeplitz_hash(corrected, [int(c) for c in seed], out_len)
    watch.lap("verification_and_privacy_amplification")
    print(f"[Bob  ] final key fingerprint {fingerprint(final)}  (compare with Alice's by eye)")
    save_secret(final, "bob", watch)

    chan.receive("11_done")                                    # wait until Alice is finished
    chan.clear()


# =====================================================================
#  8. Start-up
# =====================================================================
def detect_role():
    folder = os.path.basename(HERE).lower()
    if folder.endswith("_a"):
        return "alice"
    if folder.endswith("_b"):
        return "bob"
    return None


def main():
    p = argparse.ArgumentParser(description="Complete BB84 QKD between Node A (Alice) and Node B (Bob)")
    p.add_argument("--role", choices=["alice", "bob"], help="default: from the folder name")
    p.add_argument("--qubits", type=int, default=8000, help="Alice: qubits to send")
    p.add_argument("--key-bits", type=int, default=256, help="Alice: wanted length of the final key")
    p.add_argument("--loss", type=float, default=0.10, help="Alice: chance a qubit is lost in the channel")
    p.add_argument("--noise", type=float, default=0.03, help="Alice: chance a qubit is corrupted")
    p.add_argument("--channel", default=os.environ.get(
        "QKD_CHANNEL_DIR", os.path.join(tempfile.gettempdir(), "qkd_channel")),
        help="shared folder for the JSON messages")
    p.add_argument("--timeout", type=int, default=240, help="seconds to wait for the other node")
    args = p.parse_args()

    role = args.role or detect_role()
    if role is None:
        sys.exit("Can't tell the role from the folder name. Use --role alice or --role bob.")

    print(f"[{role.upper()}] channel folder: {args.channel}")
    chan = Channel(args.channel, args.timeout)
    try:
        if role == "alice":
            run_alice(chan, args.qubits, args.loss, args.noise, args.key_bits)
        else:
            run_bob(chan)
    except (AuthError, AbortError, TimeoutError) as e:
        print(f"[{role.upper()}] STOPPED: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
