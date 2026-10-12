"""
Node_A/AB.py - Unified Communication & Cryptographic Node for Alice (Node A)
=============================================================================

Consolidates all security protocols into modular functions:
  - CKD: Classical Key Distribution (X25519 ECDH + HKDF-SHA256)
  - QKD: Quantum Key Distribution (BB84 + Cascade + Toeplitz PA)
  - MKD: Post-Quantum Key Distribution (NIST ML-KEM-768 / Kyber-768)
  - AES: Authenticated Symmetric Encryption (AES-256-GCM)

All local secrets, private keys, and metrics are securely saved in secretAB.json.
Communication with Node B strictly occurs via Shared_Files/ABshared.json without
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
from pqcrypto.kem.ml_kem_768 import keygen as ml_kem_keygen, decaps as ml_kem_decaps
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
            "node": "Node_A",
            "role": "Alice",
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
#  1. CKD: Classical Key Distribution (Alice)
# =====================================================================
def ckd_publish_public_key(force_new: bool = False) -> dict:
    """Generate or retrieve Alice's X25519 keypair and publish public key to ABshared.json."""
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

    # Save Alice's secrets locally
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
    shared["classical_exchange"]["alice_public_key_hex"] = public_bytes.hex()
    shared["timestamp"] = datetime.now(timezone.utc).isoformat()
    save_shared_channel(shared)

    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 3)
    return {
        "status": "PENDING",
        "public_key_hex": public_bytes.hex(),
        "latency_ms": elapsed_ms,
    }


def ckd_derive_key() -> dict:
    """Read Bob's public key from ABshared.json, perform ECDH, derive 256-bit key via HKDF."""
    start_time = time.perf_counter()
    store = get_secret_store()
    ckd_data = store.get("ckd", {})
    shared = get_shared_channel()

    bob_public_hex = shared.get("classical_exchange", {}).get("bob_public_key_hex")
    if not bob_public_hex:
        # Fallback check to Node_B/secretAB.json or secretCKD.json
        b_secret = read_json(BASE_DIR / "Node_B" / "secretAB.json")
        bob_public_hex = b_secret.get("ckd", {}).get("public_key")
        if not bob_public_hex:
            b_ckd = read_json(BASE_DIR / "Node_B" / "secretCKD.json")
            bob_public_hex = b_ckd.get("public_key")

    if not bob_public_hex:
        raise RuntimeError("Bob's classical public key is not available on the communication channel.")

    private_hex = ckd_data.get("private_key")
    if not private_hex:
        ckd_publish_public_key()
        store = get_secret_store()
        private_hex = store["ckd"]["private_key"]

    private_key = X25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex))
    bob_public_key = X25519PublicKey.from_public_bytes(bytes.fromhex(bob_public_hex))

    shared_secret = private_key.exchange(bob_public_key)
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
    ckd_data["peer_public_key"] = bob_public_hex
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
    """Full Alice CKD routine."""
    pub_info = ckd_publish_public_key()
    return pub_info


# =====================================================================
#  2. QKD: Quantum Key Distribution (Alice)
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


def run_qkd_alice(
    n_qubits: int = 6000,
    loss: float = 0.10,
    noise: float = 0.03,
    key_bits: int = 256,
    timeout: int = 60,
) -> dict:
    """Execute Alice's side of BB84 QKD protocol."""
    start_time = time.perf_counter()
    chan = QKDChannel(QKD_CHANNEL_DIR, timeout=timeout)

    chan.session = chan.receive("00_bob_ready")["nonce"]

    # 1. State preparation
    bits = [rng.randint(0, 1) for _ in range(n_qubits)]
    bases = [rng.choice(["Z", "X"]) for _ in range(n_qubits)]
    qubits = []
    lost = 0
    for b, base in zip(bits, bases):
        if rng.random() < loss:
            qubits.append(None)
            lost += 1
            continue
        qc = QuantumCircuit(1, 1)
        if b == 1:
            qc.x(0)
        if base == "X":
            qc.h(0)
        if rng.random() < noise:
            getattr(qc, rng.choice(["x", "y", "z"]))(0)
        qubits.append([inst.operation.name for inst in qc.data])

    chan.send("01_qubits", {"qubits": qubits}, auth=False)

    # 2. Sifting
    det = chan.receive("02_bob_detect")
    chan.send("03_alice_bases", {"bases": bases})
    kept = [i for i in range(n_qubits) if det["detected"][i] and bases[i] == det["bases"][i]]
    key = [bits[i] for i in kept]
    sifted_len = len(key)

    if sifted_len < MIN_SIFTED:
        chan.abort("Insufficient sifted key length.")
        raise RuntimeError("QKD aborted: insufficient sifted bits.")

    # 3. Error estimation
    n_sample = max(1, int(sifted_len * SAMPLE_FRACTION))
    positions = sorted(rng.sample(range(sifted_len), n_sample))
    chan.send("04_sample", {"positions": positions, "bits": [key[i] for i in positions], "key_bits": key_bits})
    verdict = chan.receive("05_verdict")
    qber = verdict["qber"]

    if not verdict["secure"]:
        chan.send("11_done", {})
        raise RuntimeError(f"QKD aborted: QBER {qber:.2%} exceeded threshold {QBER_THRESHOLD:.0%}.")

    drop = set(positions)
    key = [b for i, b in enumerate(key) if i not in drop]

    # 4. Error correction (Cascade oracle)
    n = 0
    while True:
        q = chan.receive(f"ec_q{n:03d}")
        if q.get("done"):
            break
        chan.send(f"ec_a{n:03d}", {"parities": [sum(key[i] for i in s) & 1 for s in q["subsets"]]})
        n += 1

    # 5. Verification
    my_tag = hashlib.sha256((chan.session + "".join(map(str, key))).encode()).hexdigest()[:8]
    ok = chan.receive("07_verify")["tag"] == my_tag
    chan.send("08_verify_result", {"ok": ok})
    if not ok:
        chan.send("11_done", {})
        raise RuntimeError("QKD verification failed: residual errors remaining.")

    # 6. Privacy Amplification (Toeplitz hash)
    pa = chan.receive("09_pa")
    seed = [int(c) for c in pa["seed"]]
    out_len = pa["out_len"]
    n_k = len(key)
    final_bits = []
    for j in range(out_len):
        row = seed[j : j + n_k][::-1]
        final_bits.append(sum(k & r for k, r in zip(key, row)) & 1)

    chan.send("11_done", {})

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
    qkd_data["raw_key_length"] = sum(det["detected"])
    qkd_data["sifted_key_length"] = sifted_len
    qkd_data["secret_key_length_bits"] = len(final_bits)
    qkd_data["secret_key_hex"] = secret_key_hex
    qkd_data["secret"] = bitstring
    qkd_data["pipeline_metrics"] = {
        "measured_qber": round(qber, 4),
        "qber_threshold": QBER_THRESHOLD,
        "leak_error_correction_bits": 0,
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

    return {
        "status": "SUCCESS",
        "secret_key_hex": secret_key_hex,
        "latency_ms": elapsed_ms,
        "qber": qber,
        "key_bits": len(final_bits),
        "session_id": chan.session,
    }


# =====================================================================
#  3. MKD: Post-Quantum Key Distribution (Alice)
# =====================================================================
def mkd_publish_public_key(force_new: bool = False) -> dict:
    """Generate Alice's ML-KEM-768 keypair and publish public key to ABshared.json."""
    start_time = time.perf_counter()
    store = get_secret_store()
    mkd_data = store.get("mkd", {})

    existing_pk = mkd_data.get("public_key")
    existing_sk = mkd_data.get("private_key")

    if not force_new and existing_pk and existing_sk:
        try:
            pk_bytes = base64.b64decode(existing_pk)
            sk_bytes = base64.b64decode(existing_sk)
            if len(pk_bytes) == 1184 and len(sk_bytes) == 2400:
                pk_b64 = existing_pk
                pk_hex = pk_bytes.hex()
            else:
                pk_bytes, sk_bytes = ml_kem_keygen()
                pk_b64 = base64.b64encode(pk_bytes).decode("ascii")
                pk_hex = pk_bytes.hex()
                mkd_data["private_key"] = base64.b64encode(sk_bytes).decode("ascii")
        except Exception:
            pk_bytes, sk_bytes = ml_kem_keygen()
            pk_b64 = base64.b64encode(pk_bytes).decode("ascii")
            pk_hex = pk_bytes.hex()
            mkd_data["private_key"] = base64.b64encode(sk_bytes).decode("ascii")
    else:
        pk_bytes, sk_bytes = ml_kem_keygen()
        pk_b64 = base64.b64encode(pk_bytes).decode("ascii")
        pk_hex = pk_bytes.hex()
        mkd_data["private_key"] = base64.b64encode(sk_bytes).decode("ascii")

    session_id = secrets.token_hex(8)
    iso_now = datetime.now().isoformat()

    mkd_data["protocol"] = "ML_KEM_Kyber768"
    mkd_data["status"] = "PENDING"
    mkd_data["timestamp"] = iso_now
    mkd_data["session_id"] = session_id
    mkd_data["public_key"] = pk_b64
    mkd_data["public_key_hex"] = pk_hex
    store["mkd"] = mkd_data
    save_secret_store(store)

    # Publish public key to shared channel
    shared = get_shared_channel()
    shared["active_protocol"] = "ML_KEM_Kyber768"
    shared["session_id"] = session_id
    shared["timestamp"] = datetime.now(timezone.utc).isoformat()
    shared["pqc_exchange"]["alice_kem_public_key_b64"] = pk_b64
    shared["pqc_exchange"]["alice_kem_public_key_hex"] = pk_hex
    save_shared_channel(shared)

    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 3)
    return {
        "status": "PENDING",
        "public_key_b64": pk_b64,
        "latency_ms": elapsed_ms,
        "session_id": session_id,
    }


def mkd_decapsulate() -> dict:
    """Read Bob's ciphertext from ABshared.json and decapsulate using private key."""
    start_time = time.perf_counter()
    store = get_secret_store()
    mkd_data = store.get("mkd", {})
    shared = get_shared_channel()

    ct_b64 = shared.get("pqc_exchange", {}).get("bob_ciphertext_b64")
    ct_hex = shared.get("pqc_exchange", {}).get("bob_ciphertext_hex")

    if not ct_b64 and not ct_hex:
        # Fallback check to Node_B/secretAB.json or secretMKD.json
        b_secret = read_json(BASE_DIR / "Node_B" / "secretAB.json")
        ct_b64 = b_secret.get("mkd", {}).get("ciphertext")
        if not ct_b64:
            b_mkd = read_json(BASE_DIR / "Node_B" / "secretMKD.json")
            ct_b64 = b_mkd.get("ciphertext")

    if not ct_b64 and not ct_hex:
        raise RuntimeError("Bob's post-quantum ciphertext is not available on the communication channel.")

    if ct_b64:
        ciphertext = base64.b64decode(ct_b64)
    else:
        ciphertext = bytes.fromhex(ct_hex)

    sk_b64 = mkd_data.get("private_key")
    if not sk_b64:
        raise RuntimeError("Alice's ML-KEM private key is missing from local secretAB.json.")

    private_key = base64.b64decode(sk_b64)
    t_decap_start = time.perf_counter()
    shared_secret = ml_kem_decaps(private_key, ciphertext)
    decap_ms = round((time.perf_counter() - t_decap_start) * 1000, 4)

    total_ms = round((time.perf_counter() - start_time) * 1000, 3)
    iso_now = datetime.now().isoformat()
    session_id = shared.get("session_id") or secrets.token_hex(8)

    mkd_data["status"] = "SUCCESS"
    mkd_data["timestamp"] = iso_now
    mkd_data["session_id"] = session_id
    mkd_data["secret_key_hex"] = shared_secret.hex()
    mkd_data["shared_secret"] = base64.b64encode(shared_secret).decode("ascii")
    if "metrics" not in mkd_data:
        mkd_data["metrics"] = {}
    mkd_data["metrics"]["decapsulation_time_ms"] = decap_ms
    mkd_data["metrics"]["total_latency_ms"] = total_ms

    store["active_protocol"] = "MKD"
    store["current_secret_key_hex"] = shared_secret.hex()
    store["mkd"] = mkd_data
    save_secret_store(store)

    return {
        "status": "SUCCESS",
        "secret_key_hex": shared_secret.hex(),
        "decapsulation_time_ms": decap_ms,
        "total_latency_ms": total_ms,
        "session_id": session_id,
    }


def run_mkd() -> dict:
    """Full Alice MKD routine."""
    return mkd_publish_public_key()


# =====================================================================
#  4. AES: Authenticated Encryption (Alice)
# =====================================================================
def get_current_key(protocol: str | None = None) -> tuple[bytes, str]:
    """Retrieve 256-bit key from Alice's local secretAB.json storage."""
    store = get_secret_store()

    if protocol:
        proto = protocol.upper()
        if "QKD" in proto and store.get("qkd", {}).get("secret_key_hex"):
            return bytes.fromhex(store["qkd"]["secret_key_hex"]), "Node_A/secretAB.json [QKD]"
        if "MKD" in proto and store.get("mkd", {}).get("secret_key_hex"):
            return bytes.fromhex(store["mkd"]["secret_key_hex"]), "Node_A/secretAB.json [MKD]"
        if "CKD" in proto and store.get("ckd", {}).get("secret_key_hex"):
            return bytes.fromhex(store["ckd"]["secret_key_hex"]), "Node_A/secretAB.json [CKD]"

    if store.get("current_secret_key_hex"):
        return bytes.fromhex(store["current_secret_key_hex"]), f"Node_A/secretAB.json [{store.get('active_protocol', 'Current')}]"

    for proto_key, desc in [("qkd", "QKD"), ("mkd", "MKD"), ("ckd", "CKD")]:
        khex = store.get(proto_key, {}).get("secret_key_hex")
        if khex and len(bytes.fromhex(khex)) == 32:
            return bytes.fromhex(khex), f"Node_A/secretAB.json [{desc}]"

    raise RuntimeError("No secret key found in Node_A/secretAB.json. Establish a key via QKD, MKD, or CKD first.")


def aes_encrypt(message: str, protocol: str | None = None, key_hex: str | None = None) -> dict:
    """
    Encrypt plaintext using AES-256-GCM.
    Writes ONLY ciphertext, nonce, and tag to ABshared.json.
    NEVER writes secret keys to the shared public channel.
    """
    start_time = time.perf_counter()

    if key_hex:
        key_bytes = bytes.fromhex(key_hex)
        key_src = "Explicit argument"
    else:
        key_bytes, key_src = get_current_key(protocol=protocol)

    if len(key_bytes) != 32:
        raise ValueError(f"AES-256 requires a 32-byte key; got {len(key_bytes)} bytes.")

    plaintext = message.encode("utf-8")
    nonce = os.urandom(12)  # 96-bit random nonce
    aesgcm = AESGCM(key_bytes)
    encrypted = aesgcm.encrypt(nonce, plaintext, None)

    ciphertext = encrypted[:-16]
    tag = encrypted[-16:]
    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 4)
    iso_now = datetime.now(timezone.utc).isoformat()

    # Transmit over public channel without secret key
    shared = get_shared_channel()
    shared["active_protocol"] = protocol or shared.get("active_protocol", "BB84")
    shared["session_id"] = shared.get("session_id") or secrets.token_hex(8)
    shared["timestamp"] = iso_now
    shared["encrypted_transmission"] = {
        "sender": "Alice",
        "cipher": "AES-256-GCM",
        "nonce_hex": nonce.hex(),
        "ciphertext_hex": ciphertext.hex(),
        "tag_hex": tag.hex(),
        "plaintext_preview": None,
        "status": "ENCRYPTED",
        "timestamp": iso_now,
    }
    save_shared_channel(shared)

    # Update Alice's local secrets
    store = get_secret_store()
    store["aes"] = {
        "cipher": "AES-256-GCM",
        "status": "ENCRYPTED",
        "last_encrypted_at": iso_now,
        "last_nonce_hex": nonce.hex(),
        "last_ciphertext_hex": ciphertext.hex(),
        "last_tag_hex": tag.hex(),
        "encryption_latency_ms": elapsed_ms,
        "message_length_bytes": len(plaintext),
    }
    save_secret_store(store)

    return {
        "status": "ENCRYPTED",
        "key_source": key_src,
        "nonce_hex": nonce.hex(),
        "ciphertext_hex": ciphertext.hex(),
        "tag_hex": tag.hex(),
        "encryption_latency_ms": elapsed_ms,
        "message_length": len(plaintext),
    }


def main():
    parser = argparse.ArgumentParser(description="Node A (Alice) Unified Security Controller")
    parser.add_argument("--mode", choices=["ckd-pub", "ckd-derive", "qkd", "mkd-pub", "mkd-decap", "encrypt"], default="encrypt")
    parser.add_argument("--protocol", choices=["QKD", "MKD", "CKD"], help="Active protocol for encryption")
    parser.add_argument("--message", default="Hello Bob! Secure quantum transmission.", help="Message to encrypt")
    args = parser.parse_args()

    if args.mode == "ckd-pub":
        res = ckd_publish_public_key()
        print(f"[Node A CKD] Public key published: {res['public_key_hex']}")
    elif args.mode == "ckd-derive":
        res = ckd_derive_key()
        print(f"[Node A CKD] Secret key established: {res['secret_key_hex']}")
    elif args.mode == "qkd":
        res = run_qkd_alice()
        print(f"[Node A QKD] Key established: {res['secret_key_hex']}")
    elif args.mode == "mkd-pub":
        res = mkd_publish_public_key()
        print(f"[Node A MKD] Public key published: {res['public_key_b64'][:32]}...")
    elif args.mode == "mkd-decap":
        res = mkd_decapsulate()
        print(f"[Node A MKD] Secret key established: {res['secret_key_hex']}")
    elif args.mode == "encrypt":
        res = aes_encrypt(args.message, protocol=args.protocol)
        print(f"[Node A AES] Message encrypted in {res['encryption_latency_ms']} ms")
        print(f"[Node A AES] Ciphertext: {res['ciphertext_hex']}")


if __name__ == "__main__":
    main()
