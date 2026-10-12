"""
ABMKD.py - Post-Quantum Key Distribution (ML-KEM-768 / Kyber-768) for Node A (Alice)
====================================================================================

Implements NIST Post-Quantum Cryptography Standard ML-KEM-768:
  1. Node A (Alice) generates an ML-KEM-768 public/private keypair.
  2. Public key (1184 bytes) is published for Node B (Bob).
  3. When Node B encapsulates and returns ciphertext (1088 bytes),
     Alice decapsulates using her private key to recover the 32-byte shared secret.
  4. Maps secret key, parameters, and latency metrics directly into secretMKD.json.
"""

import argparse
import base64
import json
import secrets
import sys
import time
from datetime import datetime
from pathlib import Path

from pqcrypto.kem.ml_kem_768 import keygen, decaps

DEFAULT_FOLDER = Path(__file__).resolve().parent
JSON_FILE = DEFAULT_FOLDER / "secretMKD.json"
NODE_B_FILE = DEFAULT_FOLDER.parent / "Node_B" / "secretMKD.json"
SHARED_FILE = DEFAULT_FOLDER.parent / "Shared_Files" / "ABshared.json"


def encode_b64(data: bytes) -> str:
    """Encode bytes to ASCII base64 string."""
    return base64.b64encode(data).decode("ascii")


def decode_bytes(val: str | None) -> bytes:
    """Decode bytes from either Hex or Base64 string."""
    if not val:
        return b""
    try:
        return bytes.fromhex(val)
    except ValueError:
        pass
    return base64.b64decode(val, validate=True)


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


def get_default_mkd_data(node_name: str = "Node_A", role_name: str = "Alice") -> dict:
    return {
        "node": node_name,
        "protocol": "ML_KEM_Kyber768",
        "role": role_name,
        "status": "IDLE",
        "timestamp": None,
        "session_id": None,
        "kem_parameters": {
            "algorithm": "Kyber-768",
            "security_level": "NIST_Level_3",
            "shared_secret_length_bytes": 32,
        },
        "secret_key_hex": None,
        "metrics": {
            "decapsulation_time_ms": 0.0,
            "total_latency_ms": 0.0,
            "ciphertext_size_bytes": 1088,
            "public_key_size_bytes": 1184,
        },
    }


def load_template_data(path: Path = JSON_FILE) -> dict:
    data = read_json(path)
    template = get_default_mkd_data()
    for k, v in template.items():
        if k not in data:
            data[k] = v
        elif isinstance(v, dict) and isinstance(data[k], dict):
            for sub_k, sub_v in v.items():
                if sub_k not in data[k]:
                    data[k][sub_k] = sub_v
    return data


def init(force_new: bool = False, json_path: Path = JSON_FILE) -> dict:
    """Generate or retrieve Alice's ML-KEM-768 keypair and publish public key."""
    start_time = time.perf_counter()
    data = load_template_data(json_path)

    # Check if a valid private key already exists and fresh generation was not requested
    existing_pk = data.get("public_key")
    existing_sk = data.get("private_key")
    if not force_new and existing_pk and existing_sk:
        try:
            pk_bytes = decode_bytes(existing_pk)
            sk_bytes = decode_bytes(existing_sk)
            if len(pk_bytes) == 1184 and len(sk_bytes) == 2400:
                print("Node A: Using existing ML-KEM-768 key pair.")
                return data
        except Exception:
            pass

    public_key, private_key = keygen()
    session_id = secrets.token_hex(8)

    data["node"] = "Node_A"
    data["protocol"] = "ML_KEM_Kyber768"
    data["role"] = "Alice"
    data["status"] = "PENDING"
    data["timestamp"] = datetime.now().isoformat()
    data["session_id"] = session_id
    data["public_key"] = encode_b64(public_key)
    data["public_key_hex"] = public_key.hex()
    data["private_key"] = encode_b64(private_key)
    data["secret_key_hex"] = None
    data["secret_key"] = None
    data["shared_secret"] = None

    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 3)
    data["metrics"]["total_latency_ms"] = elapsed_ms
    data["metrics"]["public_key_size_bytes"] = len(public_key)

    write_json(json_path, data)
    print("Node A: Key pair generated (1184-byte public key, 2400-byte private key).")
    print(f"Node A: Public key saved to {json_path.name}. Run Node B to encapsulate.")
    return data


def establish(json_path: Path = JSON_FILE, peer_path: Path = NODE_B_FILE) -> dict:
    """Decapsulate ciphertext received from Node B and recover shared secret."""
    start_time = time.perf_counter()
    data = load_template_data(json_path)
    peer_data = read_json(peer_path)

    ciphertext_str = peer_data.get("ciphertext") or peer_data.get("ciphertext_hex")
    if not ciphertext_str:
        print("Node A: Bob's ciphertext is not available yet.")
        print("Run Node_B/ABMKD.py, then run this command again.")
        return data

    private_key_str = data.get("private_key") or data.get("private_key_hex")
    if not private_key_str:
        print("Node A: No private key found. Run init first.")
        init(json_path=json_path)
        data = load_template_data(json_path)
        private_key_str = data.get("private_key")

    private_key = decode_bytes(private_key_str)
    ciphertext = decode_bytes(ciphertext_str)

    if len(private_key) != 2400:
        raise ValueError(f"Invalid ML-KEM-768 private key size: {len(private_key)} bytes (expected 2400).")
    if len(ciphertext) != 1088:
        raise ValueError(f"Invalid ML-KEM-768 ciphertext size: {len(ciphertext)} bytes (expected 1088).")

    # Perform decapsulation
    t_decap_start = time.perf_counter()
    shared_secret = decaps(private_key, ciphertext)
    decap_ms = round((time.perf_counter() - t_decap_start) * 1000, 4)

    total_elapsed_ms = round((time.perf_counter() - start_time) * 1000, 3)
    finish_timestamp = datetime.now().isoformat()
    session_id = peer_data.get("session_id") or data.get("session_id") or secrets.token_hex(8)

    data["status"] = "SUCCESS"
    data["timestamp"] = finish_timestamp
    data["session_id"] = session_id
    data["secret_key_hex"] = shared_secret.hex()
    data["secret_key"] = shared_secret.hex()
    data["shared_secret"] = encode_b64(shared_secret)

    data["metrics"]["decapsulation_time_ms"] = decap_ms
    data["metrics"]["total_latency_ms"] = total_elapsed_ms
    data["metrics"]["ciphertext_size_bytes"] = len(ciphertext)
    data["metrics"]["public_key_size_bytes"] = len(decode_bytes(data.get("public_key")))

    write_json(json_path, data)
    print("Node A: Decapsulation successful!")
    print(f"Node A: Shared secret established ({len(shared_secret)} bytes / 256 bits).")
    print(f"Node A: Secret key hex: {shared_secret.hex()}")
    print(f"Node A: Decapsulation time: {decap_ms} ms (Total: {total_elapsed_ms} ms)")
    return data


def run_alice(action: str | None = None, force_new: bool = False) -> dict:
    """Run Alice's MKD procedure automatically based on state."""
    data = read_json(JSON_FILE)
    peer_data = read_json(NODE_B_FILE)

    if action == "init":
        return init(force_new=force_new)
    elif action == "establish":
        return establish()

    # Automatic mode:
    # If no key pair exists or force_new -> init
    if not data.get("public_key") or force_new:
        return init(force_new=force_new)

    # If Bob has already provided ciphertext and Alice hasn't established yet (or re-establishing)
    if peer_data.get("ciphertext"):
        return establish()

    # Otherwise ensure keypair is ready
    return init(force_new=False)


def run_mkd_exchange(
    node_a_dir: Path | None = None,
    node_b_dir: Path | None = None,
) -> tuple[dict, dict]:
    """Execute complete simulated MKD exchange between Node A and Node B in sequence."""
    base = DEFAULT_FOLDER.parent if DEFAULT_FOLDER.name in ("Node_A", "Node_B") else DEFAULT_FOLDER
    a_dir = node_a_dir or (base / "Node_A")
    b_dir = node_b_dir or (base / "Node_B")

    a_json = a_dir / "secretMKD.json"
    b_json = b_dir / "secretMKD.json"

    # Step 1: Alice generates keypair
    init(force_new=True, json_path=a_json)

    # Step 2: Bob encapsulates against Alice's public key
    import importlib.util
    b_script = b_dir / "ABMKD.py"
    spec = importlib.util.spec_from_file_location("bob_mkd", b_script)
    bob_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bob_mod)
    bob_result = bob_mod.establish(json_path=b_json, peer_path=a_json)

    # Step 3: Alice decapsulates Bob's ciphertext
    alice_result = establish(json_path=a_json, peer_path=b_json)

    return alice_result, bob_result


def main():
    parser = argparse.ArgumentParser(description="ML-KEM-768 Post-Quantum Key Distribution (Node A - Alice).")
    parser.add_argument("action", nargs="?", choices=["init", "establish"], help="Optional explicit action")
    parser.add_argument("--new", action="store_true", help="Force generate a fresh keypair")
    parser.add_argument("--both", action="store_true", help="Run full Alice + Bob exchange automatically")
    args = parser.parse_args()

    if args.both:
        print("[CSDQKD] Running full ML-KEM-768 Post-Quantum Key Exchange...")
        a_res, b_res = run_mkd_exchange()
        assert a_res["secret_key_hex"] == b_res["secret_key_hex"], "Keys do not match!"
        print("[CSDQKD] Exchange complete! Both nodes have established identical 256-bit shared keys.")
    else:
        run_alice(action=args.action, force_new=args.new)


if __name__ == "__main__":
    main()