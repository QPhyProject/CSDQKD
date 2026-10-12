"""
ABMKD.py - Post-Quantum Key Distribution (ML-KEM-768 / Kyber-768) for Node B (Bob)
====================================================================================

Implements NIST Post-Quantum Cryptography Standard ML-KEM-768:
  1. Node B (Bob) reads Node A's public key (1184 bytes).
  2. Encapsulates against the public key, producing:
     - 1088-byte ciphertext to be sent back to Node A.
     - 32-byte shared secret key.
  3. Maps secret key, parameters, and encapsulation metrics directly into secretMKD.json.
"""

import argparse
import base64
import json
import secrets
import sys
import time
from datetime import datetime
from pathlib import Path

from pqcrypto.kem.ml_kem_768 import encaps

DEFAULT_FOLDER = Path(__file__).resolve().parent
JSON_FILE = DEFAULT_FOLDER / "secretMKD.json"
NODE_A_FILE = DEFAULT_FOLDER.parent / "Node_A" / "secretMKD.json"
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


def get_default_mkd_data(node_name: str = "Node_B", role_name: str = "Bob") -> dict:
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
            "encapsulation_time_ms": 0.0,
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


def establish(json_path: Path = JSON_FILE, peer_path: Path = NODE_A_FILE) -> dict:
    """Read Alice's public key, encapsulate to derive shared secret and ciphertext."""
    start_time = time.perf_counter()
    data = load_template_data(json_path)
    peer_data = read_json(peer_path)

    public_key_str = peer_data.get("public_key") or peer_data.get("public_key_hex")
    if not public_key_str:
        print("Node B: Alice's public key is not available yet.")
        print("Run Node_A/ABMKD.py first, then run this script.")
        data["status"] = "PENDING"
        write_json(json_path, data)
        return data

    public_key = decode_bytes(public_key_str)
    if len(public_key) != 1184:
        raise ValueError(f"Invalid ML-KEM-768 public key size: {len(public_key)} bytes (expected 1184).")

    # Perform encapsulation
    t_encap_start = time.perf_counter()
    ciphertext, shared_secret = encaps(public_key)
    encap_ms = round((time.perf_counter() - t_encap_start) * 1000, 4)

    total_elapsed_ms = round((time.perf_counter() - start_time) * 1000, 3)
    finish_timestamp = datetime.now().isoformat()
    session_id = peer_data.get("session_id") or secrets.token_hex(8)

    data["node"] = "Node_B"
    data["protocol"] = "ML_KEM_Kyber768"
    data["role"] = "Bob"
    data["status"] = "SUCCESS"
    data["timestamp"] = finish_timestamp
    data["session_id"] = session_id
    data["secret_key_hex"] = shared_secret.hex()
    data["secret_key"] = shared_secret.hex()
    data["shared_secret"] = encode_b64(shared_secret)
    data["ciphertext"] = encode_b64(ciphertext)
    data["ciphertext_hex"] = ciphertext.hex()

    data["metrics"]["encapsulation_time_ms"] = encap_ms
    data["metrics"]["total_latency_ms"] = total_elapsed_ms
    data["metrics"]["ciphertext_size_bytes"] = len(ciphertext)
    data["metrics"]["public_key_size_bytes"] = len(public_key)

    write_json(json_path, data)
    print("Node B: Encapsulation successful!")
    print(f"Node B: Ciphertext generated ({len(ciphertext)} bytes).")
    print(f"Node B: Shared secret established ({len(shared_secret)} bytes / 256 bits).")
    print(f"Node B: Secret key hex: {shared_secret.hex()}")
    print(f"Node B: Encapsulation time: {encap_ms} ms (Total: {total_elapsed_ms} ms)")
    return data


def run_bob() -> dict:
    """Run Bob's MKD encapsulation."""
    return establish()


def main():
    parser = argparse.ArgumentParser(description="ML-KEM-768 Post-Quantum Key Distribution (Node B - Bob).")
    parser.parse_args()

    run_bob()


if __name__ == "__main__":
    main()