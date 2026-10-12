import argparse
import json
import secrets
import time
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Default folder and file locations
DEFAULT_FOLDER = Path(__file__).resolve().parent


def read_json(path: Path) -> dict:
    """Read a JSON file safely, returning an empty dict if the file does not exist."""
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)
    except (json.JSONDecodeError, OSError):
        return {}


def write_json(path: Path, data: dict) -> None:
    """Write data to a JSON file formatted with 4 spaces indent."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def get_default_ckd_data(node_name: str, role_name: str) -> dict:
    """Return the baseline template structure for secretCKD.json."""
    return {
        "node": node_name,
        "protocol": "ECDH_X25519",
        "role": role_name,
        "status": "IDLE",
        "timestamp": None,
        "session_id": None,
        "key_parameters": {
            "curve": "X25519",
            "key_length_bits": 256,
        },
        "secret_key_hex": None,
        "key_derivation": {
            "kdf": "HKDF-SHA256",
            "salt_hex": None,
            "info": "CSDQKD-Classical-Key-Exchange",
        },
        "metrics": {
            "latency_ms": 0.0,
            "established_at": None,
        },
    }


def load_or_generate_keypair(
    data: dict, force_new: bool = False
) -> tuple[X25519PrivateKey, bytes, bytes]:
    """Load existing private key from data dict, or generate a fresh X25519 keypair."""
    if not force_new:
        try:
            private_hex = data.get("private_key") or data.get("private_key_hex", "")
            private_bytes = bytes.fromhex(private_hex)
            if len(private_bytes) == 32:
                private_key = X25519PrivateKey.from_private_bytes(private_bytes)
                public_bytes = private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
                return private_key, private_bytes, public_bytes
        except (ValueError, TypeError):
            pass

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
    return private_key, private_bytes, public_bytes


def derive_secret_key(
    private_key: X25519PrivateKey,
    peer_public_bytes: bytes,
    info_str: str = "CSDQKD-Classical-Key-Exchange",
    salt_bytes: bytes | None = None,
    length: int = 32,
) -> tuple[bytes, bytes]:
    """
    Perform X25519 ECDH exchange and HKDF-SHA256 key derivation.
    Returns (shared_secret, derived_secret_key).
    """
    if len(peer_public_bytes) != 32:
        raise ValueError("Peer public key must be exactly 32 bytes.")

    peer_public_key = X25519PublicKey.from_public_bytes(peer_public_bytes)
    shared_secret = private_key.exchange(peer_public_key)

    info_bytes = info_str.encode("utf-8") if isinstance(info_str, str) else info_str
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt_bytes,
        info=info_bytes,
    ).derive(shared_secret)

    return shared_secret, derived_key


def run_ckd(
    folder: Path | None = None,
    role: str | None = None,
    force_new: bool = False,
) -> dict:
    """
    Execute Classical Key Distribution (CKD) for the node.
    Maps keys, parameters, and metrics directly to secretCKD.json.
    """
    start_time = time.perf_counter()
    start_timestamp = datetime.now().isoformat()

    folder = folder or DEFAULT_FOLDER
    node_name = folder.name
    if not role:
        role = "Alice" if node_name == "Node_A" else "Bob"

    peer_node = "Node_B" if node_name == "Node_A" else "Node_A"
    peer_role = "Bob" if role == "Alice" else "Alice"

    my_file = folder / "secretCKD.json"
    peer_file = folder.parent / peer_node / "secretCKD.json"
    shared_file = folder.parent / "Shared_Files" / "ABshared.json"

    # 1. Load or initialize node's secretCKD.json
    data = read_json(my_file)
    template = get_default_ckd_data(node_name, role)
    for key, val in template.items():
        if key not in data:
            data[key] = val
        elif isinstance(val, dict) and isinstance(data[key], dict):
            for sub_k, sub_v in val.items():
                if sub_k not in data[key]:
                    data[key][sub_k] = sub_v

    # 2. Load or generate node's private/public keypair
    private_key, private_bytes, public_bytes = load_or_generate_keypair(data, force_new=force_new)
    public_hex = public_bytes.hex()
    private_hex = private_bytes.hex()

    data["private_key"] = private_hex
    data["public_key"] = public_hex
    write_json(my_file, data)
    print(f"{role}'s public key saved.")

    # Update public channel in Shared_Files/ABshared.json if present
    if shared_file.exists():
        try:
            shared_data = read_json(shared_file)
            if "classical_exchange" in shared_data and isinstance(shared_data["classical_exchange"], dict):
                exchange_key = "alice_public_key_hex" if role == "Alice" else "bob_public_key_hex"
                shared_data["classical_exchange"][exchange_key] = public_hex
                write_json(shared_file, shared_data)
        except Exception:
            pass

    # 3. Read peer's public key
    peer_data = read_json(peer_file)
    peer_public_hex = peer_data.get("public_key") or peer_data.get("public_key_hex", "")

    if not peer_public_hex and shared_file.exists():
        shared_data = read_json(shared_file)
        peer_exchange_key = "bob_public_key_hex" if role == "Alice" else "alice_public_key_hex"
        peer_public_hex = shared_data.get("classical_exchange", {}).get(peer_exchange_key, "")

    if not peer_public_hex:
        data["status"] = "PENDING"
        write_json(my_file, data)
        print(f"{peer_role}'s public key is not available yet.")
        print(f"Run {peer_node}/ABCKD.py, then run this script again.")
        return data

    # 4. Perform ECDH and HKDF key derivation
    try:
        peer_public_bytes = bytes.fromhex(peer_public_hex)
        kdf_info = data.get("key_derivation", {}).get("info", "CSDQKD-Classical-Key-Exchange")
        salt_hex = data.get("key_derivation", {}).get("salt_hex")
        salt_bytes = bytes.fromhex(salt_hex) if salt_hex else None

        shared_secret, secret_key = derive_secret_key(
            private_key=private_key,
            peer_public_bytes=peer_public_bytes,
            info_str=kdf_info,
            salt_bytes=salt_bytes,
            length=32,
        )

        elapsed_time = time.perf_counter() - start_time
        elapsed_ms = round(elapsed_time * 1000, 3)
        finish_timestamp = datetime.now().isoformat()

        # Session ID coordination
        session_id = data.get("session_id") or peer_data.get("session_id") or secrets.token_hex(8)

        # 5. Map everything to secretCKD.json
        data["status"] = "SUCCESS"
        data["timestamp"] = finish_timestamp
        data["session_id"] = session_id
        data["secret_key_hex"] = secret_key.hex()
        data["secret_key"] = secret_key.hex()
        data["peer_public_key"] = peer_public_hex

        if "metrics" not in data or not isinstance(data["metrics"], dict):
            data["metrics"] = {}
        data["metrics"]["latency_ms"] = elapsed_ms
        data["metrics"]["key_distribution_time_seconds"] = round(elapsed_time, 6)
        data["metrics"]["key_distribution_started_at"] = start_timestamp
        data["metrics"]["established_at"] = finish_timestamp

        write_json(my_file, data)

        # Update Shared_Files/ABshared.json if present
        if shared_file.exists():
            try:
                shared_data = read_json(shared_file)
                if "classical_exchange" in shared_data and isinstance(shared_data["classical_exchange"], dict):
                    shared_data["classical_exchange"]["alice_public_key_hex"] = (
                        public_hex if role == "Alice" else peer_public_hex
                    )
                    shared_data["classical_exchange"]["bob_public_key_hex"] = (
                        peer_public_hex if role == "Alice" else public_hex
                    )
                shared_data["session_id"] = session_id
                shared_data["timestamp"] = finish_timestamp
                write_json(shared_file, shared_data)
            except Exception:
                pass

        print("ECDH successful!")
        print(f"{role}'s secret key saved to {my_file.relative_to(folder.parent)}")
        print("Shared secret saved successfully.")
        print(f"Key distribution time: {elapsed_time:.6f} seconds ({elapsed_ms} ms)")
        return data

    except (ValueError, TypeError) as error:
        print("Could not derive the key:", error)
        data["status"] = "FAILED"
        write_json(my_file, data)
        return data


def main():
    parser = argparse.ArgumentParser(description="Classical Key Distribution (CKD) using X25519 ECDH and HKDF.")
    parser.add_argument("--role", choices=["Alice", "Bob"], help="Explicitly specify role (default: auto from folder)")
    parser.add_argument("--new", action="store_true", help="Force generate a new private/public keypair")
    args = parser.parse_args()

    run_ckd(folder=DEFAULT_FOLDER, role=args.role, force_new=args.new)


if __name__ == "__main__":
    main()
