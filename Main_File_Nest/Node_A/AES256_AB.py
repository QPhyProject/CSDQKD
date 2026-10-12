"""
AES256_AB.py - AES-256-GCM Authenticated Encryption for Node A (Alice)
=====================================================================

Implements authenticated symmetric encryption:
  1. Resolves a 256-bit (32-byte) key from secretQKD.json, secretMKD.json,
     secretCKD.json, or ABshared.json.
  2. Encrypts Alice's plaintext using AES-256-GCM with a secure 96-bit (12-byte) random nonce.
  3. Writes ciphertext, authentication tag, and nonce to Shared_Files/ABshared.json.
  4. Updates Alice's dashboard state in DashboardAlice.json.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE_DIR = Path(__file__).resolve().parent.parent
NODE_DIR = Path(__file__).resolve().parent
SHARED_FILE = BASE_DIR / "Shared_Files" / "ABshared.json"
LOCAL_SHARED_FILE = NODE_DIR / "shared_AB.json"
DASHBOARD_FILE = NODE_DIR / "DashboardAlice.json"


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


def get_secret_key(
    protocol: str | None = None,
    explicit_key_hex: str | None = None,
    node_folder: Path = NODE_DIR,
) -> tuple[bytes, str]:
    """
    Retrieve 32-byte AES key from explicit argument, secret JSON files, or shared channel.
    Returns (key_bytes, source_description).
    """
    if explicit_key_hex:
        key_bytes = bytes.fromhex(explicit_key_hex)
        if len(key_bytes) != 32:
            raise ValueError(f"Explicit key must be exactly 32 bytes (64 hex characters), got {len(key_bytes)}.")
        return key_bytes, "Explicit CLI key argument"

    shared_data = read_json(SHARED_FILE)
    active_proto = (protocol or shared_data.get("active_protocol", "")).upper()

    candidates = []
    if "QKD" in active_proto or "BB84" in active_proto:
        candidates = [("secretQKD.json", "QKD (BB84)")]
    elif "MKD" in active_proto or "KYBER" in active_proto or "ML_KEM" in active_proto:
        candidates = [("secretMKD.json", "MKD (ML-KEM-768)")]
    elif "CKD" in active_proto or "ECDH" in active_proto or "X25519" in active_proto:
        candidates = [("secretCKD.json", "CKD (ECDH-X25519)")]
    else:
        candidates = [
            ("secretQKD.json", "QKD (BB84)"),
            ("secretMKD.json", "MKD (ML-KEM-768)"),
            ("secretCKD.json", "CKD (ECDH-X25519)"),
        ]

    for fname, desc in candidates:
        fpath = node_folder / fname
        if fpath.exists():
            data = read_json(fpath)
            khex = data.get("secret_key_hex") or data.get("secret_key")
            if khex and isinstance(khex, str):
                try:
                    kbytes = bytes.fromhex(khex)
                    if len(kbytes) == 32:
                        return kbytes, f"{fname} [{desc}]"
                except ValueError:
                    pass

    # Fallback to shared channel key if present
    transmission = shared_data.get("encrypted_transmission", {})
    t_key_hex = transmission.get("secret_key_hex")
    if t_key_hex and isinstance(t_key_hex, str):
        try:
            kbytes = bytes.fromhex(t_key_hex)
            if len(kbytes) == 32:
                return kbytes, "ABshared.json [encrypted_transmission.secret_key_hex]"
        except ValueError:
            pass

    # Fallback default key for demonstration if none established yet
    fallback_hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    return bytes.fromhex(fallback_hex), "Default demonstration key"


def encrypt_message(
    message: str,
    key_bytes: bytes | None = None,
    protocol: str | None = None,
    shared_path: Path = SHARED_FILE,
) -> dict:
    """Encrypt a plaintext message using AES-256-GCM and store to shared transmission channel."""
    if key_bytes is None:
        key_bytes, key_src = get_secret_key(protocol=protocol)
    else:
        key_src = "Provided key bytes"

    if len(key_bytes) != 32:
        raise ValueError("The AES-256 key must be exactly 32 bytes.")

    plaintext = message.encode("utf-8")
    aesgcm = AESGCM(key_bytes)
    nonce = os.urandom(12)  # Standard 96-bit GCM nonce
    encrypted = aesgcm.encrypt(nonce, plaintext, None)

    ciphertext = encrypted[:-16]
    tag = encrypted[-16:]

    data = read_json(shared_path)
    if not data:
        data = {
            "channel": "Alice_Bob_Shared",
            "active_protocol": protocol or "BB84",
            "session_id": None,
            "timestamp": None,
            "encrypted_transmission": {},
        }

    transmission = data.get("encrypted_transmission", {})
    transmission["sender"] = "Alice"
    transmission["cipher"] = "AES-256-GCM"
    transmission["secret_key_hex"] = key_bytes.hex()
    transmission["nonce_hex"] = nonce.hex()
    transmission["ciphertext_hex"] = ciphertext.hex()
    transmission["tag_hex"] = tag.hex()
    transmission["plaintext_preview"] = None
    transmission["status"] = "ENCRYPTED"

    iso_now = datetime.now(timezone.utc).isoformat()
    transmission["timestamp"] = iso_now
    data["encrypted_transmission"] = transmission
    data["session_id"] = data.get("session_id") or os.urandom(8).hex()
    data["timestamp"] = iso_now

    write_json(shared_path, data)
    if LOCAL_SHARED_FILE.exists():
        write_json(LOCAL_SHARED_FILE, data)

    # Update Alice's dashboard
    dash = read_json(DASHBOARD_FILE)
    if dash and isinstance(dash.get("log_history"), list):
        dash["log_history"].append({
            "timestamp": iso_now,
            "level": "INFO",
            "event": f"Encrypted and transmitted message of {len(plaintext)} bytes using AES-256-GCM",
        })
        write_json(DASHBOARD_FILE, dash)

    print("\nMessage encrypted successfully!")
    print(f"Key Source:       {key_src}")
    print(f"Encrypted data saved to {shared_path.name}.")
    print("Nonce:            ", nonce.hex())
    print("Ciphertext:       ", ciphertext.hex())
    print("Authentication tag:", tag.hex())
    print("Plaintext is not stored in the shared file.")
    return {
        "status": "ENCRYPTED",
        "nonce_hex": nonce.hex(),
        "ciphertext_hex": ciphertext.hex(),
        "tag_hex": tag.hex(),
        "secret_key_hex": key_bytes.hex(),
    }


def main():
    parser = argparse.ArgumentParser(description="AES-256-GCM Encryption for Node A (Alice).")
    parser.add_argument("message", nargs="?", help="Plaintext message to encrypt")
    parser.add_argument("--protocol", choices=["QKD", "MKD", "CKD"], help="Key source protocol")
    parser.add_argument("--key", help="Explicit 32-byte hex key")
    args = parser.parse_args()

    message = args.message
    if not message:
        if sys.stdin.isatty():
            message = input("Alice, enter your message for Bob: ")
        else:
            message = "Hello Bob! Quantum-secured confidential transmission."

    key_bytes = None
    if args.key:
        key_bytes = bytes.fromhex(args.key)

    encrypt_message(message=message, key_bytes=key_bytes, protocol=args.protocol)


if __name__ == "__main__":
    main()
