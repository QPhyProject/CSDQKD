"""
AES256_AB.py - AES-256-GCM Authenticated Decryption for Node B (Bob)
=====================================================================

Implements authenticated symmetric decryption:
  1. Reads encrypted transmission from Shared_Files/ABshared.json.
  2. Resolves Bob's matching 256-bit (32-byte) key from secretQKD.json,
     secretMKD.json, secretCKD.json, or ABshared.json.
  3. Verifies GCM authentication tag and decrypts ciphertext.
  4. Updates Bob's dashboard decryption state in DashboardBob.json.
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
DASHBOARD_FILE = NODE_DIR / "DashboardBob.json"


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
    Retrieve Bob's 32-byte AES key from explicit argument, secret JSON files, or shared channel.
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

    fallback_hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    return bytes.fromhex(fallback_hex), "Default demonstration key"


def decrypt_message(
    key_bytes: bytes | None = None,
    protocol: str | None = None,
    shared_path: Path = SHARED_FILE,
) -> str | None:
    """Read ciphertext from shared channel, decrypt with AES-256-GCM, and update Bob's dashboard."""
    data = read_json(shared_path)
    transmission = data.get("encrypted_transmission", {})

    if transmission.get("status") != "ENCRYPTED":
        print("No encrypted message is available.")
        return None

    if key_bytes is None:
        key_bytes, key_src = get_secret_key(protocol=protocol)
    else:
        key_src = "Provided key bytes"

    if len(key_bytes) != 32:
        raise ValueError("The AES-256 key must be exactly 32 bytes.")

    nonce = bytes.fromhex(transmission["nonce_hex"])
    ciphertext = bytes.fromhex(transmission["ciphertext_hex"])
    tag = bytes.fromhex(transmission["tag_hex"])

    aesgcm = AESGCM(key_bytes)
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext + tag, None)
    plaintext = plaintext_bytes.decode("utf-8")

    iso_now = datetime.now(timezone.utc).isoformat()

    # Update Bob's dashboard state
    dash = read_json(DASHBOARD_FILE)
    if dash:
        if "decryption_status" not in dash or not isinstance(dash["decryption_status"], dict):
            dash["decryption_status"] = {}
        dash["decryption_status"]["last_received_cipher_hex"] = ciphertext.hex()
        dash["decryption_status"]["decrypted_plaintext"] = plaintext
        dash["decryption_status"]["verification_success"] = True

        if isinstance(dash.get("log_history"), list):
            dash["log_history"].append({
                "timestamp": iso_now,
                "level": "INFO",
                "event": f"Successfully decrypted message from Alice ({len(plaintext_bytes)} bytes) using AES-256-GCM",
            })
        write_json(DASHBOARD_FILE, dash)

    # Update channel status
    transmission["status"] = "DECRYPTED"
    transmission["plaintext_preview"] = plaintext[:30] + ("..." if len(plaintext) > 30 else "")
    data["encrypted_transmission"] = transmission
    data["timestamp"] = iso_now
    write_json(shared_path, data)
    if LOCAL_SHARED_FILE.exists():
        write_json(LOCAL_SHARED_FILE, data)

    print("Message decrypted successfully!")
    print(f"Key Source:         {key_src}")
    print(f"Message from Alice: {plaintext}")
    return plaintext


def main():
    parser = argparse.ArgumentParser(description="AES-256-GCM Decryption for Node B (Bob).")
    parser.add_argument("--protocol", choices=["QKD", "MKD", "CKD"], help="Key source protocol")
    parser.add_argument("--key", help="Explicit 32-byte hex key")
    args = parser.parse_args()

    key_bytes = None
    if args.key:
        key_bytes = bytes.fromhex(args.key)

    decrypt_message(key_bytes=key_bytes, protocol=args.protocol)


if __name__ == "__main__":
    main()
