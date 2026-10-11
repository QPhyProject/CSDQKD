import json
import os
from pathlib import Path
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE_DIR = Path(__file__).resolve().parent.parent
SHARED_FILE = BASE_DIR / "Shared_Files" / "ABshared.json"


def main():
    with open(SHARED_FILE, "r", encoding="utf-8") as file:
        data = json.load(file)

    transmission = data["encrypted_transmission"]
    key = bytes.fromhex(transmission["secret_key_hex"])

    if len(key) != 32:
        raise ValueError("The AES-256 key must be exactly 32 bytes.")

    message = input("Alice, enter your message for Bob: ")
    plaintext = message.encode("utf-8")

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    encrypted = aesgcm.encrypt(nonce, plaintext, None)

    ciphertext = encrypted[:-16]
    tag = encrypted[-16:]

    transmission["sender"] = "Alice"
    transmission["cipher"] = "AES-256-GCM"
    transmission["nonce_hex"] = nonce.hex()
    transmission["ciphertext_hex"] = ciphertext.hex()
    transmission["tag_hex"] = tag.hex()
    transmission["plaintext_preview"] = None
    transmission["status"] = "ENCRYPTED"

    data["session_id"] = data.get("session_id") or os.urandom(8).hex()
    data["timestamp"] = datetime.now(timezone.utc).isoformat()

    with open(SHARED_FILE, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)

    print("\nMessage encrypted successfully!")
    print("Encrypted data saved to ABshared.json.")
    print("Nonce:", nonce.hex())
    print("Ciphertext:", ciphertext.hex())
    print("Authentication tag:", tag.hex())
    print("Plaintext is not stored in the shared file.")


if __name__ == "__main__":
    main()
