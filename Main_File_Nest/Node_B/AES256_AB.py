
import json
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE_DIR = Path(__file__).resolve().parent.parent
SHARED_FILE = BASE_DIR / "Shared_Files" / "ABshared.json"


def main():
    with open(SHARED_FILE, "r", encoding="utf-8") as file:
        data = json.load(file)

    transmission = data["encrypted_transmission"]

    if transmission["status"] != "ENCRYPTED":
        print("No encrypted message is available.")
        return

    key = bytes.fromhex(transmission["secret_key_hex"])
    nonce = bytes.fromhex(transmission["nonce_hex"])
    ciphertext = bytes.fromhex(transmission["ciphertext_hex"])
    tag = bytes.fromhex(transmission["tag_hex"])

    if len(key) != 32:
        raise ValueError("The AES-256 key must be exactly 32 bytes.")

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)

    print("Message decrypted successfully!")
    print("Message from Alice:", plaintext.decode("utf-8"))


if __name__ == "__main__":
    main()
