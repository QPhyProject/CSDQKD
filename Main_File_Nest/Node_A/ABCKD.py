
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# File locations
folder = Path(__file__).resolve().parent
my_file = folder / "secretCKD.json"
peer_file = folder.parent / "Node_B" / "secretCKD.json"
output_file = folder / "secretOQD.json"


def read_json(path):
    if not path.exists():
        return {}
    with open(path, "r") as file:
        return json.load(file)


def write_json(path, data):
    with open(path, "w") as file:
        json.dump(data, file, indent=4)


# Load Alice's data
data = read_json(my_file)

# Load or generate Alice's private key
try:
    private_bytes = bytes.fromhex(data.get("private_key", ""))
    if len(private_bytes) != 32:
        raise ValueError("Invalid private key length")

    private_key = X25519PrivateKey.from_private_bytes(private_bytes)

except (ValueError, TypeError):
    private_key = X25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

# Get Alice's public key
public_bytes = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

data["private_key"] = private_bytes.hex()
data["public_key"] = public_bytes.hex()
write_json(my_file, data)

print("Alice's public key saved.")

# Read Bob's public key
peer_data = read_json(peer_file)
peer_public_hex = peer_data.get("public_key", "")

if not peer_public_hex:
    print("Bob's public key is not available yet.")
    print("Run Node_B/ABCKD.py, then run this script again.")
else:
    try:
        peer_public_bytes = bytes.fromhex(peer_public_hex)

        if len(peer_public_bytes) != 32:
            raise ValueError("Bob's public key must be 32 bytes")

        peer_public_key = X25519PublicKey.from_public_bytes(
            peer_public_bytes
        )

        # Perform ECDH
        shared_secret = private_key.exchange(peer_public_key)

        # Derive a 32-byte key using HKDF
        secret_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"Classical-Key-Distribution"
        ).derive(shared_secret)

        # Save the derived secret
        write_json(output_file, {
            "secret_key": secret_key.hex()
        })

        data["peer_public_key"] = peer_public_hex
        write_json(my_file, data)

        print("ECDH successful!")
        print("Alice's secret key saved to Node_A/secretOQD.json")

    except (ValueError, TypeError) as error:
        print("Could not derive the key:", error)
