import json
import base64
from pathlib import Path
from pqcrypto.kem.ml_kem_768 import encaps

BASE = Path(__file__).parent
JSON_FILE = BASE / "secretMKD.json"
NODE_A_FILE = BASE.parent / "Node_A" / "secretMKD.json"

def encode(data):
    return base64.b64encode(data).decode("ascii")

def decode(data):
    return base64.b64decode(data, validate=True)

def establish():
    node_a = json.loads(NODE_A_FILE.read_text())

    public_key = decode(node_a["public_key"])
    ciphertext, shared_secret = encaps(public_key)

    data = {
        "algorithm": "ML-KEM-768",
        "ciphertext": encode(ciphertext),
        "shared_secret": encode(shared_secret)
    }

    JSON_FILE.write_text(json.dumps(data, indent=4))
    print("Node B: Shared secret established.")

if __name__ == "__main__":
    establish()