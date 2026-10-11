import json
import base64
from pathlib import Path
from pqcrypto.kem.ml_kem_768 import keygen, decaps

BASE = Path(__file__).parent
JSON_FILE = BASE / "secretMKD.json"
NODE_B_FILE = BASE.parent / "Node_B" / "secretMKD.json"

def encode(data):
    return base64.b64encode(data).decode("ascii")

def decode(data):
    return base64.b64decode(data, validate=True)

def init():
    public_key, private_key = keygen()

    data = {
        "algorithm": "ML-KEM-768",
        "public_key": encode(public_key),
        "private_key": encode(private_key),
        "shared_secret": None
    }

    JSON_FILE.write_text(json.dumps(data, indent=4))
    print("Node A: Key pair generated.")

def establish():
    data = json.loads(JSON_FILE.read_text())
    node_b = json.loads(NODE_B_FILE.read_text())

    shared_secret = decaps(
        decode(data["private_key"]),
        decode(node_b["ciphertext"])
    )

    data["shared_secret"] = encode(shared_secret)
    JSON_FILE.write_text(json.dumps(data, indent=4))

    print("Node A: Shared secret established.")

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2 or sys.argv[1] not in ("init", "establish"):
        print("Usage: python ABMKD.py [init|establish]")
        raise SystemExit(1)

    if sys.argv[1] == "init":
        init()
    else:
        establish()