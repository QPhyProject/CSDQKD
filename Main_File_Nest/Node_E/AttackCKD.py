"""Educational MITM demonstration for an unauthenticated X25519/ECDH exchange.

Run only as a local demonstration. This script does not access a network,
modify your project files, or attack another system.

Requirement: pip install cryptography
"""

import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def public_bytes(private_key):
    return private_key.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )


def fingerprint(secret):
    """Show a short fingerprint rather than printing the shared secret itself."""
    return hashlib.sha256(secret).hexdigest()[:16]


def main():
    # Alice and Bob generate their normal X25519 key pairs.
    alice_private = x25519.X25519PrivateKey.generate()
    bob_private = x25519.X25519PrivateKey.generate()

    # The attacker creates two separate key pairs, one for each side.
    attacker_to_alice_private = x25519.X25519PrivateKey.generate()
    attacker_to_bob_private = x25519.X25519PrivateKey.generate()

    alice_public = alice_private.public_key()
    bob_public = bob_private.public_key()
    attacker_to_alice_public = attacker_to_alice_private.public_key()
    attacker_to_bob_public = attacker_to_bob_private.public_key()

    print("=== Local MITM demonstration: unauthenticated X25519 ===")
    print("Simulating public-key substitution; no network traffic is used.\n")

    # Substitution: Alice receives the attacker's public key instead of Bob's.
    # Bob receives the attacker's other public key instead of Alice's.
    alice_shared = alice_private.exchange(attacker_to_alice_public)
    attacker_shared_with_alice = attacker_to_alice_private.exchange(alice_public)

    bob_shared = bob_private.exchange(attacker_to_bob_public)
    attacker_shared_with_bob = attacker_to_bob_private.exchange(bob_public)

    print("Alice's derived key fingerprint:          ", fingerprint(alice_shared))
    print("Attacker's key with Alice fingerprint:    ", fingerprint(attacker_shared_with_alice))
    print("Bob's derived key fingerprint:            ", fingerprint(bob_shared))
    print("Attacker's key with Bob fingerprint:      ", fingerprint(attacker_shared_with_bob))
    print()

    alice_link_compromised = alice_shared == attacker_shared_with_alice
    bob_link_compromised = bob_shared == attacker_shared_with_bob
    alice_bob_match = alice_shared == bob_shared

    print("Alice and attacker share the same key: ", alice_link_compromised)
    print("Bob and attacker share the same key:   ", bob_link_compromised)
    print("Alice and Bob share the same key:      ", alice_bob_match)

    if alice_link_compromised and bob_link_compromised and not alice_bob_match:
        print("\nRESULT: MITM demonstrated in this unauthenticated exchange.")
        print("The attacker has a separate shared key with each side.")
        print("Alice and Bob do not independently establish the same key.")

    print("\nMitigation: authenticate public keys (for example, with verified digital")
    print("signatures/certificates or a pre-shared trusted fingerprint) and reject")
    print("unexpected keys. ECDH alone does not authenticate who sent a public key.")


if __name__ == "__main__":
    main()
