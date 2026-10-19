"""Educational MITM demonstration for an unauthenticated ML-KEM-768 exchange.

Run only as a local demonstration. This script does not access a network,
modify your project files, or attack another system.

Requirement: pip install pqcrypto
"""

import hashlib
from pqcrypto.kem.ml_kem_768 import (
    decaps as ml_kem_decaps,
    encaps as ml_kem_encaps,
    keygen as ml_kem_keygen,
)


def fingerprint(secret: bytes) -> str:
    """Show a short fingerprint rather than printing the shared secret itself."""
    return hashlib.sha256(secret).hexdigest()[:16]


def main():
    print("=== Local MITM demonstration: unauthenticated ML-KEM-768 ===")
    print("Simulating encapsulation-key substitution; no network traffic is used.\n")

    # 1. Alice generates legitimate ML-KEM-768 keypair
    alice_ek, alice_dk = ml_kem_keygen()

    # 2. Attacker generates malicious ML-KEM-768 keypair
    attacker_ek, attacker_dk = ml_kem_keygen()

    # 3. Substitution: Bob receives Attacker's EK instead of Alice's
    ct_from_bob, bob_secret = ml_kem_encaps(attacker_ek)

    # 4. Attacker decapsulates Bob's ciphertext using Attacker's DK
    attacker_secret_with_bob = ml_kem_decaps(attacker_dk, ct_from_bob)

    # 5. Attacker encapsulates a new secret to Alice's legitimate EK
    ct_to_alice, attacker_secret_with_alice = ml_kem_encaps(alice_ek)

    # 6. Alice decapsulates using Alice's DK
    alice_secret = ml_kem_decaps(alice_dk, ct_to_alice)

    print("Alice's derived key fingerprint:          ", fingerprint(alice_secret))
    print("Attacker's key with Alice fingerprint:    ", fingerprint(attacker_secret_with_alice))
    print("Bob's derived key fingerprint:            ", fingerprint(bob_secret))
    print("Attacker's key with Bob fingerprint:      ", fingerprint(attacker_secret_with_bob))
    print()

    alice_link_compromised = (alice_secret == attacker_secret_with_alice)
    bob_link_compromised = (bob_secret == attacker_secret_with_bob)
    alice_bob_match = (alice_secret == bob_secret)

    print("Alice and attacker share the same key: ", alice_link_compromised)
    print("Bob and attacker share the same key:   ", bob_link_compromised)
    print("Alice and Bob share the same key:      ", alice_bob_match)

    if alice_link_compromised and bob_link_compromised and not alice_bob_match:
        print("\nRESULT: MITM demonstrated in unauthenticated ML-KEM-768 exchange.")
        print("Post-quantum confidentiality does NOT imply peer authentication.")
        print("The attacker holds independent shared keys with each side.")

    print("\nMitigation: Authenticate encapsulation keys using digital signatures")
    print("(e.g. NIST ML-DSA / Dilithium) and verify peer certificates before encapsulation.")


if __name__ == "__main__":
    main()
