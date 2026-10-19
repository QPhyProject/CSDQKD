"""Educational Intercept-Resend demonstration for BB84 QKD protocol.

Run only as a local demonstration. This script simulates an adversary (Eve)
intercepting flying qubits on the quantum channel, measuring them in random
bases (Z or X), and forwarding them to Bob.

Requirement: pip install qiskit qiskit-aer
"""

import random


def simulate_intercept_resend(n_qubits: int = 10000, eve_interception_rate: float = 1.0):
    rng = random.SystemRandom()

    print("=== Educational Demonstration: BB84 Intercept-Resend Eavesdropping ===")
    print(f"Simulating {n_qubits} qubits with {eve_interception_rate:.0%} Eve interception rate.\n")

    # Alice prepares random bits and bases
    alice_bits = [rng.randint(0, 1) for _ in range(n_qubits)]
    alice_bases = [rng.choice(["Z", "X"]) for _ in range(n_qubits)]

    # Eve intercepts qubits
    eve_bases = [rng.choice(["Z", "X"]) for _ in range(n_qubits)]
    eve_bits = []
    qubits_to_bob = []

    for i in range(n_qubits):
        if rng.random() < eve_interception_rate:
            # Eve measures in eve_bases[i]
            if eve_bases[i] == alice_bases[i]:
                eve_measured = alice_bits[i]
            else:
                # 50% chance of collapse to opposite state
                eve_measured = rng.randint(0, 1)
            eve_bits.append(eve_measured)
            # Eve resends state prepared in eve_bases[i]
            qubits_to_bob.append((eve_measured, eve_bases[i]))
        else:
            eve_bits.append(None)
            qubits_to_bob.append((alice_bits[i], alice_bases[i]))

    # Bob measures in random bases
    bob_bases = [rng.choice(["Z", "X"]) for _ in range(n_qubits)]
    bob_bits = []
    for i in range(n_qubits):
        arrived_bit, arrived_base = qubits_to_bob[i]
        if bob_bases[i] == arrived_base:
            bob_measured = arrived_bit
        else:
            bob_measured = rng.randint(0, 1)
        bob_bits.append(bob_measured)

    # Sifting: Alice and Bob keep bits where their bases matched
    sifted_indices = [i for i in range(n_qubits) if alice_bases[i] == bob_bases[i]]
    sifted_alice = [alice_bits[i] for i in sifted_indices]
    sifted_bob = [bob_bits[i] for i in sifted_indices]

    errors = sum(1 for a, b in zip(sifted_alice, sifted_bob) if a != b)
    qber = errors / len(sifted_indices) if sifted_indices else 0.0

    print(f"Total Qubits Sent:          {n_qubits}")
    print(f"Sifted Key Length:          {len(sifted_indices)} bits (~50%)")
    print(f"Discrepant Error Bits:      {errors}")
    print(f"Measured QBER:              {qber:.2%}")
    print(f"BB84 Security Threshold:    11.00%")
    print()

    if qber > 0.11:
        print("RESULT: Eavesdropping DETECTED!")
        print("Because QBER exceeds the 11% threshold, Alice and Bob immediately abort the protocol.")
        print("All raw bits are discarded; ZERO secret key is established.")
    else:
        print("RESULT: QBER within threshold (No significant eavesdropping detected).")


if __name__ == "__main__":
    simulate_intercept_resend()
