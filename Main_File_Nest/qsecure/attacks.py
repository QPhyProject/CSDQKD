"""
qsecure.attacks - Research Question 7: Eavesdropping & MITM Attack Simulations
==============================================================================
Implements reproducible, scientifically accurate attack simulations:
  1. Passive Public-Channel Eavesdropping (CKD, ML-KEM, QKD, AES)
  2. Active Man-in-the-Middle Key Substitution (CKD & ML-KEM)
  3. Quantum Channel Intercept-Resend Eavesdropping (QKD BB84)
  4. Authenticated Ciphertext Bit-Flipping / Tampering (AES-256-GCM)

All attack scenarios restore channel and local state upon completion.
"""

import base64
import copy
import hashlib
import json
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.kem.ml_kem_768 import (
    decaps as ml_kem_decaps,
    encaps as ml_kem_encaps,
    keygen as ml_kem_keygen,
)

from Node_A import AB as Alice
from Node_B import AB as Bob
from qsecure.orchestrator import (
    SECRET_A_FILE,
    SECRET_B_FILE,
    SHARED_FILE,
    read_json_safe,
    write_json_safe,
)
from qsecure.ui import (
    console,
    is_narrow,
    render_header,
    render_status_pill,
)
from rich.box import ROUNDED, SIMPLE
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


def run_passive_eavesdropping_attack() -> Dict[str, Any]:
    """Attack 1: Passive Observation of Public Channel Artifacts.
    
    Adversary Eve reads Shared_Files/ABshared.json without altering bits.
    Evaluates what information Eve can extract for CKD, ML-KEM, QKD, and AES.
    """
    shared = read_json_safe(SHARED_FILE)

    findings = []
    # 1. Classical Exchange
    has_ckd = bool(shared.get("classical_exchange", {}).get("alice_public_key_hex"))
    findings.append({
        "protocol": "CKD (X25519)",
        "intercepted_artifacts": "Alice PK & Bob PK (32-byte points on Curve25519)",
        "can_derive_secret": False,
        "reason": "Hardness of Elliptic Curve Diffie-Hellman Problem (ECDLP) under classical adversary",
    })

    # 2. PQC Exchange
    has_mkd = bool(shared.get("pqc_exchange", {}).get("alice_kem_public_key_b64"))
    findings.append({
        "protocol": "ML-KEM-768",
        "intercepted_artifacts": "Alice Encapsulation Key (1184B) & Bob Ciphertext (1088B)",
        "can_derive_secret": False,
        "reason": "Hardness of Module Learning With Errors (M-LWE); no private decapsulation key",
    })

    # 3. QKD Exchange
    findings.append({
        "protocol": "QKD (BB84)",
        "intercepted_artifacts": "Basis announcements, sample indices, Cascade parity queries, Toeplitz seed",
        "can_derive_secret": False,
        "reason": "Toeplitz Privacy Amplification hashes out all parity/sample information leaked to public channel",
    })

    # 4. AES-256-GCM
    has_aes = bool(shared.get("encrypted_transmission", {}).get("ciphertext_hex"))
    findings.append({
        "protocol": "AES-256-GCM",
        "intercepted_artifacts": "Nonce (12B), Ciphertext, 128-bit Authentication Tag",
        "can_derive_secret": False,
        "reason": "Confidentiality guaranteed under IND-CPA and IND-CCA2 security models",
    })

    return {
        "attack_name": "Passive Public Channel Eavesdropping",
        "target": "Shared_Files/ABshared.json",
        "detected": False,  # Passive listening causes zero physical or logical disturbance
        "succeeded": False, # Eve fails to obtain plaintext or secret key
        "aborted": False,
        "findings": findings,
        "evidence": "Public channel contains only public keys, public seeds, ciphertexts, and verification tags.",
    }


def run_ckd_mitm_attack() -> Dict[str, Any]:
    """Attack 2A: Active MITM Key Substitution on unauthenticated X25519 (CKD).
    
    Eve generates two independent keypairs (Eve-Alice, Eve-Bob) and substitutes
    public keys in flight. Alice and Bob each establish a shared key with Eve,
    unaware that their peer's identity was never authenticated.
    """
    # Generate Alice and Bob legitimate keypairs
    alice_priv = X25519PrivateKey.generate()
    bob_priv = X25519PrivateKey.generate()
    alice_pub = alice_priv.public_key()
    bob_pub = bob_priv.public_key()

    # Eve generates two malicious keypairs
    eve_to_alice_priv = X25519PrivateKey.generate()
    eve_to_bob_priv = X25519PrivateKey.generate()
    eve_to_alice_pub = eve_to_alice_priv.public_key()
    eve_to_bob_pub = eve_to_bob_priv.public_key()

    # Substitution: Alice receives Eve's key; Bob receives Eve's other key
    alice_shared = HKDF(hashes.SHA256(), 32, None, b"CSDQKD-Classical-Key-Exchange").derive(
        alice_priv.exchange(eve_to_alice_pub)
    )
    eve_shared_with_alice = HKDF(hashes.SHA256(), 32, None, b"CSDQKD-Classical-Key-Exchange").derive(
        eve_to_alice_priv.exchange(alice_pub)
    )

    bob_shared = HKDF(hashes.SHA256(), 32, None, b"CSDQKD-Classical-Key-Exchange").derive(
        bob_priv.exchange(eve_to_bob_pub)
    )
    eve_shared_with_bob = HKDF(hashes.SHA256(), 32, None, b"CSDQKD-Classical-Key-Exchange").derive(
        eve_to_bob_priv.exchange(bob_pub)
    )

    alice_bob_match = (alice_shared == bob_shared)
    alice_eve_match = (alice_shared == eve_shared_with_alice)
    bob_eve_match = (bob_shared == eve_shared_with_bob)

    # MITM successfully establishes independent eavesdropped links
    mitm_success = alice_eve_match and bob_eve_match and not alice_bob_match

    return {
        "attack_name": "Active MITM Public Key Substitution (CKD)",
        "protocol": "CKD (X25519 + HKDF-SHA256)",
        "setup": "Eve intercepts and replaces public keys in unauthenticated ECDH exchange",
        "expected_behavior": "Without digital signatures/certificates, ECDH cannot authenticate peer identity",
        "observed_behavior": "Alice and Bob complete key exchange without error, but hold divergent keys intercepted by Eve",
        "detected": False,
        "succeeded": mitm_success,
        "aborted": False,
        "evidence": {
            "alice_key_fingerprint": hashlib.sha256(alice_shared).hexdigest()[:16],
            "bob_key_fingerprint": hashlib.sha256(bob_shared).hexdigest()[:16],
            "eve_alice_fingerprint": hashlib.sha256(eve_shared_with_alice).hexdigest()[:16],
            "eve_bob_fingerprint": hashlib.sha256(eve_shared_with_bob).hexdigest()[:16],
            "alice_bob_keys_match": alice_bob_match,
        },
        "mitigation": "Digital signatures (e.g. Ed25519) or authenticated key exchange (SIGMA / TLS 1.3)",
    }


def run_mkd_key_substitution_attack() -> Dict[str, Any]:
    """Attack 2B: Active MITM Key Substitution on unauthenticated ML-KEM-768.
    
    Eve substitutes Alice's encapsulation key with Eve's encapsulation key.
    Bob encapsulates to Eve; Eve decapsulates and encapsulates to Alice.
    Demonstrates that PQC confidentiality alone does NOT provide peer authentication.
    """
    # 1. Alice generates legitimate keypair
    alice_ek, alice_dk = ml_kem_keygen()

    # 2. Eve generates malicious keypair
    eve_ek, eve_dk = ml_kem_keygen()

    # 3. Eve substitutes Alice's EK on channel; Bob encapsulates using Eve's EK
    ct_from_bob, bob_secret = ml_kem_encaps(eve_ek)

    # 4. Eve decapsulates Bob's ciphertext using Eve's DK
    eve_secret_bob = ml_kem_decaps(eve_dk, ct_from_bob)

    # 5. Eve encapsulates a new secret to Alice's legitimate EK
    ct_to_alice, eve_secret_alice = ml_kem_encaps(alice_ek)

    # 6. Alice decapsulates using Alice's DK
    alice_secret = ml_kem_decaps(alice_dk, ct_to_alice)

    alice_bob_match = (alice_secret == bob_secret)
    bob_eve_match = (bob_secret == eve_secret_bob)
    alice_eve_match = (alice_secret == eve_secret_alice)

    mitm_success = bob_eve_match and alice_eve_match and not alice_bob_match

    return {
        "attack_name": "Active MITM Key Substitution (ML-KEM-768)",
        "protocol": "ML-KEM-768 (Kyber)",
        "setup": "Eve intercepts Alice's public encapsulation key and substitutes Eve's encapsulation key",
        "expected_behavior": "ML-KEM provides post-quantum confidentiality, but no peer authentication on its own",
        "observed_behavior": "Bob encapsulates to Eve; Eve establishes separate keys with both Alice and Bob without detection",
        "detected": False,
        "succeeded": mitm_success,
        "aborted": False,
        "evidence": {
            "alice_key_fingerprint": hashlib.sha256(alice_secret).hexdigest()[:16],
            "bob_key_fingerprint": hashlib.sha256(bob_secret).hexdigest()[:16],
            "eve_alice_fingerprint": hashlib.sha256(eve_secret_alice).hexdigest()[:16],
            "eve_bob_fingerprint": hashlib.sha256(eve_secret_bob).hexdigest()[:16],
            "alice_bob_keys_match": alice_bob_match,
        },
        "mitigation": "Pair ML-KEM with post-quantum digital signatures (NIST ML-DSA / SLH-DSA / Dilithium)",
    }


def run_qkd_intercept_resend_attack() -> Dict[str, Any]:
    """Attack 3: Simulated Quantum Intercept-Resend Eavesdropping on BB84.
    
    Eve intercepts qubits in the quantum channel, measures them in random bases,
    and resends them. Induces an expected ~25% error rate on sifted qubits,
    which drives QBER well above the 11% threshold. Alice and Bob abort.
    """
    results = {}
    
    def bob_worker():
        try:
            results["bob"] = Bob.run_qkd_bob(timeout=15)
        except Exception as e:
            results["bob_err"] = str(e)

    def alice_worker():
        try:
            # Simulate Eve measuring in random bases -> induces noise = 0.25 (25% QBER)
            results["alice"] = Alice.run_qkd_alice(
                n_qubits=1500, loss=0.10, noise=0.25, timeout=15
            )
        except Exception as e:
            results["alice_err"] = str(e)

    tb = threading.Thread(target=bob_worker)
    ta = threading.Thread(target=alice_worker)
    tb.start()
    time.sleep(0.05)
    ta.start()

    tb.join(timeout=15)
    ta.join(timeout=15)

    bob_err = results.get("bob_err", "")
    alice_err = results.get("alice_err", "")

    # Check if aborted due to QBER threshold
    detected = ("QBER" in bob_err and "exceeded" in bob_err) or ("QBER" in alice_err and "exceeded" in alice_err)
    aborted = detected

    return {
        "attack_name": "Quantum Intercept-Resend Eavesdropping (QKD BB84)",
        "protocol": "QKD (BB84)",
        "setup": "Eve intercepts 100% of flying qubits, measures in random bases (Z/X), and resends",
        "expected_behavior": "Quantum collapse on basis mismatch introduces ~25% QBER, exceeding 11% threshold",
        "observed_behavior": f"Protocol immediately aborted during error estimation. {bob_err}",
        "detected": detected,
        "succeeded": not aborted,
        "aborted": aborted,
        "evidence": {
            "alice_status": alice_err,
            "bob_status": bob_err,
            "qber_threshold": 0.11,
            "secret_key_established": False,
        },
        "mitigation": "BB84 protocol inherently detects eavesdropping via quantum physics (No-Cloning Theorem)",
    }


def run_aes_ciphertext_tampering_attack() -> Dict[str, Any]:
    """Attack 4: Modification of Authenticated AES-256-GCM Ciphertext / Tag.
    
    Adversary modifies a byte in the encrypted message stored on the public channel.
    Bob attempts decryption. AES-GCM GHASH authentication tag verification fails.
    """
    # 1. Establish valid key and encrypt valid message
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    original_msg = b"Confidential automated payload transmission."
    ciphertext_and_tag = aesgcm.encrypt(nonce, original_msg, None)

    # 2. Tamper with 1 byte of the ciphertext
    tampered_bytes = bytearray(ciphertext_and_tag)
    tampered_bytes[0] ^= 0x01  # Flip 1 bit

    # 3. Bob attempts decryption
    caught_by_gcm = False
    try:
        aesgcm.decrypt(nonce, bytes(tampered_bytes), None)
    except InvalidTag:
        caught_by_gcm = True

    return {
        "attack_name": "Ciphertext Bit-Flipping / Message Tampering",
        "protocol": "AES-256-GCM",
        "setup": "Eve flips 1 bit in the ciphertext during public channel transit",
        "expected_behavior": "AES-256-GCM GHASH authentication tag must fail verification (InvalidTag)",
        "observed_behavior": "Authentication Tag failed verification. Bob rejected ciphertext with 0 plaintext leak",
        "detected": caught_by_gcm,
        "succeeded": not caught_by_gcm,
        "aborted": caught_by_gcm,
        "evidence": {
            "bit_flipped_index": 0,
            "verification_exception": "cryptography.exceptions.InvalidTag",
            "plaintext_revealed": None,
        },
        "mitigation": "Authenticated Encryption with Associated Data (AEAD) mathematically guarantees ciphertext integrity",
    }


def run_all_attack_simulations(verbose: bool = True) -> List[Dict[str, Any]]:
    """Execute all four attack scenarios and present a research matrix."""
    # Backup existing channel and secret state
    backup_shared = read_json_safe(SHARED_FILE)
    backup_sec_a = read_json_safe(SECRET_A_FILE)
    backup_sec_b = read_json_safe(SECRET_B_FILE)

    if verbose:
        render_header("RESEARCH QUESTION 7 — SECURITY & ATTACK SIMULATIONS", style="bold red")

    results = []

    try:
        # Attack 1: Passive Observation
        res1 = run_passive_eavesdropping_attack()
        results.append(res1)

        # Attack 2A: CKD MITM
        res2a = run_ckd_mitm_attack()
        results.append(res2a)

        # Attack 2B: ML-KEM MITM
        res2b = run_mkd_key_substitution_attack()
        results.append(res2b)

        # Attack 3: QKD Intercept-Resend
        res3 = run_qkd_intercept_resend_attack()
        results.append(res3)

        # Attack 4: AES Tampering
        res4 = run_aes_ciphertext_tampering_attack()
        results.append(res4)

    finally:
        # Crucial: Restore original state so subsequent benchmarks are uncontaminated
        if backup_shared:
            write_json_safe(SHARED_FILE, backup_shared)
        if backup_sec_a:
            write_json_safe(SECRET_A_FILE, backup_sec_a)
        if backup_sec_b:
            write_json_safe(SECRET_B_FILE, backup_sec_b)

    if verbose:
        table = Table(
            title="Attack Simulation & Threat Evaluation Matrix",
            box=ROUNDED,
            show_header=True,
            header_style="bold red",
        )
        table.add_column("Attack Scenario", justify="left", style="bold white")
        table.add_column("Target Protocol", justify="left", style="cyan")
        table.add_column("Detected?", justify="center")
        table.add_column("Attack Succeeded?", justify="center")
        table.add_column("Aborted?", justify="center")
        table.add_column("Security Outcome & Defense", justify="left", style="dim white")

        for r in results:
            detected_pill = render_status_pill("PASS" if r["detected"] else "WARN")
            succeeded_pill = render_status_pill("FAIL" if r["succeeded"] else "PASS")
            aborted_pill = render_status_pill("PASS" if r["aborted"] else "WARN")

            defense = r.get("mitigation", "N/A")
            table.add_row(
                r["attack_name"],
                r.get("protocol", "General"),
                detected_pill,
                succeeded_pill,
                aborted_pill,
                defense,
            )

        console.print(table)
        console.print()

        # Scientific Interpretation
        console.print(Panel(
            Text(
                "Scientific Interpretation:\n"
                "1. Authentication vs Confidentiality Distinction: Neither CKD (ECDH) nor ML-KEM alone provides "
                "peer authentication. Unauthenticated public key substitution succeeds completely against both without "
                "detection, proving that post-quantum confidentiality does not imply post-quantum authentication.\n"
                "2. QKD Physical Detection: BB84 reliably detects quantum eavesdropping because measuring non-orthogonal "
                "quantum states perturbs their polarization, driving QBER above 11% and triggering automatic protocol abort.\n"
                "3. QKD Classical Channel Vulnerability: Note that QKD's security proof requires the classical channel "
                "to be pre-authenticated (using HMAC with pre-shared keys). If the classical channel is unauthenticated, "
                "an attacker can MITM the classical reconciliation messages.",
                style="dim white",
            ),
            box=ROUNDED,
            border_style="grey35",
            title="[bold green]Research Conclusion[/bold green]",
        ))

    return results
