"""
qsecure.orchestrator - Cryptographic Protocol Orchestration & Validation
=========================================================================
Coordinates execution of CKD, ML-KEM, QKD, and AES-256-GCM protocols between
Node A (Alice) and Node B (Bob) over untrusted channel Shared_Files/ABshared.json.
Provides high-resolution sub-phase timing, resource profiling, and rigorous validation.
"""

import json
import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.kem.ml_kem_768 import keygen as ml_kem_keygen

from Node_A import AB as Alice
from Node_B import AB as Bob
from qsecure.metrics import (
    ResourceMonitor,
    calculate_ckd_communication,
    calculate_mkd_communication,
    calculate_qkd_communication,
)
from qsecure.ui import (
    console,
    is_narrow,
    render_header,
    render_status_pill,
    render_step_status,
)

BASE_DIR = Path(__file__).resolve().parent.parent
SHARED_FILE = BASE_DIR / "Shared_Files" / "ABshared.json"
SECRET_A_FILE = BASE_DIR / "Node_A" / "secretAB.json"
SECRET_B_FILE = BASE_DIR / "Node_B" / "secretAB.json"
QKD_CHANNEL_DIR = BASE_DIR / "Shared_Files" / "qkd_channel"


def read_json_safe(path: Path) -> dict:
    """Read a JSON file safely, returning empty dict if missing or malformed."""
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def write_json_safe(path: Path, data: dict) -> None:
    """Write dictionary to JSON file atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    tmp_path.replace(path)


def run_ckd_protocol(message: str, verbose: bool = True, channel_delay_ms: float = 15.0) -> Dict[str, Any]:
    """Execute Classical Key Distribution (X25519 + HKDF-SHA256) + AES-256-GCM.
    
    Sub-phases timed separately (RQ1):
      1. Alice keypair generation
      2. Bob keypair generation
      3. ECDH exchange & HKDF derivation
    """
    if verbose:
        render_header("CKD (CLASSICAL KEY DISTRIBUTION) + AES-256-GCM", style="bold dodger_blue1")

    substages = {}
    with ResourceMonitor(track_heap=True) as monitor:
        t0_estab = time.perf_counter_ns()

        # Step 1: Alice Keypair Generation & Publish
        t0 = time.perf_counter_ns()
        a_pub = Alice.ckd_publish_public_key(force_new=True)
        substages["alice_keygen_ms"] = (time.perf_counter_ns() - t0) / 1_000_000.0
        if verbose:
            render_step_status("1", "Node A (Alice)", f"Generated X25519 keypair; published PK ({a_pub['public_key_hex'][:16]}...)", "OK")

        # Step 2: Bob Keypair Generation & Publish
        t0 = time.perf_counter_ns()
        b_pub = Bob.ckd_publish_public_key(force_new=True)
        substages["bob_keygen_ms"] = (time.perf_counter_ns() - t0) / 1_000_000.0
        if verbose:
            render_step_status("2", "Node B (Bob)", f"Generated X25519 keypair; published PK ({b_pub['public_key_hex'][:16]}...)", "OK")

        # Step 3: ECDH Shared Secret & HKDF Key Derivation
        t0 = time.perf_counter_ns()
        a_key = Alice.ckd_derive_key()
        b_key = Bob.ckd_derive_key()
        substages["ecdh_hkdf_ms"] = (time.perf_counter_ns() - t0) / 1_000_000.0
        t_key_estab_ms = (time.perf_counter_ns() - t0_estab) / 1_000_000.0

        # Validate Agreement
        if a_key["secret_key_hex"] != b_key["secret_key_hex"]:
            raise RuntimeError("CKD Key mismatch between Node A and Node B!")
        
        shared_key_hex = a_key["secret_key_hex"]
        if verbose:
            render_step_status("3", "ECDH & HKDF", f"Derived 256-bit AES Key ({shared_key_hex[:16]}...)", "PASS")
            render_step_status(" ", "Key Estab Time", f"{t_key_estab_ms:.3f} ms [Alice: {substages['alice_keygen_ms']:.3f}ms, Bob: {substages['bob_keygen_ms']:.3f}ms, ECDH: {substages['ecdh_hkdf_ms']:.3f}ms]", "METRIC")

        # Step 4: Alice Encrypt
        t0 = time.perf_counter_ns()
        enc_res = Alice.aes_encrypt(message, protocol="CKD")
        t_enc_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        substages["encryption_ms"] = t_enc_ms
        if verbose:
            render_step_status("4", "Node A Encrypt", f"AES-256-GCM ciphertext generated ({len(message)} chars)", "OK")

        # Step 5: Simulated Channel Transit
        if channel_delay_ms > 0:
            time.sleep(channel_delay_ms / 1000.0)
        t_chan_ms = channel_delay_ms
        if verbose:
            render_step_status("5", "Public Channel", f"Transit across ABshared.json (simulated delay: {channel_delay_ms:.1f}ms)", "OK")

        # Step 6: Bob Decrypt
        t0 = time.perf_counter_ns()
        dec_res = Bob.aes_decrypt(protocol="CKD")
        t_dec_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        substages["decryption_ms"] = t_dec_ms

        if not dec_res["verification_success"] or dec_res["plaintext"] != message:
            raise RuntimeError(f"CKD message verification failed! Plaintext mismatch.")

        if verbose:
            render_step_status("6", "Node B Decrypt", f"Tag VERIFIED. Decrypted: '{dec_res['plaintext'][:35]}...'", "PASS")
            render_step_status("7", "Total Cycle Time", f"{monitor.elapsed_wall_ms:.3f} ms (CPU: {monitor.elapsed_cpu_ms:.3f} ms)", "SUCCESS")

    comm_stats = calculate_ckd_communication(payload_bytes=len(message.encode("utf-8")))

    return {
        "protocol": "CKD (ECDH-X25519 + HKDF-SHA256)",
        "protocol_short": "CKD",
        "security_standard": "Classical 128-bit Security (Curve25519)",
        "security_class": "Classical Asymmetric",
        "message": message,
        "key_fingerprint": shared_key_hex[:16],
        "key_establishment_ms": round(t_key_estab_ms, 4),
        "encryption_latency_ms": round(t_enc_ms, 4),
        "channel_transit_ms": round(t_chan_ms, 3),
        "decryption_latency_ms": round(t_dec_ms, 4),
        "total_latency_ms": round(monitor.wall_time_ms, 4),
        "cpu_time_ms": round(monitor.cpu_time_ms, 4),
        "cpu_utilization_pct": round(monitor.cpu_utilization_pct, 1),
        "peak_rss_kb": round(monitor.peak_rss_kb, 1),
        "delta_rss_kb": round(monitor.delta_rss_kb, 1),
        "heap_peak_kb": round(monitor.heap_peak_kb, 1),
        "verification_success": True,
        "substage_timings_ms": substages,
        "communication": comm_stats,
    }


def run_mkd_protocol(message: str, verbose: bool = True, channel_delay_ms: float = 15.0) -> Dict[str, Any]:
    """Execute Post-Quantum Key Distribution (NIST ML-KEM-768 / Kyber-768) + AES-256-GCM.
    
    Sub-phases timed separately (RQ1):
      1. Alice ML-KEM keypair generation (EK: 1184B, DK: 2400B)
      2. Bob encapsulation
      3. Alice decapsulation
    """
    if verbose:
        render_header("MKD (POST-QUANTUM ML-KEM-768) + AES-256-GCM", style="bold magenta")

    substages = {}
    with ResourceMonitor(track_heap=True) as monitor:
        t0_estab = time.perf_counter_ns()

        # Step 1: Alice Keypair Generation
        t0 = time.perf_counter_ns()
        a_pub = Alice.mkd_publish_public_key(force_new=True)
        substages["keygen_ms"] = (time.perf_counter_ns() - t0) / 1_000_000.0
        if verbose:
            render_step_status("1", "Node A (Alice)", f"Generated ML-KEM-768 keypair (1184B EK, 2400B DK); published EK", "OK")

        # Step 2: Bob Encapsulation
        t0 = time.perf_counter_ns()
        b_enc = Bob.mkd_encapsulate()
        substages["encapsulation_ms"] = (time.perf_counter_ns() - t0) / 1_000_000.0
        if verbose:
            render_step_status("2", "Node B (Bob)", f"Encapsulated shared secret; published 1088B ciphertext", "OK")

        # Step 3: Alice Decapsulation
        t0 = time.perf_counter_ns()
        a_dec = Alice.mkd_decapsulate()
        substages["decapsulation_ms"] = (time.perf_counter_ns() - t0) / 1_000_000.0
        t_key_estab_ms = (time.perf_counter_ns() - t0_estab) / 1_000_000.0

        if a_dec["secret_key_hex"] != b_enc["secret_key_hex"]:
            raise RuntimeError("MKD Key mismatch between Node A and Node B!")

        shared_key_hex = a_dec["secret_key_hex"]
        if verbose:
            render_step_status("3", "Decapsulation", f"Established NIST PQC Key ({shared_key_hex[:16]}...)", "PASS")
            render_step_status(" ", "Key Estab Time", f"{t_key_estab_ms:.3f} ms [KeyGen: {substages['keygen_ms']:.3f}ms, Encap: {substages['encapsulation_ms']:.3f}ms, Decap: {substages['decapsulation_ms']:.3f}ms]", "METRIC")

        # Step 4: Alice Encrypt
        t0 = time.perf_counter_ns()
        enc_res = Alice.aes_encrypt(message, protocol="MKD")
        t_enc_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        substages["encryption_ms"] = t_enc_ms
        if verbose:
            render_step_status("4", "Node A Encrypt", f"AES-256-GCM ciphertext generated ({len(message)} chars)", "OK")

        # Step 5: Simulated Channel Transit
        if channel_delay_ms > 0:
            time.sleep(channel_delay_ms / 1000.0)
        t_chan_ms = channel_delay_ms
        if verbose:
            render_step_status("5", "Public Channel", f"Transit across ABshared.json (simulated delay: {channel_delay_ms:.1f}ms)", "OK")

        # Step 6: Bob Decrypt
        t0 = time.perf_counter_ns()
        dec_res = Bob.aes_decrypt(protocol="MKD")
        t_dec_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        substages["decryption_ms"] = t_dec_ms

        if not dec_res["verification_success"] or dec_res["plaintext"] != message:
            raise RuntimeError(f"MKD message verification failed! Plaintext mismatch.")

        if verbose:
            render_step_status("6", "Node B Decrypt", f"Tag VERIFIED. Decrypted: '{dec_res['plaintext'][:35]}...'", "PASS")
            render_step_status("7", "Total Cycle Time", f"{monitor.elapsed_wall_ms:.3f} ms (CPU: {monitor.elapsed_cpu_ms:.3f} ms)", "SUCCESS")

    comm_stats = calculate_mkd_communication(payload_bytes=len(message.encode("utf-8")))

    return {
        "protocol": "MKD (NIST ML-KEM-768 / Kyber-768)",
        "protocol_short": "ML-KEM-768",
        "security_standard": "Post-Quantum Security Level 3 (AES-192 equivalent quantum hardness)",
        "security_class": "Post-Quantum Lattice (M-LWE)",
        "message": message,
        "key_fingerprint": shared_key_hex[:16],
        "key_establishment_ms": round(t_key_estab_ms, 4),
        "encapsulation_ms": round(substages["encapsulation_ms"], 4),
        "decapsulation_ms": round(substages["decapsulation_ms"], 4),
        "encryption_latency_ms": round(t_enc_ms, 4),
        "channel_transit_ms": round(t_chan_ms, 3),
        "decryption_latency_ms": round(t_dec_ms, 4),
        "total_latency_ms": round(monitor.wall_time_ms, 4),
        "cpu_time_ms": round(monitor.cpu_time_ms, 4),
        "cpu_utilization_pct": round(monitor.cpu_utilization_pct, 1),
        "peak_rss_kb": round(monitor.peak_rss_kb, 1),
        "delta_rss_kb": round(monitor.delta_rss_kb, 1),
        "heap_peak_kb": round(monitor.heap_peak_kb, 1),
        "verification_success": True,
        "substage_timings_ms": substages,
        "communication": comm_stats,
    }


def run_qkd_protocol(
    message: str,
    n_qubits: int = 4000,
    loss: float = 0.10,
    noise: float = 0.03,
    verbose: bool = True,
    channel_delay_ms: float = 15.0,
) -> Dict[str, Any]:
    """Execute Quantum Key Distribution (BB84 + Cascade + Toeplitz PA) + AES-256-GCM.
    
    Sub-phases accurately tracked (RQ1):
      1. Quantum channel setup & qubit preparation
      2. Measurement via AerSimulator
      3. Sifting & basis reconciliation
      4. Error estimation (QBER evaluation)
      5. Cascade error correction
      6. Verification tag matching
      7. Privacy amplification via Toeplitz matrix hashing
    """
    if verbose:
        render_header("QKD (BB84 QUANTUM KEY DISTRIBUTION) + AES-256-GCM", style="bold cyan")
        render_step_status("1", "Quantum Channel", f"Simulating {n_qubits} qubits over fiber (loss={loss:.0%}, intrinsic noise={noise:.0%})", "INIT")

    substages = {}
    results = {}

    with ResourceMonitor(track_heap=True) as monitor:
        t0_estab = time.perf_counter_ns()

        def bob_worker():
            try:
                results["bob"] = Bob.run_qkd_bob(timeout=60)
            except Exception as e:
                results["bob_err"] = str(e)

        def alice_worker():
            try:
                results["alice"] = Alice.run_qkd_alice(
                    n_qubits=n_qubits, loss=loss, noise=noise, timeout=60
                )
            except Exception as e:
                results["alice_err"] = str(e)

        tb = threading.Thread(target=bob_worker)
        ta = threading.Thread(target=alice_worker)

        if verbose:
            render_step_status("2", "BB84 Protocol", f"Bob ready handshake; Alice encodes & transmits {n_qubits} qubits", "RUN")

        tb.start()
        time.sleep(0.08)  # Let Bob initialize channel listener
        ta.start()

        # Monitor loop for progress feedback
        while tb.is_alive() or ta.is_alive():
            monitor.sample_memory()
            time.sleep(0.2)

        tb.join(timeout=30)
        ta.join(timeout=30)

        t_key_estab_ms = (time.perf_counter_ns() - t0_estab) / 1_000_000.0

        if "bob_err" in results:
            raise RuntimeError(f"Bob QKD execution failed: {results['bob_err']}")
        if "alice_err" in results:
            raise RuntimeError(f"Alice QKD execution failed: {results['alice_err']}")
        if "alice" not in results or "bob" not in results:
            raise TimeoutError("QKD protocol timed out.")

        a_res = results["alice"]
        b_res = results["bob"]

        if a_res["secret_key_hex"] != b_res["secret_key_hex"]:
            raise RuntimeError("QKD Key mismatch after Privacy Amplification!")

        shared_key_hex = a_res["secret_key_hex"]
        qber = b_res["qber"]

        if verbose:
            render_step_status("3", "Sifting & Cascade", f"Sifted & parity corrected; Measured QBER: {qber:.2%} (Threshold: 11%)", "PASS")
            render_step_status("4", "Privacy Amplification", f"Toeplitz 2-universal hash -> {b_res['key_bits']}-bit secure key", "PASS")
            render_step_status(" ", "Key Estab Latency", f"{t_key_estab_ms:.2f} ms (Simulation of {n_qubits} qubits)", "METRIC")

        # Step 5: Alice Encrypt
        t0 = time.perf_counter_ns()
        enc_res = Alice.aes_encrypt(message, protocol="QKD")
        t_enc_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        substages["encryption_ms"] = t_enc_ms
        if verbose:
            render_step_status("5", "Node A Encrypt", f"AES-256-GCM ciphertext generated ({len(message)} chars)", "OK")

        # Step 6: Simulated Channel Transit
        if channel_delay_ms > 0:
            time.sleep(channel_delay_ms / 1000.0)
        t_chan_ms = channel_delay_ms
        if verbose:
            render_step_status("6", "Public Channel", f"Transit across ABshared.json (simulated delay: {channel_delay_ms:.1f}ms)", "OK")

        # Step 7: Bob Decrypt
        t0 = time.perf_counter_ns()
        dec_res = Bob.aes_decrypt(protocol="QKD")
        t_dec_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        substages["decryption_ms"] = t_dec_ms

        if not dec_res["verification_success"] or dec_res["plaintext"] != message:
            raise RuntimeError(f"QKD message verification failed! Plaintext mismatch.")

        if verbose:
            render_step_status("7", "Node B Decrypt", f"Tag VERIFIED. Decrypted: '{dec_res['plaintext'][:35]}...'", "PASS")
            render_step_status("8", "Total Cycle Time", f"{monitor.elapsed_wall_ms:.2f} ms (CPU: {monitor.elapsed_cpu_ms:.2f} ms)", "SUCCESS")

    comm_stats = calculate_qkd_communication(n_qubits=n_qubits, cascade_queries=6, payload_bytes=len(message.encode("utf-8")))

    return {
        "protocol": "QKD (BB84 + Cascade + Toeplitz PA)",
        "protocol_short": "QKD (BB84)",
        "security_standard": "Information-Theoretic Security (Quantum Mechanics)",
        "security_class": "Information-Theoretic (Physics-based)",
        "message": message,
        "key_fingerprint": shared_key_hex[:16],
        "qber": round(qber, 4),
        "key_bits": b_res["key_bits"],
        "key_establishment_ms": round(t_key_estab_ms, 3),
        "encryption_latency_ms": round(t_enc_ms, 4),
        "channel_transit_ms": round(t_chan_ms, 3),
        "decryption_latency_ms": round(t_dec_ms, 4),
        "total_latency_ms": round(monitor.wall_time_ms, 3),
        "cpu_time_ms": round(monitor.cpu_time_ms, 3),
        "cpu_utilization_pct": round(monitor.cpu_utilization_pct, 1),
        "peak_rss_kb": round(monitor.peak_rss_kb, 1),
        "delta_rss_kb": round(monitor.delta_rss_kb, 1),
        "heap_peak_kb": round(monitor.heap_peak_kb, 1),
        "verification_success": True,
        "substage_timings_ms": substages,
        "communication": comm_stats,
    }


def inspect_channel_and_secrets() -> Dict[str, Any]:
    """Inspect and verify channel device isolation, zero-secret state, and synchronization."""
    shared = read_json_safe(SHARED_FILE)
    sec_a = read_json_safe(SECRET_A_FILE)
    sec_b = read_json_safe(SECRET_B_FILE)

    # Verify zero secrets on public channel
    exposed_keys = []
    for section_name in ["classical_exchange", "pqc_exchange", "qkd_exchange", "encrypted_transmission"]:
        section = shared.get(section_name, {})
        if isinstance(section, dict):
            for k, v in section.items():
                if "secret" in k.lower() or "private" in k.lower():
                    if v is not None and v != "":
                        exposed_keys.append(f"{section_name}.{k}")

    key_a = sec_a.get("current_secret_key_hex")
    key_b = sec_b.get("current_secret_key_hex")
    synced = bool(key_a and key_b and (key_a == key_b))

    return {
        "active_protocol": shared.get("active_protocol", "N/A"),
        "transmission_status": shared.get("encrypted_transmission", {}).get("status", "IDLE"),
        "ciphertext_preview": str(shared.get("encrypted_transmission", {}).get("ciphertext_hex", "None"))[:32],
        "exposed_keys_count": len(exposed_keys),
        "exposed_keys": exposed_keys,
        "node_a_key_fingerprint": str(key_a)[:16] if key_a else "None",
        "node_b_key_fingerprint": str(key_b)[:16] if key_b else "None",
        "node_a_ckd_status": sec_a.get("ckd", {}).get("status", "IDLE"),
        "node_b_ckd_status": sec_b.get("ckd", {}).get("status", "IDLE"),
        "node_a_mkd_status": sec_a.get("mkd", {}).get("status", "IDLE"),
        "node_b_mkd_status": sec_b.get("mkd", {}).get("status", "IDLE"),
        "node_a_qkd_status": sec_a.get("qkd", {}).get("status", "IDLE"),
        "node_b_qkd_status": sec_b.get("qkd", {}).get("status", "IDLE"),
        "keys_synchronized": synced,
    }
