#!/usr/bin/env python3
"""
main.py - QSecure Cryptographic Orchestration & Interactive CLI
================================================================
Central controller simulating communication between two sovereign nodes:
  - Node A (Alice)
  - Node B (Bob)

Over an untrusted channel (Shared_Files/ABshared.json) with absolute separation
of secrets (Node_A/secretAB.json and Node_B/secretAB.json).

Supported protocols:
  1. QKD: Quantum Key Distribution (BB84 + Cascade + Toeplitz PA)
  2. MKD: Post-Quantum Key Distribution (NIST ML-KEM-768 / Kyber-768)
  3. CKD: Classical Key Distribution (X25519 ECDH + HKDF-SHA256)
  4. AES: Authenticated Symmetric Encryption (AES-256-GCM)

Rewrites logs.json on every run with granular execution metrics.
"""

import argparse
import json
import os
import platform
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

# Add project root to path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from Node_A import AB as Alice
from Node_B import AB as Bob

LOGS_FILE = BASE_DIR / "logs.json"
SHARED_FILE = BASE_DIR / "Shared_Files" / "ABshared.json"
SECRET_A_FILE = BASE_DIR / "Node_A" / "secretAB.json"
SECRET_B_FILE = BASE_DIR / "Node_B" / "secretAB.json"


# =====================================================================
#  ANSI Color Constants & Helpers
# =====================================================================
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"

    BG_CYAN = "\033[46m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_BLACK = "\033[40m"


LOGO = f"""
{C.CYAN}{C.BOLD}
   ██████╗  ███████╗ ███████╗  ██████╗ ██╗   ██╗ ██████╗  ███████╗
  ██╔═══██╗ ██╔════╝ ██╔════╝ ██╔════╝ ██║   ██║ ██╔══██╗ ██╔════╝
  ██║   ██║ ███████╗ █████╗   ██║      ██║   ██║ ██████╔╝ █████╗  
  ██║▄▄ ██║ ╚════██║ ██╔══╝   ██║      ██║   ██║ ██╔══██╗ ██╔══╝  
  ╚██████╔╝ ███████║ ███████╗ ╚██████╗ ╚██████╔╝ ██║  ██║ ███████╗
   ╚══▀▀═╝  ╚══════╝ ╚══════╝  ╚═════╝  ╚═════╝  ╚═╝  ╚═╝ ╚══════╝
{C.RESET}{C.MAGENTA}{C.BOLD}     [ Quantum-Resilient Cryptographic Communication System ]{C.RESET}
{C.DIM}             Dual-Node Simulator: Node A (Alice) <-> Node B (Bob){C.RESET}
"""


def clear_screen():
    if sys.stdout.isatty():
        os.system("clear" if os.name != "nt" else "cls")


def print_banner():
    print(LOGO)


def print_header(title: str, color: str = C.CYAN):
    width = 76
    print(f"\n{color}{C.BOLD}{'═' * width}")
    print(f"  {title.center(width - 4)}")
    print(f"{'═' * width}{C.RESET}")


def print_status(step: str, detail: str, status: str = "OK", color: str = C.GREEN):
    badge = f"{color}[{status}]{C.RESET}"
    print(f" {badge} {C.BOLD}{step:<32}{C.RESET} : {detail}")


def read_json_file(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def write_json_file(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


# =====================================================================
#  Session Logging Management
# =====================================================================
class Logger:
    def __init__(self, log_path: Path = LOGS_FILE):
        self.log_path = log_path
        self.session_data = {
            "session_id": f"qsec_{int(time.time())}",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "environment": {
                "system": platform.system(),
                "node": platform.node(),
                "release": platform.release(),
                "python_version": platform.python_version(),
            },
            "transactions": [],
        }
        self.save()

    def record_transaction(self, tx: dict):
        tx["timestamp"] = datetime.now(timezone.utc).isoformat()
        self.session_data["transactions"].append(tx)
        self.save()

    def save(self):
        write_json_file(self.log_path, self.session_data)


logger = Logger()


# =====================================================================
#  Protocol Orchestrators
# =====================================================================
def run_ckd_protocol(message: str) -> dict:
    """Execute Classical Key Distribution (X25519 + HKDF) + AES-256-GCM."""
    print_header("CKD (CLASSICAL KEY DISTRIBUTION) + AES-256-GCM", C.BLUE)
    t_start = time.perf_counter()

    # 1. Key Establishment
    print_status("1. Node A (Alice)", "Generating X25519 keypair & publishing public key", "RUN", C.YELLOW)
    a_pub = Alice.ckd_publish_public_key()
    print_status("   Public Key (Alice)", f"{a_pub['public_key_hex'][:32]}...", "DONE", C.GREEN)

    print_status("2. Node B (Bob)", "Generating X25519 keypair & publishing public key", "RUN", C.YELLOW)
    b_pub = Bob.ckd_publish_public_key()
    print_status("   Public Key (Bob)", f"{b_pub['public_key_hex'][:32]}...", "DONE", C.GREEN)

    print_status("3. Diffie-Hellman", "Executing ECDH exchange & HKDF-SHA256 derivation", "RUN", C.YELLOW)
    a_key = Alice.ckd_derive_key()
    b_key = Bob.ckd_derive_key()

    if a_key["secret_key_hex"] != b_key["secret_key_hex"]:
        raise RuntimeError("CKD Key mismatch between Node A and Node B!")

    key_hex = a_key["secret_key_hex"]
    t_key_ms = round((time.perf_counter() - t_start) * 1000, 3)
    print_status("   Secret Key Derived", f"{key_hex[:24]}... [256-bit AES Key]", "SUCCESS", C.GREEN)
    print_status("   Key Establishment Time", f"{t_key_ms:.3f} ms", "METRIC", C.CYAN)

    # 2. Message Encryption by Alice
    print_status("4. Node A Encrypt", f"Encrypting message ({len(message)} chars) via AES-256-GCM", "RUN", C.YELLOW)
    t_enc_start = time.perf_counter()
    enc_res = Alice.aes_encrypt(message, protocol="CKD")
    t_enc_ms = round((time.perf_counter() - t_enc_start) * 1000, 4)
    print_status("   Ciphertext Generated", f"{enc_res['ciphertext_hex'][:32]}... Tag: {enc_res['tag_hex']}", "DONE", C.GREEN)
    print_status("   Encryption Latency", f"{t_enc_ms:.4f} ms", "METRIC", C.CYAN)

    # 3. Simulated Channel Delivery
    t_chan_start = time.perf_counter()
    time.sleep(0.015)  # 15ms simulated channel flight time
    t_chan_ms = round((time.perf_counter() - t_chan_start) * 1000, 3)
    print_status("5. Public Channel Transit", f"Dispatched across ABshared.json (No secrets exposed)", "SENT", C.GREEN)
    print_status("   Channel Transit Time", f"{t_chan_ms:.3f} ms", "METRIC", C.CYAN)

    # 4. Message Decryption by Bob
    print_status("6. Node B Decrypt", "Reading ciphertext, verifying GCM tag, decrypting", "RUN", C.YELLOW)
    t_dec_start = time.perf_counter()
    dec_res = Bob.aes_decrypt(protocol="CKD")
    t_dec_ms = round((time.perf_counter() - t_dec_start) * 1000, 4)
    print_status("   Decryption Status", f"Authentication Tag VERIFIED. Plaintext: '{dec_res['plaintext']}'", "DONE", C.GREEN)
    print_status("   Decryption Latency", f"{t_dec_ms:.4f} ms", "METRIC", C.CYAN)

    t_total_ms = round((time.perf_counter() - t_start) * 1000, 3)
    print_status("7. Total Cycle Time", f"{t_total_ms:.3f} ms", "COMPLETED", C.MAGENTA)

    metrics = {
        "protocol": "CKD (ECDH-X25519 + HKDF-SHA256)",
        "security_standard": "Classical 128-bit Security (Curve25519)",
        "message": message,
        "key_fingerprint": key_hex[:16],
        "key_establishment_ms": t_key_ms,
        "encryption_latency_ms": t_enc_ms,
        "channel_transit_ms": t_chan_ms,
        "decryption_latency_ms": t_dec_ms,
        "total_latency_ms": t_total_ms,
        "verification_success": dec_res["verification_success"],
    }
    logger.record_transaction(metrics)
    return metrics


def run_mkd_protocol(message: str) -> dict:
    """Execute Post-Quantum Key Distribution (ML-KEM-768 / Kyber) + AES-256-GCM."""
    print_header("MKD (POST-QUANTUM ML-KEM-768) + AES-256-GCM", C.MAGENTA)
    t_start = time.perf_counter()

    # 1. Keypair Generation & Public Key Announcement by Alice
    print_status("1. Node A (Alice)", "Generating ML-KEM-768 keypair (1184-byte PK, 2400-byte SK)", "RUN", C.YELLOW)
    a_pub = Alice.mkd_publish_public_key(force_new=True)
    print_status("   Public Key Published", f"{a_pub['public_key_b64'][:32]}... to ABshared.json", "DONE", C.GREEN)

    # 2. Encapsulation by Bob
    print_status("2. Node B (Bob)", "Reading Alice PK from channel, encapsulating shared secret", "RUN", C.YELLOW)
    b_enc = Bob.mkd_encapsulate()
    print_status("   Ciphertext Published", f"{b_enc['ciphertext_hex'][:32]}... ({len(bytes.fromhex(b_enc['ciphertext_hex']))} bytes)", "DONE", C.GREEN)
    print_status("   Bob Shared Secret", f"{b_enc['secret_key_hex'][:24]}...", "SAVED", C.GREEN)

    # 3. Decapsulation by Alice
    print_status("3. Node A (Alice)", "Reading Bob ciphertext from channel, decapsulating", "RUN", C.YELLOW)
    a_dec = Alice.mkd_decapsulate()
    print_status("   Alice Shared Secret", f"{a_dec['secret_key_hex'][:24]}...", "SAVED", C.GREEN)

    if a_dec["secret_key_hex"] != b_enc["secret_key_hex"]:
        raise RuntimeError("MKD Key mismatch between Node A and Node B!")

    key_hex = a_dec["secret_key_hex"]
    t_key_ms = round((time.perf_counter() - t_start) * 1000, 3)
    print_status("   PQC Key Established", f"{key_hex[:24]}... [NIST Level 3]", "SUCCESS", C.GREEN)
    print_status("   Key Establishment Time", f"{t_key_ms:.3f} ms (Encap: {b_enc['encapsulation_time_ms']}ms, Decap: {a_dec['decapsulation_time_ms']}ms)", "METRIC", C.CYAN)

    # 4. Message Encryption by Alice
    print_status("4. Node A Encrypt", f"Encrypting message ({len(message)} chars) via AES-256-GCM", "RUN", C.YELLOW)
    t_enc_start = time.perf_counter()
    enc_res = Alice.aes_encrypt(message, protocol="MKD")
    t_enc_ms = round((time.perf_counter() - t_enc_start) * 1000, 4)
    print_status("   Ciphertext Generated", f"{enc_res['ciphertext_hex'][:32]}... Tag: {enc_res['tag_hex']}", "DONE", C.GREEN)
    print_status("   Encryption Latency", f"{t_enc_ms:.4f} ms", "METRIC", C.CYAN)

    # 5. Channel Transit
    t_chan_start = time.perf_counter()
    time.sleep(0.015)
    t_chan_ms = round((time.perf_counter() - t_chan_start) * 1000, 3)
    print_status("5. Public Channel Transit", "Dispatched across ABshared.json (Zero secrets exposed)", "SENT", C.GREEN)
    print_status("   Channel Transit Time", f"{t_chan_ms:.3f} ms", "METRIC", C.CYAN)

    # 6. Message Decryption by Bob
    print_status("6. Node B Decrypt", "Reading ciphertext, verifying GCM tag, decrypting", "RUN", C.YELLOW)
    t_dec_start = time.perf_counter()
    dec_res = Bob.aes_decrypt(protocol="MKD")
    t_dec_ms = round((time.perf_counter() - t_dec_start) * 1000, 4)
    print_status("   Decryption Status", f"Authentication Tag VERIFIED. Plaintext: '{dec_res['plaintext']}'", "DONE", C.GREEN)
    print_status("   Decryption Latency", f"{t_dec_ms:.4f} ms", "METRIC", C.CYAN)

    t_total_ms = round((time.perf_counter() - t_start) * 1000, 3)
    print_status("7. Total Cycle Time", f"{t_total_ms:.3f} ms", "COMPLETED", C.MAGENTA)

    metrics = {
        "protocol": "MKD (NIST ML-KEM-768 / Kyber-768)",
        "security_standard": "Post-Quantum Security Level 3 (AES-192 equivalent quantum hardness)",
        "message": message,
        "key_fingerprint": key_hex[:16],
        "key_establishment_ms": t_key_ms,
        "encapsulation_ms": b_enc["encapsulation_time_ms"],
        "decapsulation_ms": a_dec["decapsulation_time_ms"],
        "encryption_latency_ms": t_enc_ms,
        "channel_transit_ms": t_chan_ms,
        "decryption_latency_ms": t_dec_ms,
        "total_latency_ms": t_total_ms,
        "verification_success": dec_res["verification_success"],
    }
    logger.record_transaction(metrics)
    return metrics


def run_qkd_protocol(message: str) -> dict:
    """Execute Quantum Key Distribution (BB84 + Cascade + Toeplitz PA) + AES-256-GCM."""
    print_header("QKD (BB84 QUANTUM KEY DISTRIBUTION) + AES-256-GCM", C.CYAN)
    t_start = time.perf_counter()

    print_status("1. Quantum Channel Setup", "Simulating 6000 qubits over 50km fiber (10% loss, 3% noise)", "INIT", C.CYAN)

    results = {}

    def bob_worker():
        try:
            results["bob"] = Bob.run_qkd_bob(timeout=60)
        except Exception as e:
            results["bob_err"] = str(e)

    def alice_worker():
        try:
            results["alice"] = Alice.run_qkd_alice(n_qubits=6000, loss=0.10, noise=0.03, timeout=60)
        except Exception as e:
            results["alice_err"] = str(e)

    tb = threading.Thread(target=bob_worker)
    ta = threading.Thread(target=alice_worker)

    print_status("2. BB84 Transmission", "Bob announces readiness; Alice encodes & transmits polarized qubits", "RUN", C.YELLOW)
    tb.start()
    time.sleep(0.1)  # small stagger to let Bob initialize ready handshake
    ta.start()

    tb.join(timeout=45)
    ta.join(timeout=45)

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

    key_hex = a_res["secret_key_hex"]
    t_key_ms = round((time.perf_counter() - t_start) * 1000, 3)

    print_status("3. Sifting & Cascade EC", f"Sifted & corrected parity errors; Measured QBER: {b_res['qber']:.2%}", "DONE", C.GREEN)
    print_status("4. Privacy Amplification", f"Toeplitz 2-universal hash -> {b_res['key_bits']}-bit secure key", "DONE", C.GREEN)
    print_status("   Secret Key Derived", f"{key_hex[:24]}... [Unconditional Information-Theoretic]", "SUCCESS", C.GREEN)
    print_status("   QKD Latency", f"{t_key_ms:.3f} ms", "METRIC", C.CYAN)

    # 5. Message Encryption by Alice
    print_status("5. Node A Encrypt", f"Encrypting message ({len(message)} chars) via AES-256-GCM", "RUN", C.YELLOW)
    t_enc_start = time.perf_counter()
    enc_res = Alice.aes_encrypt(message, protocol="QKD")
    t_enc_ms = round((time.perf_counter() - t_enc_start) * 1000, 4)
    print_status("   Ciphertext Generated", f"{enc_res['ciphertext_hex'][:32]}... Tag: {enc_res['tag_hex']}", "DONE", C.GREEN)
    print_status("   Encryption Latency", f"{t_enc_ms:.4f} ms", "METRIC", C.CYAN)

    # 6. Channel Transit
    t_chan_start = time.perf_counter()
    time.sleep(0.015)
    t_chan_ms = round((time.perf_counter() - t_chan_start) * 1000, 3)
    print_status("6. Public Channel Transit", "Dispatched across ABshared.json (Zero secrets exposed)", "SENT", C.GREEN)
    print_status("   Channel Transit Time", f"{t_chan_ms:.3f} ms", "METRIC", C.CYAN)

    # 7. Message Decryption by Bob
    print_status("7. Node B Decrypt", "Reading ciphertext, verifying GCM tag, decrypting", "RUN", C.YELLOW)
    t_dec_start = time.perf_counter()
    dec_res = Bob.aes_decrypt(protocol="QKD")
    t_dec_ms = round((time.perf_counter() - t_dec_start) * 1000, 4)
    print_status("   Decryption Status", f"Authentication Tag VERIFIED. Plaintext: '{dec_res['plaintext']}'", "DONE", C.GREEN)
    print_status("   Decryption Latency", f"{t_dec_ms:.4f} ms", "METRIC", C.CYAN)

    t_total_ms = round((time.perf_counter() - t_start) * 1000, 3)
    print_status("8. Total Cycle Time", f"{t_total_ms:.3f} ms", "COMPLETED", C.MAGENTA)

    metrics = {
        "protocol": "QKD (BB84 + Cascade + Toeplitz PA)",
        "security_standard": "Information-Theoretic Security (Quantum Mechanics)",
        "message": message,
        "key_fingerprint": key_hex[:16],
        "qber": round(b_res["qber"], 4),
        "key_bits": b_res["key_bits"],
        "key_establishment_ms": t_key_ms,
        "encryption_latency_ms": t_enc_ms,
        "channel_transit_ms": t_chan_ms,
        "decryption_latency_ms": t_dec_ms,
        "total_latency_ms": t_total_ms,
        "verification_success": dec_res["verification_success"],
    }
    logger.record_transaction(metrics)
    return metrics


def run_benchmark():
    """Run full comparative benchmark across CKD, MKD, and QKD."""
    print_header("QSECURE COMPREHENSIVE PROTOCOL BENCHMARK", C.YELLOW)
    test_msg = "QSecure automated benchmark transmission payload [256-bit AES-GCM]."

    results = []
    print(f"\n{C.BOLD}Benchmarking 1/3: Classical Key Distribution (X25519)...{C.RESET}")
    ckd_res = run_ckd_protocol(test_msg)
    results.append(ckd_res)

    print(f"\n{C.BOLD}Benchmarking 2/3: Post-Quantum Key Distribution (ML-KEM-768)...{C.RESET}")
    mkd_res = run_mkd_protocol(test_msg)
    results.append(mkd_res)

    print(f"\n{C.BOLD}Benchmarking 3/3: Quantum Key Distribution (BB84)...{C.RESET}")
    qkd_res = run_qkd_protocol(test_msg)
    results.append(qkd_res)

    # Render summary table
    print_header("BENCHMARK COMPARISON MATRIX", C.GREEN)
    header_fmt = f"{C.BOLD}{'Protocol':<22} | {'Security Type':<26} | {'Key Estab (ms)':<15} | {'Encrypt (ms)':<13} | {'Decrypt (ms)':<13} | {'Total (ms)':<11}{C.RESET}"
    print(header_fmt)
    print("-" * 110)

    for r in results:
        p_name = r["protocol"].split("(")[0].strip()
        sec = r["security_standard"][:25]
        row = (
            f"{C.CYAN}{p_name:<22}{C.RESET} | "
            f"{C.WHITE}{sec:<26}{C.RESET} | "
            f"{C.YELLOW}{r['key_establishment_ms']:>14.2f} {C.RESET} | "
            f"{C.GREEN}{r['encryption_latency_ms']:>12.4f} {C.RESET} | "
            f"{C.GREEN}{r['decryption_latency_ms']:>12.4f} {C.RESET} | "
            f"{C.MAGENTA}{r['total_latency_ms']:>10.2f}{C.RESET}"
        )
        print(row)
    print("-" * 110)
    print(f"{C.DIM}Metrics recorded in logs.json{C.RESET}\n")


def inspect_channel_and_secrets():
    """Display channel verification and local secret storage state."""
    print_header("CHANNEL & SECRET ISOLATION INSPECTION", C.CYAN)
    shared = read_json_file(SHARED_FILE)
    sec_a = read_json_file(SECRET_A_FILE)
    sec_b = read_json_file(SECRET_B_FILE)

    # Verify zero secrets on public channel
    exposed_keys = []
    if "encrypted_transmission" in shared:
        for k in ["secret_key_hex", "secret_key"]:
            if k in shared["encrypted_transmission"]:
                exposed_keys.append(k)

    print(f"\n{C.BOLD}1. Untrusted Public Channel (Shared_Files/ABshared.json):{C.RESET}")
    print(f"   Active Protocol : {C.CYAN}{shared.get('active_protocol', 'N/A')}{C.RESET}")
    print(f"   Transmission    : {C.YELLOW}{shared.get('encrypted_transmission', {}).get('status', 'IDLE')}{C.RESET}")
    print(f"   Ciphertext      : {C.DIM}{str(shared.get('encrypted_transmission', {}).get('ciphertext_hex'))[:48]}...{C.RESET}")
    if exposed_keys:
        print(f"   {C.RED}[FAIL] Exposed keys found on public channel: {exposed_keys}{C.RESET}")
    else:
        print(f"   {C.GREEN}[PASS] Zero Secret Keys on Public Channel (Strict Device Isolation Verified){C.RESET}")

    print(f"\n{C.BOLD}2. Node A Local Storage (Node_A/secretAB.json):{C.RESET}")
    print(f"   Role            : Alice")
    print(f"   Active Key Hex  : {C.GREEN}{str(sec_a.get('current_secret_key_hex'))[:32]}...{C.RESET}")
    print(f"   CKD Status      : {sec_a.get('ckd', {}).get('status')}")
    print(f"   QKD Status      : {sec_a.get('qkd', {}).get('status')}")
    print(f"   MKD Status      : {sec_a.get('mkd', {}).get('status')}")

    print(f"\n{C.BOLD}3. Node B Local Storage (Node_B/secretAB.json):{C.RESET}")
    print(f"   Role            : Bob")
    print(f"   Active Key Hex  : {C.GREEN}{str(sec_b.get('current_secret_key_hex'))[:32]}...{C.RESET}")
    print(f"   CKD Status      : {sec_b.get('ckd', {}).get('status')}")
    print(f"   QKD Status      : {sec_b.get('qkd', {}).get('status')}")
    print(f"   MKD Status      : {sec_b.get('mkd', {}).get('status')}")

    # Check key synchronization
    if sec_a.get("current_secret_key_hex") and sec_a.get("current_secret_key_hex") == sec_b.get("current_secret_key_hex"):
        print(f"\n   {C.GREEN}[SYNC VERIFIED] Node A and Node B currently hold matching 256-bit secret keys.{C.RESET}")
    else:
        print(f"\n   {C.YELLOW}[SYNC PENDING] Node A and Node B keys differ or are uninitialized.{C.RESET}")


# =====================================================================
#  Interactive CLI Menu
# =====================================================================
def interactive_menu():
    while True:
        print_banner()
        print(f"{C.BOLD}Select Communication / Cryptographic Operation:{C.RESET}\n")
        print(f"  {C.CYAN}[1]{C.RESET} {C.BOLD}Communicate via QKD + AES-256{C.RESET}    (BB84 Quantum Key Distribution)")
        print(f"  {C.MAGENTA}[2]{C.RESET} {C.BOLD}Communicate via MKD + AES-256{C.RESET}    (Post-Quantum ML-KEM-768 / Kyber)")
        print(f"  {C.BLUE}[3]{C.RESET} {C.BOLD}Communicate via CKD + AES-256{C.RESET}    (Classical ECDH-X25519 + HKDF)")
        print(f"  {C.YELLOW}[4]{C.RESET} {C.BOLD}Send Custom Message with Current Key{C.RESET}")
        print(f"  {C.GREEN}[5]{C.RESET} {C.BOLD}Run Full Benchmark (All 3 Protocols Comparative Analysis){C.RESET}")
        print(f"  {C.WHITE}[6]{C.RESET} {C.BOLD}Inspect System & Channel Status (Verify Zero-Secret Channel){C.RESET}")
        print(f"  {C.RED}[7]{C.RESET} {C.BOLD}Exit{C.RESET}\n")

        try:
            choice = input(f"{C.BOLD}Enter option [1-7]: {C.RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting QSecure...")
            break

        if choice == "1":
            default_msg = "Top-secret quantum-secured transmission from Node A to Node B."
            custom = input(f"\nMessage to encrypt (Press Enter for default: '{default_msg}'): ").strip()
            msg = custom if custom else default_msg
            try:
                run_qkd_protocol(msg)
            except Exception as e:
                print(f"\n{C.RED}[ERROR] QKD Protocol failed: {e}{C.RESET}")
            input(f"\n{C.DIM}Press Enter to return to menu...{C.RESET}")

        elif choice == "2":
            default_msg = "Post-quantum lattice-encrypted transmission resistant to Shor's algorithm."
            custom = input(f"\nMessage to encrypt (Press Enter for default: '{default_msg}'): ").strip()
            msg = custom if custom else default_msg
            try:
                run_mkd_protocol(msg)
            except Exception as e:
                print(f"\n{C.RED}[ERROR] MKD Protocol failed: {e}{C.RESET}")
            input(f"\n{C.DIM}Press Enter to return to menu...{C.RESET}")

        elif choice == "3":
            default_msg = "Classical high-throughput encrypted transmission via Curve25519."
            custom = input(f"\nMessage to encrypt (Press Enter for default: '{default_msg}'): ").strip()
            msg = custom if custom else default_msg
            try:
                run_ckd_protocol(msg)
            except Exception as e:
                print(f"\n{C.RED}[ERROR] CKD Protocol failed: {e}{C.RESET}")
            input(f"\n{C.DIM}Press Enter to return to menu...{C.RESET}")

        elif choice == "4":
            custom = input("\nEnter plaintext message to send from Alice to Bob: ").strip()
            if not custom:
                custom = "Direct transmission payload."
            try:
                t_start = time.perf_counter()
                enc_res = Alice.aes_encrypt(custom)
                dec_res = Bob.aes_decrypt()
                t_total_ms = round((time.perf_counter() - t_start) * 1000, 3)
                print_status("Alice Encrypt", f"Key source: {enc_res['key_source']} in {enc_res['encryption_latency_ms']} ms", "OK", C.GREEN)
                print_status("Bob Decrypt", f"Decrypted: '{dec_res['plaintext']}' in {dec_res['decryption_latency_ms']} ms", "OK", C.GREEN)
                print_status("Total Latency", f"{t_total_ms} ms", "METRIC", C.MAGENTA)
            except Exception as e:
                print(f"\n{C.RED}[ERROR] Direct encryption failed: {e}{C.RESET}")
            input(f"\n{C.DIM}Press Enter to return to menu...{C.RESET}")

        elif choice == "5":
            run_benchmark()
            input(f"\n{C.DIM}Press Enter to return to menu...{C.RESET}")

        elif choice == "6":
            inspect_channel_and_secrets()
            input(f"\n{C.DIM}Press Enter to return to menu...{C.RESET}")

        elif choice == "7":
            print(f"\n{C.CYAN}Shutting down QSecure. Session log saved to logs.json.{C.RESET}\n")
            break

        else:
            print(f"\n{C.RED}Invalid selection. Please choose an option from 1 to 7.{C.RESET}")
            time.sleep(1)


# =====================================================================
#  CLI Arguments Entry Point
# =====================================================================
def main():
    parser = argparse.ArgumentParser(description="QSecure - Quantum-Resilient Cryptographic Orchestrator")
    parser.add_argument("--protocol", choices=["QKD", "MKD", "CKD"], help="Run single protocol immediately")
    parser.add_argument("--message", default="Automated QSecure transmission.", help="Message to encrypt")
    parser.add_argument("--benchmark", action="store_true", help="Run comprehensive comparative benchmark")
    parser.add_argument("--status", action="store_true", help="Inspect channel and secret state")
    args = parser.parse_args()

    if args.benchmark:
        print_banner()
        run_benchmark()
    elif args.status:
        print_banner()
        inspect_channel_and_secrets()
    elif args.protocol == "QKD":
        print_banner()
        run_qkd_protocol(args.message)
    elif args.protocol == "MKD":
        print_banner()
        run_mkd_protocol(args.message)
    elif args.protocol == "CKD":
        print_banner()
        run_ckd_protocol(args.message)
    else:
        interactive_menu()


if __name__ == "__main__":
    main()
