# QSecure 2.0: Comparative Cryptographic Benchmarking Laboratory

**Quantum-Resilient Cryptographic Orchestration & Comparative Performance Evaluation**

QSecure 2.0 is a research terminal application that compares three fundamental paradigms for establishing shared 256-bit symmetric secrets between two sovereign communicating nodes, **Alice (Node A)** and **Bob (Node B)**, for authenticated symmetric encryption via **AES-256-GCM**:

1. **CKD — Classical Key Distribution**: X25519 Elliptic-Curve Diffie-Hellman (ECDH) + HKDF-SHA256.
2. **ML-KEM — Post-Quantum Key Distribution**: NIST FIPS 203 Module Lattice-based Key Encapsulation Mechanism (ML-KEM-768 / Kyber-768).
3. **QKD — Quantum Key Distribution**: BB84 protocol with Cascade interactive error correction and Toeplitz matrix privacy amplification.

---

## Architecture & Security Isolation

- **Untrusted Public Channel** (`Shared_Files/ABshared.json`): Transmits public keys, encapsulation ciphertexts, and AES-256-GCM ciphertexts. **Zero secret or private keys are ever exposed on the public channel.**
- **Node A Local Vault** (`Node_A/secretAB.json`): Alice's sovereign keystore holding private keys, derived secrets, and local metrics.
- **Node B Local Vault** (`Node_B/secretAB.json`): Bob's sovereign keystore holding decapsulation secrets and local metrics.
- **QKD Classical Channel** (`Shared_Files/qkd_channel/`): Authenticated classical reconciliation messages protected by pre-shared HMAC keys.
- **Audit & Experiment Log** (`logs.json`): Non-destructive JSON history recording granular execution metrics without exposing secret keys.

---

## Installation & Prerequisites

Python 3.10+ is recommended. Install required dependencies:

```bash
pip install -r requirements.txt
```

### Dependencies:
- `cryptography`: X25519 ECDH, HKDF-SHA256, AES-256-GCM.
- `pqcrypto`: NIST ML-KEM-768 (Kyber-768).
- `qiskit` & `qiskit-aer`: Quantum circuits and AerSimulator for BB84 photon measurement.
- `rich`: Modern responsive terminal UI and comparison tables.
- `psutil`: High-resolution process CPU and memory RSS monitoring.

---

## Launching QSecure 2.0

### Interactive Terminal Interface
Launch the laboratory dashboard from the repository root:
```bash
python3 main.py
```
*(Alternatively, you can launch from `Main_File_Nest/main.py`)*

### Command-Line Arguments & Automation

| Flag | Purpose | Example |
| :--- | :--- | :--- |
| `--benchmark` | Run full comparative benchmark (CKD, ML-KEM, QKD) | `python3 main.py --benchmark` |
| `--protocol {CKD,MKD,QKD}` | Run a single protocol demonstration | `python3 main.py --protocol MKD` |
| `--message "TEXT"` | Specify custom payload to encrypt | `python3 main.py --protocol CKD --message "Confidential"` |
| `--status` | Inspect channel and verify zero secrets on public channel | `python3 main.py --status` |
| `--latency` | Run network latency experiment (RQ5: 0 to 200 ms) | `python3 main.py --latency` |
| `--scalability` | Run multi-node scalability experiment (RQ6: 2 to 32 nodes) | `python3 main.py --scalability` |
| `--attacks` | Run controlled security & MITM attack simulations (RQ7) | `python3 main.py --attacks` |
| `--quantum-threat` | Display quantum adversary analysis (RQ8: Shor's/Grover's) | `python3 main.py --quantum-threat` |
| `--dashboard` | Render master research results dashboard synthesizing all 8 RQs | `python3 main.py --dashboard` |
| `--export` | Export session report to Markdown, CSV, and JSON | `python3 main.py --export` |
| `--repetitions N` | Set number of experiment repetitions | `python3 main.py --benchmark --repetitions 5` |
| `--qubits N` | Set qubit count for QKD simulation (default: 6000) | `python3 main.py --protocol QKD --qubits 6000` |

---

## Research Questions & Findings (RQ1 – RQ8)

1. **RQ1: Key Generation Time**
   - **ML-KEM-768**: Fastest establishment (~0.4 ms), with keygen (~0.08 ms), encapsulation (~0.14 ms), and decapsulation (~0.21 ms).
   - **CKD (X25519)**: ~1.2 ms, dominated by point multiplication and HKDF.
   - **QKD (BB84)**: ~8,200 ms, dominated by interactive multi-pass reconciliation and sampling.
2. **RQ2: Communication Overhead**
   - **CKD**: 64 bytes raw cryptographic keys (Alice 32B PK + Bob 32B PK).
   - **ML-KEM**: 2,272 bytes raw cryptographic payload (1184B EK + 1088B CT).
   - **QKD**: 6,000 transmitted qubits + ~135 KB of classical JSON reconciliation messages across 11 RTTs.
3. **RQ3: Computational Cost (CPU)**
   - Software simulation CPU time: ML-KEM (~0.4 ms) consumes least CPU, followed by CKD (~1.1 ms) and QKD (~8.1s).
   - Physical QKD hardware power (lasers/cryogenic detectors) is marked as unsupported for software measurement.
4. **RQ4: Memory Usage**
   - CKD and ML-KEM have negligible incremental heap footprints (< 100 KB).
   - QKD allocates ~15-30 MB of heap memory for quantum circuit operation lists and basis arrays.
5. **RQ5: Key Establishment Latency Under Network Delays**
   - CKD and ML-KEM require only **1 RTT** ($2 \times \text{delay}$), scaling minimally with distance.
   - QKD Cascade requires **~11 sequential RTTs**, suffering severe flight delays (+2,200 ms at 100ms one-way delay).
6. **RQ6: Multi-Node Scalability**
   - In a 32-node Full Mesh (496 links), ML-KEM completes all establishments in ~220 ms CPU time and ~1.1 MB of data.
   - QKD requires 496 physical fiber channels, ~3 million transmitted qubits, and ~68 minutes of sequential execution.
7. **RQ7: Eavesdropping and Active MITM Attacks**
   - Unauthenticated CKD and ML-KEM are completely vulnerable to active MITM key substitution (neither provides peer authentication alone).
   - QKD inherently detects quantum interception: intercept-resend eavesdropping drives QBER above the 11% threshold and triggers immediate protocol abort.
   - AES-256-GCM reliably detects 100% of ciphertext tampering via `InvalidTag`.
8. **RQ8: Security Under Quantum Threats**
   - CKD is completely broken by Shor's algorithm on a Cryptographically Relevant Quantum Computer ($O((\log N)^3)$ polynomial time). Subject to Harvest Now, Decrypt Later (HNDL) risk.
   - ML-KEM-768 resists all known quantum attacks (NIST Category 3 / AES-192 equivalent).
   - QKD provides unconditional information-theoretic security rooted in physics, but requires pre-authenticated classical channels and dedicated physical infrastructure.
