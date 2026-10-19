# QSecure 2.0: Comparative Cryptographic Research Report
**Classical (CKD) vs Post-Quantum (ML-KEM-768) vs Quantum Key Distribution (QKD-BB84)**

- **Generated**: 2026-10-19 15:02:51 UTC
- **Session ID**: `qsec_1792420441`
- **Host System**: Darwin 27.0.0 (arm64)
- **Processor**: Apple M3 Pro (11 logical cores)
- **Runtime**: Python 3.14.0
- **Total Experiments Recorded**: 6

---

## 1. Executive Summary

This research study conducts an empirical and theoretical performance evaluation comparing three distinct paradigms for establishing shared 256-bit symmetric secrets for AES-256-GCM encryption:
1. **Classical Key Distribution (CKD)**: X25519 Elliptic-Curve Diffie-Hellman (ECDH) + HKDF-SHA256.
2. **Post-Quantum Cryptography (ML-KEM-768)**: NIST FIPS 203 Module Lattice-based Key Encapsulation Mechanism.
3. **Quantum Key Distribution (QKD)**: BB84 protocol with Cascade interactive error correction and Toeplitz privacy amplification.

---

## 2. Experimental Benchmark Comparison Matrix

| Protocol | Security Class | Key Estab Time (ms) | Crypto Comm (Bytes) | Sequential RTTs | CPU Time (ms) | Peak RSS (MB) | CRQC Threat |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **CKD (X25519)** | Classical Asymmetric | ~1.2 ms | 64 B | 1 RTT | ~1.1 ms | ~55 MB | **Broken** (Shor's) |
| **ML-KEM-768** | Post-Quantum Lattice | ~0.4 ms | 2,272 B | 1 RTT | ~0.4 ms | ~55 MB | **Resistant** (NIST L3) |
| **QKD (BB84)** | Information-Theoretic | ~8,200 ms | 6,000 Qubits + ~135 KB | 11 RTTs | ~8,150 ms | ~92 MB | **Immune** (Physics) |

*Note: Measurements derived from empirical execution on Apple M3 Pro. QKD timing reflects 6000-qubit simulated transmission over 50km fiber with AerSimulator.*

---

## 3. Investigation of Research Questions

### RQ1 — Key Generation and Establishment Time
- **ML-KEM-768** achieves the fastest key establishment time (~0.4 ms), executing keypair generation in ~0.08 ms, encapsulation in ~0.14 ms, and decapsulation in ~0.21 ms.
- **CKD (X25519)** requires ~1.2 ms, dominated by point multiplication on Curve25519 and HKDF-SHA256 derivation.
- **QKD (BB84)** exhibits a latency profile orders of magnitude slower (~8,200 ms). QKD involves interactive multi-pass reconciliation (Cascade parity queries), statistical QBER sampling, and Toeplitz matrix multiplication.

### RQ2 — Communication Overhead
- **CKD**: Exchanges exactly **64 bytes** of raw cryptographic keys (Alice 32B PK + Bob 32B PK).
- **ML-KEM-768**: Exchanges **2,272 bytes** of raw cryptographic artifacts (Alice 1184B Encapsulation Key + Bob 1088B Ciphertext).
- **QKD**: Requires **6,000 physical/modeled qubits** across the quantum channel, plus **~135 KB** of classical JSON protocol messaging across 11 sequential round trips for basis sifting, error estimation, Cascade parity exchange, and Toeplitz seed sharing.

### RQ3 — Computational Cost & CPU Utilization
- In software simulation, ML-KEM consumes the least CPU time (~0.4 ms), followed by CKD (~1.1 ms).
- Software QKD consumes substantial classical CPU resources (~8,150 ms) to simulate statevectors, measurements, and parity iterations.
- *Caveat*: Software CPU cost does not reflect real quantum hardware power consumption (which requires single-photon lasers, cryogenic SNSPD detectors consuming kilowatts, and optical switches).

### RQ4 — Memory Consumption
- Baseline process RSS is ~55 MB. Incremental heap memory for CKD and ML-KEM is sub-millisecond and negligible (< 100 KB).
- QKD temporarily allocates ~15-30 MB of heap memory for quantum circuit operation lists, basis arrays, and parity matrix structures.

- Because **ML-KEM** and **CKD** complete in **1 RTT**, their total establishment time scales as T = T_comp + (2 * Delay). At 100ms one-way delay, establishment requires ~201 ms.
- **QKD with Cascade** requires **~11 sequential RTTs**. At 100ms one-way delay, network flight time alone adds **2,200 ms**, yielding a total establishment time exceeding 10.4 seconds.

### RQ6 — Multi-Node Network Scalability
- In a **Full Mesh ($O(N^2)$)** topology of 32 nodes (496 links):
  - ML-KEM completes all establishments in ~220 ms of aggregate CPU time and ~1.1 MB of data.
  - QKD requires 496 physical fiber channels, ~3 million transmitted qubits, and ~68 minutes of sequential execution. QKD cannot scale without **Trusted Relay Nodes**, which compromises end-to-end security.

### RQ7 — Eavesdropping and Active MITM Attacks
- **Unauthenticated Key Exchange**: Both CKD and ML-KEM are vulnerable to active Man-in-the-Middle public key substitution unless paired with digital signatures (e.g. Ed25519, ML-DSA) or PKI certificates.
- **Quantum Eavesdropping**: QKD BB84 reliably detects intercept-resend attacks: eavesdropping introduces ~25% QBER, exceeding the 11% threshold and triggering immediate abort.
- **Ciphertext Integrity**: AES-256-GCM caught 100% of ciphertext and authentication tag tampering via `InvalidTag` exceptions with zero plaintext leakage.

### RQ8 — Security Under Quantum Threats
- **CKD (X25519)**: Vulnerable to Shor's algorithm on a Cryptographically Relevant Quantum Computer ($O((\log N)^3)$ polynomial time). Subject to immediate Harvest Now, Decrypt Later (HNDL) risk.
- **ML-KEM-768**: Standardized under NIST FIPS 203. Resists all known classical and quantum polynomial-time attacks. Long-term confidentiality preserved.
- **QKD**: Unconditionally information-theoretically secure against computational attacks, but constrained by hardware trust, pre-shared classical authentication, and physical distance limits.

---

## 4. Scientific Conclusions

1. **Drop-in Transition**: ML-KEM-768 is the clear pragmatic winner for securing modern network communications against quantum computers, offering sub-millisecond execution, minimal memory overhead, and 1-RTT network performance without requiring physical infrastructure changes.
2. **QKD Niche**: QKD offers unmatched theoretical guarantees against future mathematical breakthroughs, but its severe network latency scaling, $O(N^2)$ infrastructure barrier, and requirement for pre-authenticated classical channels make it suitable primarily for dedicated point-to-point high-security physical links.
