![Quantum PQC Canary CI](https://github.com/Haidriyam/quantum-pqc-tls-canary/actions/workflows/devsecops-ci.yml/badge.svg)

# Hybrid Post-Quantum Cryptography (PQC) Ingress Canary & Telemetry Pipeline

An ingress controller and cryptographic security canary implementing hybrid post-quantum key encapsulation (NIST FIPS 203 ML-KEM-768 + X25519). Designed to protect high-consequence edge cyber-physical systems (CPS) from Harvest-Now-Decrypt-Later (HNDL) quantum threats while actively monitoring wire-overhead amplification and preventing protocol downgrade attacks.

```text
[ Edge CPS / SCADA Node ] ──► [ Hybrid Handshake: ML-KEM-768 + X25519 ]
                                                │
                                                ▼
[ MTU & Latency Canary ] ◄── [ Shared Secret Combiner: SHA-384 ] ◄── [ Downgrade Detector ]
         │                                      │
         ▼                                      ▼
(Wire Overhead Audited)                (Zero-Trust Telemetry)