# Performance Benchmark Results (`veriseal` — Table 2.12)

## 1. Environment & Methodology

| Component | Specification |
| :--- | :--- |
| **CPU** | AMD Ryzen 7 7435HS (16 logical cores) |
| **Memory (RAM)** | 8036548 kB |
| **Operating System / Kernel** | Linux 6.6.87.2-microsoft-standard-WSL2 (x86_64) (`Linux-6.6.87.2-microsoft-standard-WSL2-x86_64-with-glibc2.39`) |
| **Python Runtime** | Python 3.13.18 |
| **Cryptographic Library** | `cryptography` 50.0.2 (OpenSSL 4.0.3 29 Sep 2026) |
| **Monotonic Timer** | `time.perf_counter_ns (monotonic clock)` |
| **Percentile Formula** | nearest-rank: ceil(0.95 * n) (1-indexed) |
| **Repetitions** | 5 warm-up runs + 30 measured runs (Keygen: 10 runs) |

---

## 2. Key Generation Latency (`generate_keypair`)

| Profile | Runs | Median (ms) | P95 (ms) | Median (µs) | P95 (µs) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `rsa-pss-sha256` | 10 | 215.066 | 711.275 | 215065.51 | 711275.19 |
| `ecdsa-p256-sha256` | 10 | 0.054 | 0.097 | 54.34 | 97.00 |
| `ed25519` | 10 | 0.100 | 0.230 | 99.92 | 230.14 |

---

## 3. Artifact SHA-256 Hashing Latency

| Artifact | Size (Bytes) | In-Memory Median (ms) | In-Memory P95 (ms) | File Stream Median (ms) | File Stream P95 (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **10KB** | 10,240 | 0.010 | 0.012 | 0.038 | 0.060 |
| **1MB** | 1,048,576 | 0.912 | 2.200 | 2.638 | 3.456 |
| **50MB** | 52,428,800 | 46.091 | 48.429 | 57.710 | 62.042 |

---

## 4. Isolated Cryptographic Sign & Verify Latency (over Canonical Manifest `M`)

| Profile | Manifest `|M|` (B) | Sign Median (µs) | Sign P95 (µs) | Verify Median (µs) | Verify P95 (µs) | Sign Median (ms) | Verify Median (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `rsa-pss-sha256` | 306 | 3045.12 | 3924.36 | 73.18 | 165.05 | 3.045 | 0.073 |
| `ecdsa-p256-sha256` | 309 | 47.82 | 80.85 | 153.15 | 191.61 | 0.048 | 0.153 |
| `ed25519` | 299 | 77.56 | 111.41 | 158.10 | 250.82 | 0.078 | 0.158 |

---

## 5. End-to-End CLI `veriseal sign` & `veriseal verify` Latency

| Profile | Artifact | Size (Bytes) | E2E `sign` Median (ms) | E2E `sign` P95 (ms) | E2E `verify` Median (ms) | E2E `verify` P95 (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `rsa-pss-sha256` | **10KB** | 10,240 | 10.552 | 12.305 | 3.618 | 5.296 |
| `rsa-pss-sha256` | **1MB** | 1,048,576 | 18.263 | 25.708 | 6.694 | 9.365 |
| `rsa-pss-sha256` | **50MB** | 52,428,800 | 69.230 | 77.547 | 63.320 | 72.813 |
| `ecdsa-p256-sha256` | **10KB** | 10,240 | 7.251 | 9.234 | 3.317 | 5.010 |
| `ecdsa-p256-sha256` | **1MB** | 1,048,576 | 10.516 | 12.804 | 6.641 | 8.504 |
| `ecdsa-p256-sha256` | **50MB** | 52,428,800 | 68.593 | 77.617 | 64.567 | 70.590 |
| `ed25519` | **10KB** | 10,240 | 10.149 | 19.987 | 4.228 | 7.399 |
| `ed25519` | **1MB** | 1,048,576 | 10.919 | 14.430 | 8.824 | 14.389 |
| `ed25519` | **50MB** | 52,428,800 | 67.151 | 73.604 | 64.188 | 70.135 |

---

## 6. Key, Signature, Manifest, and Bundle Byte Sizes

| Profile | Private Key DER (B) | Public Key SPKI DER (B) | Private Key PEM (B) | Public Key PEM (B) | Canonical Manifest `M` (B) | Raw Signature (B) | Bundle JSON (B) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `rsa-pss-sha256` | 1794 | 422 | 2484 | 625 | 306 | 384 | 989 |
| `ecdsa-p256-sha256` | 138 | 91 | 241 | 178 | 309 | 64 | 569 |
| `ed25519` | 48 | 44 | 119 | 113 | 299 | 64 | 557 |

---

## 7. How to Reproduce

```sh
uv run python benchmarks/crypto_benchmark.py
```

- Complete JSON output (with all raw latency arrays): `benchmarks/results/benchmark_results.json`
- Complete CSV output (for Appendix `j.iii`): `benchmarks/results/raw_latencies.csv`
