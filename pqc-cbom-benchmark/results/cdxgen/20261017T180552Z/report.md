# cdxgen PQC benchmark results

- Run: `20261017T180552Z`
- cdxgen version: `[1mCycloneDX Generator 12.8.4[0m
Runtime: Node.js, Version: 24.19.0`
- Cases: 9
- Successful scans: 9/9
- Cases with at least one algorithm detection: 0/9
- Aggregate TP / FP / missed: 0 / 0 / 105
- Micro recall / precision: 0.000 / N/A

A successful scan means cdxgen exited with code 0 and produced a parseable BOM. Algorithm detection is scored separately using only components whose type is `cryptographic-asset`; ordinary dependencies do not count.

| Case | Scan | TP | FP | Missed | Recall | Precision | Runtime (s) |
|---|---:|---:|---:|---:|---:|---:|---:|
| H1 | OK | 0 | 0 | 7 | 0.000 | N/A | 37.50 |
| H2 | OK | 0 | 0 | 9 | 0.000 | N/A | 27.91 |
| H3 | OK | 0 | 0 | 10 | 0.000 | N/A | 28.31 |
| H4 | OK | 0 | 0 | 13 | 0.000 | N/A | 26.85 |
| H5 | OK | 0 | 0 | 8 | 0.000 | N/A | 26.94 |
| H6 | OK | 0 | 0 | 9 | 0.000 | N/A | 27.49 |
| H7 | OK | 0 | 0 | 14 | 0.000 | N/A | 30.35 |
| H8 | OK | 0 | 0 | 25 | 0.000 | N/A | 27.27 |
| H9 | OK | 0 | 0 | 10 | 0.000 | N/A | 26.75 |

## Per-case details

### H1 — What if macros (metaprogramming) are used to inject cryptographic elements into source code?

- Target: `targets/h01_metaprogramming`
- Command: `['C:\\Users\\saket\\AppData\\Roaming\\npm\\cdxgen.CMD', '--include-crypto', '-o', 'C:\\Users\\saket\\OneDrive\\Desktop\\pqc-compliance-schema\\pqc-cbom-benchmark\\results\\cdxgen\\20261017T180552Z\\h1\\bom.json', 'C:\\Users\\saket\\OneDrive\\Desktop\\pqc-compliance-schema\\pqc-cbom-benchmark\\targets\\h01_metaprogramming']`
- Exit code: `0`; scan succeeded: `true`; algorithm detection succeeded: `false`
- BOM: `h1\bom.json`
- Log: `h1\cdxgen.log`
- Result: `h1\result.json`
- Detected (normalized): None
- True positives: None
- False positives (normalized): None
- Missed: `AES-256-GCM`, `ChaCha20-Poly1305`, `ECDSA-P-384-SHA-384`, `HKDF-SHA-384`, `ML-KEM-768`, `SHA-512`, `X25519`

### H2 — What if cryptographic elements are abstracted behind function calls, making them less visible to static analyzers?

- Target: `targets/h02_abstraction`
- Command: `['C:\\Users\\saket\\AppData\\Roaming\\npm\\cdxgen.CMD', '--include-crypto', '-o', 'C:\\Users\\saket\\OneDrive\\Desktop\\pqc-compliance-schema\\pqc-cbom-benchmark\\results\\cdxgen\\20261017T180552Z\\h2\\bom.json', 'C:\\Users\\saket\\OneDrive\\Desktop\\pqc-compliance-schema\\pqc-cbom-benchmark\\targets\\h02_abstraction']`
- Exit code: `0`; scan succeeded: `true`; algorithm detection succeeded: `false`
- BOM: `h2\bom.json`
- Log: `h2\cdxgen.log`
- Result: `h2\result.json`
- Detected (normalized): None
- True positives: None
- False positives (normalized): None
- Missed: `AES-128-GCM`, `AES-256-CBC-PKCS7`, `ChaCha20-Poly1305`, `Ed25519`, `HKDF-SHA-256`, `HMAC-SHA-256`, `RSA-3072-PSS-SHA-256`, `SHA3-384`, `SHA-512`

### H3 — What if cryptographic elements are encapsulated within third-party dependencies?

- Target: `targets/h03_dependencies`
- Command: `['C:\\Users\\saket\\AppData\\Roaming\\npm\\cdxgen.CMD', '--include-crypto', '-o', 'C:\\Users\\saket\\OneDrive\\Desktop\\pqc-compliance-schema\\pqc-cbom-benchmark\\results\\cdxgen\\20261017T180552Z\\h3\\bom.json', 'C:\\Users\\saket\\OneDrive\\Desktop\\pqc-compliance-schema\\pqc-cbom-benchmark\\targets\\h03_dependencies']`
- Exit code: `0`; scan succeeded: `true`; algorithm detection succeeded: `false`
- BOM: `h3\bom.json`
- Log: `h3\cdxgen.log`
- Result: `h3\result.json`
- Detected (normalized): None
- True positives: None
- False positives (normalized): None
- Missed: `AES-128-CBC-PKCS7`, `AES-256-KW`, `ECDSA-P-384-SHA-384`, `Ed25519`, `HMAC-SHA-1`, `HMAC-SHA-256`, `SHA-1`, `SHA-512`, `X25519`, `XSalsa20-Poly1305`

### H4 — What if a function contains both quantum-resistant and quantum-vulnerable elements? Compliant or not?

- Target: `targets/h04_mixed_classical_pqc`
- Command: `['C:\\Users\\saket\\AppData\\Roaming\\npm\\cdxgen.CMD', '--include-crypto', '-o', 'C:\\Users\\saket\\OneDrive\\Desktop\\pqc-compliance-schema\\pqc-cbom-benchmark\\results\\cdxgen\\20261017T180552Z\\h4\\bom.json', 'C:\\Users\\saket\\OneDrive\\Desktop\\pqc-compliance-schema\\pqc-cbom-benchmark\\targets\\h04_mixed_classical_pqc']`
- Exit code: `0`; scan succeeded: `true`; algorithm detection succeeded: `false`
- BOM: `h4\bom.json`
- Log: `h4\cdxgen.log`
- Result: `h4\result.json`
- Detected (normalized): None
- True positives: None
- False positives (normalized): None
- Missed: `AES-256-GCM`, `ECDH-P-384`, `ECDSA-P-256-SHA-256`, `Ed25519`, `HKDF-SHA-256`, `HKDF-SHA-384`, `ML-DSA-65`, `ML-KEM-1024`, `ML-KEM-768`, `RSA-2048-OAEP-SHA-256`, `RSA-3072-OAEP-SHA-256`, `SHA-512`, `X25519`

### H5 — What if a wrapper encapsulates quantum-resistant cryptography under a name that suggests a quantum-vulnerable algorithm?

- Target: `targets/h05_misleading_names`
- Command: `['C:\\Users\\saket\\AppData\\Roaming\\npm\\cdxgen.CMD', '--include-crypto', '-o', 'C:\\Users\\saket\\OneDrive\\Desktop\\pqc-compliance-schema\\pqc-cbom-benchmark\\results\\cdxgen\\20261017T180552Z\\h5\\bom.json', 'C:\\Users\\saket\\OneDrive\\Desktop\\pqc-compliance-schema\\pqc-cbom-benchmark\\targets\\h05_misleading_names']`
- Exit code: `0`; scan succeeded: `true`; algorithm detection succeeded: `false`
- BOM: `h5\bom.json`
- Log: `h5\cdxgen.log`
- Result: `h5\result.json`
- Detected (normalized): None
- True positives: None
- False positives (normalized): None
- Missed: `AES-256-GCM`, `HKDF-SHA-256`, `ML-DSA-65`, `ML-KEM-1024`, `ML-KEM-768`, `RSA-2048-PSS-SHA-256`, `SHA-512`, `X25519`

### H6 — What if algorithm selection is driven by configuration files (JSON/YAML/XML/TOML/INI) and environment variables?

- Target: `targets/h06_external_config`
- Command: `['C:\\Users\\saket\\AppData\\Roaming\\npm\\cdxgen.CMD', '--include-crypto', '-o', 'C:\\Users\\saket\\OneDrive\\Desktop\\pqc-compliance-schema\\pqc-cbom-benchmark\\results\\cdxgen\\20261017T180552Z\\h6\\bom.json', 'C:\\Users\\saket\\OneDrive\\Desktop\\pqc-compliance-schema\\pqc-cbom-benchmark\\targets\\h06_external_config']`
- Exit code: `0`; scan succeeded: `true`; algorithm detection succeeded: `false`
- BOM: `h6\bom.json`
- Log: `h6\cdxgen.log`
- Result: `h6\result.json`
- Detected (normalized): None
- True positives: None
- False positives (normalized): None
- Missed: `AES-256-GCM`, `ECDSA-P-384-SHA-384`, `HKDF-SHA-256`, `HMAC-SHA-384`, `ML-KEM-1024`, `RSA-3072-OAEP-SHA-256`, `SHA-224`, `SHA-512`, `X25519`

### H7 — How deeply can a static analyzer traverse nested call hierarchies to identify cryptographic elements and evaluate PQC compliance?

- Target: `targets/h07_call_depth`
- Command: `['C:\\Users\\saket\\AppData\\Roaming\\npm\\cdxgen.CMD', '--include-crypto', '-o', 'C:\\Users\\saket\\OneDrive\\Desktop\\pqc-compliance-schema\\pqc-cbom-benchmark\\results\\cdxgen\\20261017T180552Z\\h7\\bom.json', 'C:\\Users\\saket\\OneDrive\\Desktop\\pqc-compliance-schema\\pqc-cbom-benchmark\\targets\\h07_call_depth']`
- Exit code: `0`; scan succeeded: `true`; algorithm detection succeeded: `false`
- BOM: `h7\bom.json`
- Log: `h7\cdxgen.log`
- Result: `h7\result.json`
- Detected (normalized): None
- True positives: None
- False positives (normalized): None
- Missed: `ECDH-brainpoolP256r1`, `ECDH-brainpoolP384r1`, `ECDH-brainpoolP512r1`, `ECDH-P-192`, `ECDH-P-224`, `ECDH-P-256`, `ECDH-P-384`, `ECDH-P-521`, `ECDH-secp256k1`, `ML-KEM-768`, `RSA-2048`, `RSA-3072`, `RSA-4096`, `SHA-512`

### H8 — How is the PQC compliance policy defined, configured, and communicated to the scanner, if such a mechanism exists?

- Target: `targets/h08_policy_probe`
- Command: `['C:\\Users\\saket\\AppData\\Roaming\\npm\\cdxgen.CMD', '--include-crypto', '-o', 'C:\\Users\\saket\\OneDrive\\Desktop\\pqc-compliance-schema\\pqc-cbom-benchmark\\results\\cdxgen\\20261017T180552Z\\h8\\bom.json', 'C:\\Users\\saket\\OneDrive\\Desktop\\pqc-compliance-schema\\pqc-cbom-benchmark\\targets\\h08_policy_probe']`
- Exit code: `0`; scan succeeded: `true`; algorithm detection succeeded: `false`
- BOM: `h8\bom.json`
- Log: `h8\cdxgen.log`
- Result: `h8\result.json`
- Detected (normalized): None
- True positives: None
- False positives (normalized): None
- Missed: `AES-128-GCM`, `AES-256-GCM`, `ChaCha20-Poly1305`, `ECDH-P-384`, `ECDSA-P-384-SHA-384`, `Ed25519`, `HKDF-SHA-256`, `HKDF-SHA-384`, `HMAC-SHA-256`, `HMAC-SHA-384`, `ML-DSA-44`, `ML-DSA-87`, `ML-KEM-1024`, `ML-KEM-512`, `ML-KEM-768`, `RSA-2048-PSS-SHA-256`, `RSA-3072-OAEP-SHA-256`, `SHA-1`, `SHA-224`, `SHA-256`, `SHA3-256`, `SHA-384`, `SHA-512`, `SLH-DSA-SHA2-128s`, `X25519`

### H9 — Are confidence scores assigned to detected cryptographic assets and PQC compliance findings?

- Target: `targets/h09_confidence`
- Command: `['C:\\Users\\saket\\AppData\\Roaming\\npm\\cdxgen.CMD', '--include-crypto', '-o', 'C:\\Users\\saket\\OneDrive\\Desktop\\pqc-compliance-schema\\pqc-cbom-benchmark\\results\\cdxgen\\20261017T180552Z\\h9\\bom.json', 'C:\\Users\\saket\\OneDrive\\Desktop\\pqc-compliance-schema\\pqc-cbom-benchmark\\targets\\h09_confidence']`
- Exit code: `0`; scan succeeded: `true`; algorithm detection succeeded: `false`
- BOM: `h9\bom.json`
- Log: `h9\cdxgen.log`
- Result: `h9\result.json`
- Detected (normalized): None
- True positives: None
- False positives (normalized): None
- Missed: `AES-192-GCM`, `AES-256-GCM`, `BLAKE2b-512`, `EC-secp256k1`, `MD5`, `RSA-3072`, `SHA3-256`, `SHA-384`, `SHA-512`, `SM4-128-CBC`

## Scoring and limitations

Names are case-folded and stripped of non-alphanumeric characters before exact set matching. Expected names come from the ground-truth manifest, not from cdxgen output. The manifest includes resolved active, unreachable, and dead-branch ground-truth assets; runtime-conditional items are included because this benchmark scans source rather than executing it. Registry entries and unresolved identities are recorded in the manifest but excluded from primary TP/FP/missed scores.

A clean scan does not prove an application works; this benchmark invokes cdxgen only and does not run the target applications. A zero-detection case can still be a successful scan. Review each case log for cdxgen warnings or unsupported-pattern indications; no unsupported pattern is inferred solely from a missed detection.
