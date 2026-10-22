# cdxgen JavaScript PQC benchmark results

- Run: `20261022T002413Z`
- cdxgen version: `CycloneDX Generator 12.8.4
Runtime: Node.js, Version: 24.19.0`
- Successful scans: 9/9
- Cases with algorithm detections: 9/9
- Expected assets: 105
- Cryptographic-asset components: 37
- Aggregate TP / FP / missed: 24 / 13 / 81
- Micro recall / precision: 0.229 / 0.649

| Case | Scan | TP | FP | Missed | Recall | Runtime (s) |
|---|---:|---:|---:|---:|---:|---:|
| H1 | OK | 1 | 1 | 6 | 0.143 | 13.21 |
| H2 | OK | 3 | 1 | 6 | 0.333 | 12.61 |
| H3 | OK | 3 | 2 | 7 | 0.300 | 11.75 |
| H4 | OK | 2 | 2 | 11 | 0.154 | 11.76 |
| H5 | OK | 1 | 2 | 7 | 0.125 | 11.74 |
| H6 | OK | 2 | 1 | 7 | 0.222 | 11.96 |
| H7 | OK | 1 | 1 | 13 | 0.071 | 11.82 |
| H8 | OK | 7 | 1 | 18 | 0.280 | 12.39 |
| H9 | OK | 4 | 2 | 6 | 0.400 | 12.84 |

## H1 — What if macros (metaprogramming) are used to inject cryptographic elements into source code?

- Scan: `succeeded` (exit 0)
- True positives: `SHA-512`
- False positives (normalized): `sha384`
- Registry over-approximation: None
- Missed: `AES-256-GCM`, `ChaCha20-Poly1305`, `ECDSA-P-384-SHA-384`, `HKDF-SHA-384`, `ML-KEM-768`, `X25519`
- BOM: `h1\bom.json`; log: `h1\cdxgen.log`
- Diagnostics: `Unable to identify component evidence for the input SBOM based on the slices from atom. The slices are either empty or lack appropriate tags.`

## H2 — What if cryptographic elements are abstracted behind function calls, making them less visible to static analyzers?

- Scan: `succeeded` (exit 0)
- True positives: `Ed25519`, `SHA3-384`, `SHA-512`
- False positives (normalized): `rsa`
- Registry over-approximation: None
- Missed: `AES-128-GCM`, `AES-256-CBC-PKCS7`, `ChaCha20-Poly1305`, `HKDF-SHA-256`, `HMAC-SHA-256`, `RSA-3072-PSS-SHA-256`
- BOM: `h2\bom.json`; log: `h2\cdxgen.log`
- Diagnostics: `Unable to identify component evidence for the input SBOM based on the slices from atom. The slices are either empty or lack appropriate tags.`

## H3 — What if cryptographic elements are encapsulated within third-party dependencies?

- Scan: `succeeded` (exit 0)
- True positives: `Ed25519`, `SHA-1`, `SHA-512`
- False positives (normalized): `sha256`, `sha384`
- Registry over-approximation: None
- Missed: `AES-128-CBC-PKCS7`, `AES-256-KW`, `ECDSA-P-384-SHA-384`, `HMAC-SHA-1`, `HMAC-SHA-256`, `X25519`, `XSalsa20-Poly1305`
- BOM: `h3\bom.json`; log: `h3\cdxgen.log`
- Diagnostics: `Unable to identify component evidence for the input SBOM based on the slices from atom. The slices are either empty or lack appropriate tags.`

## H4 — What if a function contains both quantum-resistant and quantum-vulnerable elements? Compliant or not?

- Scan: `succeeded` (exit 0)
- True positives: `Ed25519`, `SHA-512`
- False positives (normalized): `sha256`, `sha384`
- Registry over-approximation: None
- Missed: `AES-256-GCM`, `ECDH-P-384`, `ECDSA-P-256-SHA-256`, `HKDF-SHA-256`, `HKDF-SHA-384`, `ML-DSA-65`, `ML-KEM-1024`, `ML-KEM-768`, `RSA-2048-OAEP-SHA-256`, `RSA-3072-OAEP-SHA-256`, `X25519`
- BOM: `h4\bom.json`; log: `h4\cdxgen.log`
- Diagnostics: `Unable to identify component evidence for the input SBOM based on the slices from atom. The slices are either empty or lack appropriate tags.`

## H5 — What if a wrapper encapsulates quantum-resistant cryptography under a name that suggests a quantum-vulnerable algorithm?

- Scan: `succeeded` (exit 0)
- True positives: `SHA-512`
- False positives (normalized): `rsa`, `sha256`
- Registry over-approximation: None
- Missed: `AES-256-GCM`, `HKDF-SHA-256`, `ML-DSA-65`, `ML-KEM-1024`, `ML-KEM-768`, `RSA-2048-PSS-SHA-256`, `X25519`
- BOM: `h5\bom.json`; log: `h5\cdxgen.log`
- Diagnostics: `Unable to identify component evidence for the input SBOM based on the slices from atom. The slices are either empty or lack appropriate tags.`

## H6 — What if algorithm selection is driven by configuration files (JSON/YAML/XML/TOML/INI) and environment variables?

- Scan: `succeeded` (exit 0)
- True positives: `SHA-224`, `SHA-512`
- False positives (normalized): `rsa`
- Registry over-approximation: None
- Missed: `AES-256-GCM`, `ECDSA-P-384-SHA-384`, `HKDF-SHA-256`, `HMAC-SHA-384`, `ML-KEM-1024`, `RSA-3072-OAEP-SHA-256`, `X25519`
- BOM: `h6\bom.json`; log: `h6\cdxgen.log`
- Diagnostics: `Unable to identify component evidence for the input SBOM based on the slices from atom. The slices are either empty or lack appropriate tags.`

## H7 — How deeply can a static analyzer traverse nested call hierarchies to identify cryptographic elements and evaluate PQC compliance?

- Scan: `succeeded` (exit 0)
- True positives: `SHA-512`
- False positives (normalized): `rsa`
- Registry over-approximation: None
- Missed: `ECDH-brainpoolP256r1`, `ECDH-brainpoolP384r1`, `ECDH-brainpoolP512r1`, `ECDH-P-192`, `ECDH-P-224`, `ECDH-P-256`, `ECDH-P-384`, `ECDH-P-521`, `ECDH-secp256k1`, `ML-KEM-768`, `RSA-2048`, `RSA-3072`, `RSA-4096`
- BOM: `h7\bom.json`; log: `h7\cdxgen.log`
- Diagnostics: `Unable to identify component evidence for the input SBOM based on the slices from atom. The slices are either empty or lack appropriate tags.`

## H8 — How is the PQC compliance policy defined, configured, and communicated to the scanner, if such a mechanism exists?

- Scan: `succeeded` (exit 0)
- True positives: `Ed25519`, `SHA-1`, `SHA-224`, `SHA-256`, `SHA3-256`, `SHA-384`, `SHA-512`
- False positives (normalized): `rsa`
- Registry over-approximation: None
- Missed: `AES-128-GCM`, `AES-256-GCM`, `ChaCha20-Poly1305`, `ECDH-P-384`, `ECDSA-P-384-SHA-384`, `HKDF-SHA-256`, `HKDF-SHA-384`, `HMAC-SHA-256`, `HMAC-SHA-384`, `ML-DSA-44`, `ML-DSA-87`, `ML-KEM-1024`, `ML-KEM-512`, `ML-KEM-768`, `RSA-2048-PSS-SHA-256`, `RSA-3072-OAEP-SHA-256`, `SLH-DSA-SHA2-128s`, `X25519`
- BOM: `h8\bom.json`; log: `h8\cdxgen.log`
- Diagnostics: `Unable to identify component evidence for the input SBOM based on the slices from atom. The slices are either empty or lack appropriate tags.`

## H9 — Are confidence scores assigned to detected cryptographic assets and PQC compliance findings?

- Scan: `succeeded` (exit 0)
- True positives: `MD5`, `SHA3-256`, `SHA-384`, `SHA-512`
- False positives (normalized): `rsa`, `sha256`
- Registry over-approximation: None
- Missed: `AES-192-GCM`, `AES-256-GCM`, `BLAKE2b-512`, `EC-secp256k1`, `RSA-3072`, `SM4-128-CBC`
- BOM: `h9\bom.json`; log: `h9\cdxgen.log`
- Diagnostics: `Unable to identify component evidence for the input SBOM based on the slices from atom. The slices are either empty or lack appropriate tags.`

## Interpretation

Only CycloneDX components with `type=cryptographic-asset` count as algorithm detections. Names are case-folded and stripped of non-alphanumeric characters before exact matching. Expected names are derived from the existing Python ground truth, not from cdxgen output. Registry and unresolved identities are excluded from the primary score.

This harness invokes cdxgen only; it does not install dependencies or execute the target applications. A successful scan is distinct from successful cryptographic-asset detection. The JavaScript corpus is a translated equivalent, not a byte-for-byte port or a controlled language-only experiment; source idioms also affect visibility.
