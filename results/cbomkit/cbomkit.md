# cbomkit vs Ground Truth - PQC CBOM Benchmark
CBOMkit identified 52 of the 142 in-scope ground-truth items in h0-h09 (37%). 44 carry their full identity, 8 are partial, 3 more appear only as a wrong algorithm, and 87 are missed.

The largest difference is a CBOMkit indexing defect, not a hypothesis effect. In h02, h03 and h07 CBOMkit scanned one sub-folder only, so 46 items sat in files it never read and the probe was missed.

In the six fully scanned tests CBOMkit found 51 of 91 items (56%). All 22 ML-KEM, ML-DSA and SLH-DSA items were missed or misidentified; without them the rate is 51 of 69 (74%).

Run through the repo's CBOMkit OPA policies, the output matches 111 of 160 unit verdicts in H4, H5 and H8. Every hybrid reads as classical-only because its post-quantum half is invisible. CBOMkit emits no confidence values, no reachability and no configuration-file evidence.

| Test | .py files | Files scanned | Probe |
| --- | --- | --- | --- |
| h01 | 8 | 8 |  found |
| h02 | 12 | 2 | missed |
| h03 | 10 | 2 | missed |
| h04 | 5 | 5 | found |
| h05 | 6 | 6 | found |
| h06 | 5 | 5 | found |
| h07 | 16 | 9 | missed |
| h08 | 7 | 7 | found |
| h09 | 4 | 4 |  found |

### h01 - metaprogramming (H1)
2 of 7 found, 28.57%.

| Item | Ground truth | CBOMkit reported | Grade |
| --- | --- | --- | --- |
| H1-PROBE | SHA-512 | SHA-512 | L2, full |
| H1-01 | AES-256-GCM, AST macro | nothing | missed |
| H1-02 | ML-KEM-768, AST macro | nothing | missed |
| H1-03 | HKDF-SHA-384, exec'd template | nothing | missed |
| H1-04 | ECDSA-P-384-SHA-384, metaclass | FFDH at meta.py:18 | wrong |
| H1-05 | X25519, dynamic import | X25519, plus Ed25519, Ed448, X448, at dynload.py:11 | L2, full but ambiguous |
| H1-06 | ChaCha20-Poly1305, base64 payload | nothing | missed |

### h02 - abstraction (H2)

All 9 missed, including the probe, 0%.

### h03 - dependencies (H3)

1 of 13 found, 7.69% .And incomplete results.

### h04 - mixed classical and post-quantum (H4)

13 of 21 found, 61.90%. Every ML-KEM and ML-DSA member is missed, and so are the two AES-GCM uses whose key comes from HKDF.

| Item | Ground truth | CBOMkit reported | Grade |
| --- | --- | --- | --- |
| H4-PROBE | SHA-512 | SHA-512 | full |
| H4-U1-C | X25519 | X25519 | full |
| H4-U1-Q | ML-KEM-768 | nothing | missed |
| H4-U1-K | HKDF-SHA-256 | HKDF-SHA-256 | full |
| H4-U2-Q | ML-DSA-65 | nothing | missed |
| H4-U2-C | Ed25519 | Ed25519 | full |
| H4-U3-Q | ML-KEM-768 | nothing | missed |
| H4-U3-A | ECDSA-P-256-SHA-256 | ECDSA-secp256r1-SHA-256 | full |
| H4-U3-K | HKDF-SHA-256 | HKDF-SHA-256 | full |
| H4-U4-C | RSA-2048-OAEP-SHA-256 | RSA-2048, no OAEP | missed |
| H4-U4-S | AES-256-GCM | AES-256-GCM | full |
| H4-U5-Q | ML-KEM-1024 | nothing | missed |
| H4-U5-C | RSA-3072-OAEP-SHA-256 | RSA-3072, no OAEP | missed |
| H4-U5-K | HKDF-SHA-384 | HKDF-SHA-384 | full |
| H4-U5-S | AES-256-GCM, key from HKDF | nothing | missed |
| H4-U6-Q | ML-KEM-1024 | nothing | missed |
| H4-U6-K | HKDF-SHA-384 | HKDF-SHA-384 | full |
| H4-U6-S | AES-256-GCM, key from HKDF | nothing | missed |
| H4-U7-C | ECDH-P-384 | ECDH on secp384r1, plus an EC-secp384r1 key | full |
| H4-U7-Q | ML-KEM-1024 | nothing | missed |
| H4-U7-K | HKDF-SHA-384 | HKDF-SHA-384 | full |

With the repo's OPA policies, 24 of 28 unit verdicts match, 85.71%.

### h05 - misleading names (H5) 

9 of 18 found, 50%. Each misleading-name function gives exactly the findings of its neutral twin, so the misleading-minus-neutral difference is 0.

| Item | Ground truth | CBOMkit reported | Grade |
| --- | --- | --- | --- |
| H5-PROBE | SHA-512 | SHA-512 | full |
| H5-A1 | ML-KEM-768 in `generate_rsa_keypair` | nothing | missed |
| H5-A2 | HKDF-SHA-256 | HKDF-SHA-256 | full |
| H5-A3 | AES-256-GCM, key from HKDF | nothing | missed |
| H5-B1 | ML-DSA-65 in `generate_ecdsa_key` | nothing | missed |
| H5-C1 | ML-KEM-1024 in `LegacyRSAWrapper` | nothing | missed |
| H5-C2 | AES-256-GCM, KEM secret as key | nothing | missed |
| H5-D1 | ML-KEM-768 via alias `RSA_OAEP_SHA256` | Ed25519, Ed448, X25519, X448 at rsa\_compat.py:42 | wrong |
| H5-N1 | ML-KEM-768 | nothing | missed |
| H5-N2 | HKDF-SHA-256 | HKDF-SHA-256 | full |
| H5-N3 | AES-256-GCM, key from HKDF | nothing | missed |
| H5-N4 | ML-DSA-65 | nothing | missed |
| H5-F1 | X25519 in `kyber_keypair` | X25519 | full |
| H5-F2 | HKDF-SHA-256 | HKDF-SHA-256 | L3, full |
| H5-G1 | RSA-2048-PSS-SHA-256 in `DilithiumSigner` | RSA-2048, no PSS | missed |
| H5-M1 | X25519 | X25519 | full |
| H5-M2 | HKDF-SHA-256 | HKDF-SHA-256 | full |
| H5-M3 | RSA-2048-PSS-SHA-256 | RSA-2048, no PSS | missed |

26 of 40 unit verdicts match, 65%.

### h06 - external configuration (H6)

3 of 9 found, 33.3%. And sourcd code only.

| Item | Ground truth | CBOMkit reported | Grade |
| --- | --- | --- | --- |
| H6-PROBE | SHA-512 | SHA-512 | full |
| H6-01 | AES-256-GCM from config/crypto.json | nothing | missed |
| H6-02 | ECDSA-P-384-SHA-384 from config/signing.yaml | nothing | missed |
| H6-03 | HKDF-SHA-256 from config/kdf.xml | nothing | missed |
| H6-04 | RSA-3072-OAEP-SHA-256 from config/transport.toml | RSA-24 at services.py:32 | wrong key size, missed |
| H6-05 | HMAC-SHA-384 from config/mac.ini | nothing | missed |
| H6-06 | SHA-224, environment default | nothing | missed |
| H6-07 | ML-KEM-1024 from .env | Ed25519, Ed448, X25519, X448 at services.py:52 | wrong |
| H6-08 | X25519 from the compose file's environment | X25519, plus Ed25519, Ed448, X448, at services.py:61 | full but ambiguous |

### h07 - call depth (H7)

All 29 missed, 0%.

### h08 - policy probe (H8)

20 of 28 found, 71.42%. Every symmetric, hash, MAC and classical public-key unit is identified, and every post-quantum item is missed.

| Item | Ground truth | CBOMkit reported | Grade |
| --- | --- | --- | --- |
| H8-PROBE | SHA-512 | SHA-512 | full |
| H8-P01 | AES-128-GCM | AES-128-GCM | full |
| H8-P02 | AES-256-GCM | AES-256-GCM | full |
| H8-P03 | ChaCha20-Poly1305 | ChaCha20-Poly1305, plus Poly1305 typed as a hash | full |
| H8-P04 to P08 | SHA-256, SHA-384, SHA3-256, SHA-1, SHA-224 | each with the right output size | full (5 items) |
| H8-P09 | HMAC-SHA-256 | HMAC-SHA-256 | full |
| H8-P10 | HMAC-SHA-384 | HMAC-SHA-384 | full |
| H8-P11 to P16 | ML-KEM-512, -768, -1024; ML-DSA-44, -87; SLH-DSA-SHA2-128s | nothing | missed (6 items) |
| H8-P17 | RSA-2048-PSS-SHA-256 | RSA-PSS, 2048, with MGF1 and SHA-256 | full |
| H8-P18 | RSA-3072-OAEP-SHA-256 | RSA-3072, no OAEP | missed |
| H8-P19 | ECDSA-P-384-SHA-384 | ECDSA-secp384r1-SHA-384 | full |
| H8-P20 | Ed25519 | Ed25519 | full |
| H8-P21 | X25519 | X25519 | full |
| H8-P22-C | X25519 | X25519 | full |
| H8-P22-Q | ML-KEM-768 | nothing | missed |
| H8-P22-K | HKDF-SHA-256 | HKDF-SHA-256 | full |
| H8-P23-C | ECDH-P-384 | EC-secp384r1 key only | missed |
| H8-P23-Q | ML-KEM-1024 | nothing | missed |
| H8-P23-K | HKDF-SHA-384 | HKDF-SHA-384 | full |

61 of 92 unit verdicts match, 66.30%.

### h09 - confidence (H9)

4 of 8 found, 50%. CBOMkit emits no confidence values at all, so the rank correlation with ideal-confidence cannot be computed. None of the 5 decoys drew a finding. The unreachable and dead-branch items carry no flag that sets them apart from live code.

| Item | Ground truth (ideal confidence) | CBOMkit reported | Grade |
| --- | --- | --- | --- |
| H9-PROBE | SHA-512 | SHA-512 | full |
| H9-C1 | AES-256-GCM, literal (5) | AES-256-GCM | full |
| H9-C2 | AES-192-GCM, module constant (4) | AES-192-GCM | full |
| H9-C3 | RSA-3072, literal one call away (4) | RSA-3072 at the caller, line 28 | full |
| H9-C4a | SHA-384, path-dependent (3) | nothing | missed |
| H9-C4b | SHA3-256, path-dependent (3) | nothing | missed |
| H9-C5 | BLAKE2b-512 via getattr (3) | nothing | missed |
| H9-C9 | MD5 via hashlib (5) | nothing | missed |
| H9-C6 | ECDSA, curve from an unset environment variable (2) | nothing | not scored |
| H9-C7 | EC secp256k1, never called (1) | EC-secp256k1 | reported like live code |
| H9-C8 | SM4-128-CBC, dead branch (1) | SM4-CBC, no key size | reported like live code |

## Why the differences happen
Apart from the indexing defect, eight causes account for every miss, partial and wrong identity. Missing post-quantum support is the largest.