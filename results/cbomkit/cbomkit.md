# cbomkit vs Ground Truth — PQC CBOM Benchmark
## Summary

CBOMkit identified 52 of the 142 in-scope ground-truth items in h01–h09 (37%). 44 carry their full identity, 8 are partial, 3 more appear only as a wrong algorithm, and 87 are missed.

The largest difference is a CBOMkit indexing defect, not a hypothesis effect. In h02, h03 and h07 CBOMkit scanned one sub-folder only, so 46 items sat in files it never read and the probe was missed.

In the six fully scanned tests CBOMkit found 51 of 91 items (56%). All 22 ML-KEM, ML-DSA and SLH-DSA items were missed or misidentified; without them the rate is 51 of 69 (74%).

Run through the repo's CBOMkit OPA policies, the output matches 111 of 160 unit verdicts in H4, H5 and H8. Every hybrid reads as classical-only because its post-quantum half is invisible. CBOMkit emits no confidence values, no reachability and no configuration-file evidence.

## Scorecard by test

&#91;embedded content: ground\_truth/h01–h09.json vs results/cbomkit · ±1-line matching per ground-truth.md · 142 in-scope items, probes included\]

Each bar counts a test's in-scope items, probe included, by what CBOMkit reported at their lines. The never-scanned segments in h02, h03 and h07 come from the indexing defect described next.

## Why h02, h03 and h07 are nearly empty

CBOMkit scanned only one sub-folder of each of these targets, so their root files, including probe.py, were never analysed. The cause is CBOMkit's indexer, not the targets' code.

CBOMkit treats a folder as a module only if it holds pyproject.toml, setup.cfg or setup.py ([PythonIndexService](https://github.com/cbomkit/cbomkit-lib/blob/8fbc617afa7fcf90838c68e56a9710f76b1c839d/src/main/java/org/pqca/indexing/python/PythonIndexService.java#L51)), and no target has one. Its fallback, “if no modules were found just add all files” ([IndexingService, line 117](https://github.com/cbomkit/cbomkit-lib/blob/8fbc617afa7fcf90838c68e56a9710f76b1c839d/src/main/java/org/pqca/indexing/IndexingService.java#L117)), checks a list shared across the whole folder walk. The first leaf folder holding .py files is registered first, so every parent, including the target root, is skipped.

| Test | .py files | Files scanned | Folder CBOMkit registered | Probe |
| --- | --- | --- | --- | --- |
| h01 | 8 | 8 | target root | found |
| h02 | 12 | 2 | vault/ | missed |
| h03 | 10 | 2 | third\_party/sealkit/ | missed |
| h04 | 5 | 5 | target root | found |
| h05 | 6 | 6 | target root | found |
| h06 | 5 | 5 | target root | found |
| h07 | 16 | 9 | xmod/ | missed |
| h08 | 7 | 7 | target root | found |
| h09 | 4 | 4 | target root | found |

The scanned counts come from re-implementing that logic and running it on each target. They explain all three results: h02's vault/ holds only an import alias, h03's single finding is in sealkit/core.py, and h07's xmod/ gives nothing.

That leaves 46 items in files CBOMkit never read. Four more, H7 track C, sit in the scanned xmod/sinks.py but take their RSA key size from the unscanned track\_c.py.

An empty pyproject.toml at each target root makes the same logic index every file. Re-run h02, h03 and h07 with it before scoring H2, H3 or H7.

## Test-by-test differences

Each table puts every in-scope ground-truth item next to what CBOMkit reported at its lines. Grades follow [ground-truth.md](https://github.com/cryptofind/pqc-compliance-schema/blob/main/pqc-cbom-benchmark/ground_truth/ground-truth.md): L1 is the right family, L2 adds the key size, curve or parameter set, and L3 adds mode, padding or hash. “Full” means every field the ground truth lists; “L2 of L3” means one level short.

### h01 — metaprogramming (H1)

2 of 7 found. Only the probe and the dynamically imported X25519 come out right, and X25519 only as one of four guesses.

| Item | Ground truth | CBOMkit reported | Grade |
| --- | --- | --- | --- |
| H1-PROBE | SHA-512 | SHA-512 | L2, full |
| H1-01 | AES-256-GCM, AST macro | nothing | missed |
| H1-02 | ML-KEM-768, AST macro | nothing | missed |
| H1-03 | HKDF-SHA-384, exec'd template | nothing | missed |
| H1-04 | ECDSA-P-384-SHA-384, metaclass | FFDH at meta.py:18 | wrong |
| H1-05 | X25519, dynamic import | X25519, plus Ed25519, Ed448, X448, at dynload.py:11 | L2, full but ambiguous |
| H1-06 | ChaCha20-Poly1305, base64 payload | nothing | missed |

CBOMkit cannot resolve `impl` in dynload.py, so it reports every class with a `generate()` constructor. Every finding points at an invocation line; none points at a template or declaration.

### h02 — abstraction (H2)

All 9 missed, including the probe. Only vault/\_\_init\_\_.py and vault/\_backend.py were scanned, and \_backend.py holds just the import alias behind H2-02. The H2 indirections are untested, not negative.

### h03 — dependencies (H3)

1 of 13 found, partially. Only third\_party/sealkit/ was scanned, so PyNaCl, PyJWT, itsdangerous, pyotp and Fernet were never tested.

H3-09, AES-256 key wrap, is reported at the vendored line core.py:6 as AES-128 with primitive “other”. The 32-byte key comes from the unscanned escrow.py, and the unwrap call on line 10 is not reported. Even keys.py's `ec.generate_private_key(ec.SECP384R1())`, a pattern CBOMkit finds in h04 and h08, produced nothing.

### h04 — mixed classical and post-quantum (H4)

13 of 21 found. Every ML-KEM and ML-DSA member is missed, and so are the two AES-GCM uses whose key comes from HKDF.

| Item | Ground truth | CBOMkit reported | Grade |
| --- | --- | --- | --- |
| H4-PROBE | SHA-512 | SHA-512 | L2, full |
| H4-U1-C | X25519 | X25519 | L2, full |
| H4-U1-Q | ML-KEM-768 | nothing | missed |
| H4-U1-K | HKDF-SHA-256 | HKDF-SHA-256 | L3, full |
| H4-U2-Q | ML-DSA-65 | nothing | missed |
| H4-U2-C | Ed25519 | Ed25519 | L2, full |
| H4-U3-Q | ML-KEM-768 | nothing | missed |
| H4-U3-A | ECDSA-P-256-SHA-256 | ECDSA-secp256r1-SHA-256 | L3, full |
| H4-U3-K | HKDF-SHA-256 | HKDF-SHA-256 | L3, full |
| H4-U4-C | RSA-2048-OAEP-SHA-256 | RSA-2048, no OAEP | L2 of L3 |
| H4-U4-S | AES-256-GCM | AES-256-GCM | L3, full |
| H4-U5-Q | ML-KEM-1024 | nothing | missed |
| H4-U5-C | RSA-3072-OAEP-SHA-256 | RSA-3072, no OAEP | L2 of L3 |
| H4-U5-K | HKDF-SHA-384 | HKDF-SHA-384 | L3, full |
| H4-U5-S | AES-256-GCM, key from HKDF | nothing | missed |
| H4-U6-Q | ML-KEM-1024 | nothing | missed |
| H4-U6-K | HKDF-SHA-384 | HKDF-SHA-384 | L3, full |
| H4-U6-S | AES-256-GCM, key from HKDF | nothing | missed |
| H4-U7-C | ECDH-P-384 | ECDH on secp384r1, plus an EC-secp384r1 key | L2, full |
| H4-U7-Q | ML-KEM-1024 | nothing | missed |
| H4-U7-K | HKDF-SHA-384 | HKDF-SHA-384 | L3, full |

With the repo's OPA policies, 24 of 28 unit verdicts match. The 4 mismatches are U1, U2 and U7 under QR-HYBRID and U7 under CNSA2-LIKE: without its post-quantum partner, each hybrid reads as classical-only. The all-PQC control U6 matches only because HKDF-SHA-384 is the one member CBOMkit sees.

### h05 — misleading names (H5)

9 of 18 found. Each misleading-name function gives exactly the findings of its neutral twin, so the misleading-minus-neutral difference is 0 for pairs A, B, F and G.

| Item | Ground truth | CBOMkit reported | Grade |
| --- | --- | --- | --- |
| H5-PROBE | SHA-512 | SHA-512 | L2, full |
| H5-A1 | ML-KEM-768 in `generate_rsa_keypair` | nothing | missed |
| H5-A2 | HKDF-SHA-256 | HKDF-SHA-256 | L3, full |
| H5-A3 | AES-256-GCM, key from HKDF | nothing | missed |
| H5-B1 | ML-DSA-65 in `generate_ecdsa_key` | nothing | missed |
| H5-C1 | ML-KEM-1024 in `LegacyRSAWrapper` | nothing | missed |
| H5-C2 | AES-256-GCM, KEM secret as key | nothing | missed |
| H5-D1 | ML-KEM-768 via alias `RSA_OAEP_SHA256` | Ed25519, Ed448, X25519, X448 at rsa\_compat.py:42 | wrong |
| H5-N1 | ML-KEM-768 | nothing | missed |
| H5-N2 | HKDF-SHA-256 | HKDF-SHA-256 | L3, full |
| H5-N3 | AES-256-GCM, key from HKDF | nothing | missed |
| H5-N4 | ML-DSA-65 | nothing | missed |
| H5-F1 | X25519 in `kyber_keypair` | X25519 | L2, full |
| H5-F2 | HKDF-SHA-256 | HKDF-SHA-256 | L3, full |
| H5-G1 | RSA-2048-PSS-SHA-256 in `DilithiumSigner` | RSA-2048, no PSS | L2 of L3 |
| H5-M1 | X25519 | X25519 | L2, full |
| H5-M2 | HKDF-SHA-256 | HKDF-SHA-256 | L3, full |
| H5-M3 | RSA-2048-PSS-SHA-256 | RSA-2048, no PSS | L2 of L3 |

No name produced a false RSA, ECDSA or post-quantum finding, and none of the 7 decoys drew one. The only false findings come from H5-D1's alias: CBOMkit cannot resolve `RSA_OAEP_SHA256.generate()` and reports four classical curves on ML-KEM code.

26 of 40 unit verdicts match. U-B, U-C and U-N4 get no verdict because nothing was found, and U-D turns non-compliant under QR-STRICT and QR-HYBRID instead of compliant.

### h06 — external configuration (H6)

3 of 9 found, and no finding points at a configuration file. CBOMkit reports only .py call sites, and only where it can partly resolve the arguments.

| Item | Ground truth | CBOMkit reported | Grade |
| --- | --- | --- | --- |
| H6-PROBE | SHA-512 | SHA-512 | L2, full |
| H6-01 | AES-256-GCM from config/crypto.json | nothing | missed |
| H6-02 | ECDSA-P-384-SHA-384 from config/signing.yaml | nothing | missed |
| H6-03 | HKDF-SHA-256 from config/kdf.xml | nothing | missed |
| H6-04 | RSA-3072-OAEP-SHA-256 from config/transport.toml | RSA-24 at services.py:32 | L1 of L3, wrong key size |
| H6-05 | HMAC-SHA-384 from config/mac.ini | nothing | missed |
| H6-06 | SHA-224, environment default | nothing | missed |
| H6-07 | ML-KEM-1024 from .env | Ed25519, Ed448, X25519, X448 at services.py:52 | wrong |
| H6-08 | X25519 from the compose file's environment | X25519, plus Ed25519, Ed448, X448, at services.py:61 | L2, full but ambiguous |

Of the 5 registry entries the configuration never selects, only H6-I05 (Ed25519) is reported, at crypto\_factory.py:45, again as one of four guesses. H6-09, known only at run time, gets no finding. The 24-bit RSA size appears nowhere in code or configuration, and it turns a compliant item into “unknown” under IR8547-2031.

### h07 — call depth (H7)

All 29 missed, including the probe, so the deepest depth reached cannot be measured from this run. Tracks A, B, D and E sit in unscanned root files, and track C's sinks lack their key-size source. h09 shows CBOMkit can carry a key size across one call in a file (H9-C3), so a re-run is worthwhile.

### h08 — policy probe (H8)

20 of 28 found. Every symmetric, hash, MAC and classical public-key unit is identified, and every post-quantum item is missed.

| Item | Ground truth | CBOMkit reported | Grade |
| --- | --- | --- | --- |
| H8-PROBE | SHA-512 | SHA-512 | L2, full |
| H8-P01 | AES-128-GCM | AES-128-GCM | L3, full |
| H8-P02 | AES-256-GCM | AES-256-GCM | L3, full |
| H8-P03 | ChaCha20-Poly1305 | ChaCha20-Poly1305, plus Poly1305 typed as a hash | L2, full |
| H8-P04 to P08 | SHA-256, SHA-384, SHA3-256, SHA-1, SHA-224 | each with the right output size | L2, full (5 items) |
| H8-P09 | HMAC-SHA-256 | HMAC-SHA-256 | L3, full |
| H8-P10 | HMAC-SHA-384 | HMAC-SHA-384 | L3, full |
| H8-P11 to P16 | ML-KEM-512, -768, -1024; ML-DSA-44, -87; SLH-DSA-SHA2-128s | nothing | missed (6 items) |
| H8-P17 | RSA-2048-PSS-SHA-256 | RSA-PSS, 2048, with MGF1 and SHA-256 | L3, full |
| H8-P18 | RSA-3072-OAEP-SHA-256 | RSA-3072, no OAEP | L2 of L3 |
| H8-P19 | ECDSA-P-384-SHA-384 | ECDSA-secp384r1-SHA-384 | L3, full |
| H8-P20 | Ed25519 | Ed25519 | L2, full |
| H8-P21 | X25519 | X25519 | L2, full |
| H8-P22-C | X25519 | X25519 | L2, full |
| H8-P22-Q | ML-KEM-768 | nothing | missed |
| H8-P22-K | HKDF-SHA-256 | HKDF-SHA-256 | L3, full |
| H8-P23-C | ECDH-P-384 | EC-secp384r1 key only | L1 of L2 |
| H8-P23-Q | ML-KEM-1024 | nothing | missed |
| H8-P23-K | HKDF-SHA-384 | HKDF-SHA-384 | L3, full |

61 of 92 unit verdicts match. 24 of the 31 mismatches are the six post-quantum units with no finding; P22 and P23 read as classical-only under QR-HYBRID, and P23 also under CNSA2-LIKE.

The last four mismatches come from naming. P03 is “unknown” under three policies because the separate Poly1305 “hash” fits no policy class. P17 is “unknown” under IR8547-2031 because “RSA-PSS” puts PSS between RSA and the key size the policy looks for.

CBOMkit's own default compliance output is not in the results folder, so the H8 default-policy fingerprint cannot be read from these files.

### h09 — confidence (H9)

4 of 8 found. CBOMkit emits no confidence values at all, so the rank correlation with ideal\_confidence cannot be computed.

| Item | Ground truth (ideal confidence) | CBOMkit reported | Grade |
| --- | --- | --- | --- |
| H9-PROBE | SHA-512 | SHA-512 | L2, full |
| H9-C1 | AES-256-GCM, literal (5) | AES-256-GCM | L3, full |
| H9-C2 | AES-192-GCM, module constant (4) | AES-192-GCM | L3, full |
| H9-C3 | RSA-3072, literal one call away (4) | RSA-3072 at the caller, line 28 | L2, full |
| H9-C4a | SHA-384, path-dependent (3) | nothing | missed |
| H9-C4b | SHA3-256, path-dependent (3) | nothing | missed |
| H9-C5 | BLAKE2b-512 via getattr (3) | nothing | missed |
| H9-C9 | MD5 via hashlib (5) | nothing | missed |
| H9-C6 | ECDSA, curve from an unset environment variable (2) | nothing | not scored |
| H9-C7 | EC secp256k1, never called (1) | EC-secp256k1 | L2, reported like live code |
| H9-C8 | SM4-128-CBC, dead branch (1) | SM4-CBC, no key size | L1 of L3, reported like live code |

None of the 5 decoys drew a finding. The unreachable and dead-branch items carry no flag that sets them apart from live code.

## Why the differences happen

Apart from the indexing defect, eight causes account for every miss, partial and wrong identity. Missing post-quantum support is the largest.

| Cause | Items | Effect |
| --- | --- | --- |
| Post-quantum APIs not supported (pyca `mlkem`, `mldsa`; `pqcrypto`) | H1-02; H4 U1-Q, U2-Q, U3-Q, U5-Q, U6-Q, U7-Q; H5-A1, B1, C1, D1, N1, N4; H6-07; H8-P11 to P16, P22-Q, P23-Q | 20 missed, 2 reported as classical curves |
| AES-GCM keyed with an HKDF output or a KEM secret | H4-U5-S, U6-S; H5-A3, C2, N3 | 5 missed |
| Arguments that come from dicts, getattr or configuration | H6-01, 02, 03, 05, 06; H9-C5 | 6 missed |
| Metaprogramming: templates, exec, base64, a metaclass | H1-01, 03, 06; H1-04 | 3 missed, 1 reported as FFDH |
| Padding or key held in a variable, attribute or tuple | H4-U4-C, U5-C, H8-P18 (OAEP); H5-G1, M3 (PSS); H8-P23-C (ECDH) | 6 partial |
| Key size reported without a resolvable value | H6-04 (RSA-24); H3-09 (AES-128) | 2 partial, wrong size |
| Hash chosen by a conditional expression | H9-C4a, C4b | 2 missed |
| `hashlib`, which CBOMkit does not cover | H9-C9 | 1 missed |

When CBOMkit cannot resolve which class `.generate()` is called on, it reports Ed25519, Ed448, X25519 and X448 together, plus SHA-512 and SHAKE256 as their hashes. That happened at five call sites and gave 3 right identities and 17 wrong ones, including the classical findings on ML-KEM code in H5-D1 and H6-07.

The output also lacks several CBOM properties the README considers. CBOMkit fills name, primitive, parameter set, curve, mode, crypto functions, OID and file, line and offset, but never padding, NIST quantum security level, PQC status, migration urgency or confidence.

It adds 38 private-key and secret-key components that have no ground-truth counterpart. Two labels mislead: HKDF's parameterSetIdentifier of 256 is the derived-key length, and Poly1305 is typed as a hash.

## Limits of this comparison

These choices and gaps shape how the numbers above should be read.

- There is no CBOMkit result for h00, so the benchmark's H0-conditioned recall cannot be computed. The probes serve as the scan check instead.
- A finding matches an item when the file matches and the line is within ±1 of a non-anchor location. Decoys count only on their exact line.
- In scope means status “active”, probes and conditional items included. Registry, unresolved, unreachable, dead-branch and decoy items are reported separately.
- H1-03 and H1-06 are scored on their non-anchor lines, as ground-truth.md says, so H1 has 7 items. The repo's score\_benchmark.py, used for CryptoBOM-Forge, drops them and counts 5.
- Verdicts come from running policies/cbomkit\_opa with OPA 1.0.0 on each result. A unit takes the worst verdict of all findings on its members' lines.
- The .env file the ground truth cites for H6-07 is excluded by the repo's .gitignore, so it was never in the scanned commit.
- Targets and ground truth are unchanged between the scanned commit 0cd23c4 and main, so line numbers align.
