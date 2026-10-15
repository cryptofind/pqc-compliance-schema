# PQC static-analyzer micro-benchmark (October 2026)

35 Python cases (bench/cases) and 7 Java/JCA cases (bench/java) used in the paper
"Not Yet Quantum-Ready". raw-results/ holds every tool's unmodified output; scripts/ holds the
runner and the normalisation/scoring code. matrix_all_lines.csv gives, per case and tool, the
algorithm families reported (R=RSA, E=EC/ECDSA, X=X25519/ECDH, Ed=EdDSA, D=finite-field DH,
d=DSA, T=TLS, K=ML-KEM, S=ML-DSA, P=generic "post-quantum", H=hash/symmetric, g=generic crypto
evidence, o=non-crypto finding, -=nothing).

Tool versions: Bandit 1.9.4; Semgrep 1.181.0 with semgrep-rules (develop branch, fetched
2026-10-15); CodeQL CLI 2.27.2 (python/java security-extended suites; java experimental
quantum pack 0.0.37); Wind River Crypto Detector (commit d6156a8, keyword method; API method
crashes on Python 3.12); qproof 0.4.0; cryptohound 0.1.0 (run with a working semgrep on PATH);
pqc-audit 0.4.1; pqready 0.2.2; crypto-scanner 0.1.2; pqc-posture 0.4.0 (CLI broken; run via
pqc_posture.scan_codebase).
