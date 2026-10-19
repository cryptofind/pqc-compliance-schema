# pqc-compliance-schema
Post-Quantum Cryptography (PQC) Compliance Schema for Static Application Security Testing (SAST) Tools

## Hypotheses
### Hypothesis Question 1
What if macros (i.e., metaprogramming) are used to inject cryptographic elements into source code?
### Hypothesis Question 2
What if cryptographic elements are abstracted behind function calls, making them less visible to static source-code analyzers?
### Hypothesis Question 3
What if cryptographic elements are encapsulated within third-party dependencies, making them difficult for static source-code analyzers to identify?
### Hypothesis Question 4
What if a function contains both quantum-resistant and quantum-vulnerable cryptographic elements? Should it be classified as PQC-compliant or non-compliant?
### Hypothesis Question 5
What if a wrapper function encapsulates quantum-resistant cryptographic elements but uses a generic name that suggests a quantum-vulnerable cryptographic algorithm?
### Hypothesis Question 6
What if the selection and use of cryptographic elements are determined by external configuration files (e.g., JSON, YAML, or XML) and environment variables, rather than being explicitly specified in the source code?
### Hypothesis Question 7
How deeply can a static source-code analyzer traverse nested function call hierarchies to identify cryptographic elements and evaluate PQC compliance?
### Hypothesis Question 8
How is the PQC compliance policy defined, configured, and communicated to the scanner, if such a mechanism exists?
### Hypothesis Question 9
Are confidence scores assigned to detected cryptographic assets and PQC compliance findings to indicate the reliability of the results?

CBOM Properties Considered:
```text
File artifacts, e.g., openssl.cnf.

Sourcecode Files, e.g., crypto_demo.py.

Sourcode evidence: crypto_demo.py line 4 at char offset 3.

Protocol version, e.g., TLSv.12.

Curve, e.g., Edwards25519.

Primitive, e.g., signature.

Primitive name, e.g., Ed25519.

Dependency, e.g., 6e3d7fa7-2d9a-4d65-a69a-a3e9b465bfcd (UUID of another asset).

Performance in seconds, e.g., 10s to scan.

Migration score, e.g., Migration Readiness: 14.3% (CRITICAL). 

nist Quantum Security Level, e.g., 1.

key size, e.g., 128 bits.

migration urgency, e.g., HIGH.

confidence score, e.g., MEDIUM.

cipher mode, e.g., gcm.

PQC status, e.g., TRANSITIONAL.
```