# pqc-compliance-schema
Post-quantum cryptography compliance Schema for static application security testing (SASTs)

##### Generic Crypto Object Types
Aymmetric Algorithms
Asymmetric Algorithms  
Hash functions
Keys
Parameters
Certificates
Modes/Construction

## Compliance States
Not applicable
Unknown
Not quantum safe
Quantum safe

## Verdicts
false negatives
false positives
Duplications


### Hypotheses
#### Hypothesis Question 1
What if macros (i.e., metaprogramming) are used to inject cryptographic elements into source code?
#### Hypothesis Question 2
What if cryptographic elements are abstracted behind function calls, making them less visible to static source-code analyzers?
#### Hypothesis Question 3
What if cryptographic elements are encapsulated within third-party dependencies, making them difficult for static source-code analyzers to identify?
#### Hypothesis Question 4
What if a function contains both quantum-resistant and quantum-vulnerable cryptographic elements? Should it be classified as PQC-compliant or non-compliant?
#### Hypothesis Question 5
What if a wrapper function encapsulates quantum-resistant cryptographic elements but uses a generic name that suggests a quantum-vulnerable cryptographic algorithm?
#### Hypothesis Question 6
What if the selection and use of cryptographic elements are determined by external configuration files (e.g., JSON, YAML, or XML) and environment variables, rather than being explicitly specified in the source code?
#### Hypothesis Question 7
How deeply can a static source-code analyzer traverse nested function call hierarchies to identify cryptographic elements and evaluate PQC compliance?
#### Hypothesis Question 8
How is the PQC compliance policy defined, configured, and communicated to the scanner, if such a mechanism exists?
#### Hypothesis Question 9
Are confidence scores assigned to detected cryptographic assets and PQC compliance findings to indicate the reliability of the results?

#### Solution
The Cryptographic Intermediate Representation (CIR) abstracts away syntactic sugar, macro expansions, and wrapper layers, normalizing cryptographic operations into a unified, language-independent representation for consistent cryptographic asset discovery and PQC compliance evaluation.




