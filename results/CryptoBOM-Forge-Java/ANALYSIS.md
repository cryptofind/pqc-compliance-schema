# CryptoBOM-Forge Java Benchmark Results

## 1. Initial Results

The following table summarises the initial observed detection results for the ten Java benchmark hypotheses. These results are preliminary and have not all been validated against the Java ground truth.

| Hypothesis | Eligible Targets | Confirmed Detections | Initial Recall |
|---|---:|---:|---:|
| H00 — Baseline | 3 | 1 | 33.3% |
| H01 — Metaprogramming | 1 | 0 | 0% |
| H02 — Abstraction | 2 | 2 | 100% |
| H03 — Dependencies | N/A | N/A | N/A |
| H04 — Hybrid/PQC | 2 | 0 | Unresolved |
| H05 — Misleading Names | 2 | 2 | 100% |
| H06 — External Configuration | 1 | 1 | 100% |
| H07 — Call Depth | 1 | 1 | 100% |
| H08 — Policy Probes | 3 | 2 | 66.7% |
| H09 — Confidence/Decoys | 2 | 2 | 100% |

These figures represent the initial assessment. The eligible-target counts and confirmed detections require validation against the Java ground truth before the recall percentages can be treated as final.

## 2. Experimental Setup

Ten Java programs, H00–H09, were designed to test different cryptographic inventory challenges:

- H00: Baseline direct cryptographic API usage.
- H01: Reflection and dynamic algorithm construction.
- H02: Factories, wrappers, and abstraction.
- H03: Third-party dependency usage.
- H04: Mixed classical, post-quantum, and hybrid identifiers.
- H05: Misleading names and label-only decoys.
- H06: External configuration and dynamic algorithm selection.
- H07: Increasing call depth.
- H08: Policy-discriminating algorithms and compositions.
- H09: Evidence strength, indirect values, conditional paths, and decoys.

The Java source code was analysed using a custom CodeQL query, and the resulting SARIF findings were passed to CryptoBOM-Forge to generate CBOM output. The generated components were then compared with the expected cryptographic assets.

## 3. Further Investigation

After producing the initial table, I investigated the results in greater depth to understand whether the detected components accurately represented the cryptographic operations in the Java source code.

The investigation included:

- Reviewing the Java source code and its ground-truth markers.
- Inspecting CodeQL SARIF findings and their source locations.
- Examining the context snippets supplied to CryptoBOM-Forge.
- Reviewing the parser's algorithm-matching, key-size extraction, and mode-identification logic.
- Inspecting the generated CBOM components for incorrect algorithm names and properties.
- Attempting to correct the SARIF context and investigating the parser's snippet-extraction logic.

The investigation did not establish a reliable improvement from these attempted corrections. The original benchmark results were therefore retained as preliminary observations rather than replaced with unverified corrected results.

## 4. Observed Results and Issues

The experiments showed that CryptoBOM-Forge could generate CBOM components for some of the CodeQL findings, but the output did not always accurately represent the expected cryptographic assets.

For example, the H00 output included components named `AES-256` and `SHA512`, while the expected findings included AES-GCM and RSA-3072. Other outputs included questionable variants such as `AES-2048-GCM` and `AES-512-GCM`, as well as components with UUID-like names.

These results indicate that a reported finding or generated component cannot automatically be treated as a correctly identified cryptographic asset.

H03 could not be evaluated through the Java cipher-finding pipeline because its CodeQL database was not successfully finalised. H04 also remained unresolved because its generated component properties could not be reliably matched to the expected hybrid and post-quantum assets.

## 5. Overall Conclusion

The initial benchmark suggests that CryptoBOM-Forge can generate cryptographic inventories from supported CodeQL findings, but the completeness and correctness of the resulting CBOM depend on the upstream query, the SARIF information provided, and the parser's interpretation of the findings.

The experiments exposed two distinct evaluation concerns: whether a cryptographic asset is detected and whether its algorithm and properties are identified correctly. Both are necessary for a reliable cryptographic inventory.

The initial table should therefore be treated as an assessment of the tested pipeline configuration, not as a definitive measurement of CryptoBOM-Forge's maximum achievable performance.

## 6. Limitations

- **Incomplete detection:** Some expected cryptographic assets were not confirmed in the output of the tested pipeline.
- **Query coverage:** CryptoBOM-Forge relies on upstream CodeQL findings; cryptographic operations not reported by the query cannot be reliably represented by the downstream parser.
- **Dynamic and indirect usage:** Reflection, dynamically constructed algorithm names, external configuration, and layered abstractions presented challenges for the tested pipeline.
- **Incorrect algorithm attribution:** The parser could infer an algorithm from surrounding source context rather than the specific operation associated with a finding.
- **Inaccurate cryptographic properties:** Some generated component names and variants appeared inconsistent with the expected algorithm or key size.
- **SARIF context sensitivity:** The format and location information supplied in SARIF affected the parser's ability to extract and interpret source snippets.
- **Incomplete cases:** H03 was unavailable for evaluation, and H04 remained unresolved.
- **Unvalidated recall figures:** Eligible-target counts and confirmed detections require a systematic comparison against Java ground truth before the recall values can be considered final.
- **No demonstrated parser improvement:** The attempted SARIF and snippet-extraction corrections did not resolve the H00 output, so no reliable improvement was established.
- **Scope of conclusions:** These findings apply to the tested Java targets, query, configuration, and tool version. They do not prove that every CryptoBOM-Forge configuration will have the same limitations.
