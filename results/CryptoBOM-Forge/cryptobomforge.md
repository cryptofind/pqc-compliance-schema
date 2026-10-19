# CryptoBOM-Forge Benchmark Scoring

## 1. H0–H9 Scoring Summary

The following table presents the initial automated scoring results for the ten benchmark hypotheses.

| Hypothesis | Eligible Targets | Definite Detections | Initial Recall |
|---|---:|---:|---:|
| H0 — Baseline | 67 | 19 | 28.36% |
| H1 — Metaprogramming | 5 | 1 | 20.00% |
| H2 — Abstraction | 9 | 4 | 44.44% |
| H3 — Dependencies | 13 | 3 | 23.08% |
| H4 — Mixed | 21 | 3 | 14.29% |
| H5 — Misleading Names | 18 | 3 | 16.67% |
| H6 — External Configuration | 9 | 3 | 33.33% |
| H7 — Call Depth | 29 | 17 | 58.62% |
| H8 — Policy Probe | 28 | 7 | 25.00% |
| H9 — Confidence | 8 | 6 | 75.00% |

## 2. Result Artifact Inventory

Each hypothesis has three saved artifacts.

| Artifact Type | Files per Hypothesis | Total Files |
|---|---:|---:|
| CodeQL SARIF findings | 1 | 10 |
| CodeQL context SARIF findings | 1 | 10 |
| CryptoBOM-Forge CBOM output | 1 | 10 |
| **Total** | **3** | **30** |

## 3. Limitations

- These are initial automated scoring results, not final benchmark conclusions.
- A location match alone does not prove that a cryptographic algorithm was correctly identified.
- Cases requiring manual review are not counted as definite detections.
- Findings without reliable attribution require further investigation.
- H4–H9 require additional hypothesis-specific analysis before drawing stronger conclusions.

