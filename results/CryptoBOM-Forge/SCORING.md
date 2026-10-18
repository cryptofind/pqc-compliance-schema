\# CryptoBOM-Forge Benchmark Scoring



\## 1. H0–H9 Scoring Summary



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



These are initial automated results, not final benchmark conclusions. Recall counts definite detections only; cases requiring review are excluded. Location matches alone do not prove correct identification. Hypothesis-specific metrics require additional analysis.



\## 2. Scan Artifact Inventory



Each hypothesis has three saved scan artifacts.



| Artifact | Number of Files | Purpose |

|---|---:|---|

| CodeQL SARIF (`hXX-all-crypto.sarif`) | 10 | Records CodeQL cryptographic findings |

| CodeQL Context SARIF (`hXX-all-crypto-context.sarif`) | 10 | Provides additional finding context |

| CBOM JSON (`hXX-cbom.json`) | 10 | Contains the generated cryptographic inventory |

| \*\*Total\*\* | \*\*30\*\* | \*\*Three artifacts for each of H0–H9\*\* |



\## 3. Results Structure



The scan artifacts are organized into separate directories for each hypothesis, from `h00` to `h09`. The scoring script is located at `pqc-cbom-benchmark/tools/score\_benchmark.py`, and the ground-truth files are maintained separately under `pqc-cbom-benchmark/ground\_truth/`.



\## 4. Scoring Limitations



\- Review cases are excluded from definite recall.

\- Unattributed findings require review and are not automatically false positives.

\- H4/H8 policy agreement, H5 paired comparisons, H6 configuration evidence, H7 call-depth analysis, and H9 confidence analysis require additional targeted evaluation.

\- Ground-truth files were not modified during scoring.