## Repeatable cdxgen benchmark
`tools/run_cdxgen_benchmark.py` runs cdxgen against the nine treatment targets H1-H9
(H0 is the direct-use baseline and is not included in this nine-case run). It uses
`cdxgen --include-crypto -o <output-file> <target>` for each case and writes each
run to a new UTC-timestamped directory under `results/cdxgen/`; existing runs are
never overwritten.

Create the manifest from the ground-truth JSON once, then run the benchmark:

```bash
python results/cdxgen/run_cdxgen_benchmark.py --write-manifest
python results/cdxgen/run_cdxgen_benchmark.py
```

The checked-in `cdxgen_manifest.json` is the case-by-case expected-algorithm source
for scoring. The script refuses to overwrite an existing manifest or run directory.
Expected names come from resolved assets in the ground truth, never from cdxgen
findings. Each run contains a manifest snapshot, cdxgen version,
individual BOMs, logs, result records, `summary.json`, and `report.md`.

Scoring uses exact normalized algorithm-name matching (case-folded and
non-alphanumeric characters removed), and considers only CycloneDX components
whose type is `cryptographic-asset`. Ordinary dependency components do not count.
Resolved active, unreachable, and dead-branch assets are expected; conditional
assets are included because the benchmark scans source. Registry-only assets and
unresolved identities are retained in the manifest as exclusions, not included
in the primary TP/FP/missed score. A successful scan (zero exit and parseable BOM)
is reported separately from detection success. The harness does not run the
applications, and scan logs should be reviewed for tool warnings and limitations.