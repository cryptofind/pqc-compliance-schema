#!/bin/bash
cd /home/claude; mkdir -p results; export NO_COLOR=1 TERM=dumb COLUMNS=200 PYTHONIOENCODING=utf-8
. venv/bin/activate
semgrep --config tools/semgrep-rules/python --json --metrics=off --disable-version-check -q -o results/semgrep_py.json bench/cases 2>results/semgrep_py.err; echo "semgrep_py rc=$?"
semgrep --config tools/semgrep-rules/java --json --metrics=off --disable-version-check -q -o results/semgrep_java.json bench/java 2>results/semgrep_java.err; echo "semgrep_java rc=$?"
deactivate; . venv-pqc/bin/activate
qproof scan bench --format sarif -o results/qproof.sarif >results/qproof.log 2>&1; echo "qproof rc=$?"
cryptohound bench/cases -o results/cryptohound -f json -q >results/cryptohound.log 2>&1; echo "cryptohound rc=$?"
pqc-audit --json bench/cases >results/pqcaudit.json 2>results/pqcaudit.err; echo "pqc-audit rc=$?"
pqready source bench/cases >results/pqready.txt 2>&1; echo "pqready rc=$?"
crypto-scanner scan bench -o results/cryptoscanner.json >results/cryptoscanner.log 2>&1; echo "crypto-scanner rc=$?"
python - <<'PY' > results/pqcposture_probe.txt 2>&1
import importlib.metadata as m
files=[str(f) for f in m.files('pqc-posture') if str(f).endswith('.py') and 'dist-info' not in str(f)]
print(files[:40])
PY
deactivate
cd tools/crypto-detector; python3 cryptodetector.py --help > /home/claude/results/cd_help.txt 2>&1; echo "cd help rc=$?"
