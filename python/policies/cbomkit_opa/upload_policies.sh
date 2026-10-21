#!/usr/bin/env bash
# Upload the benchmark reference policies to the OPA server that CBOMKit uses (CBOMKIT_OPA_API_BASE).
# Then run compliance checks with policyIdentifier = qr_strict | qr_hybrid | cnsa2_like | ir8547_2031.
set -euo pipefail
OPA_URL="${1:-http://localhost:8181}"
cd "$(dirname "$0")"
for module in bench_lib qr_strict qr_hybrid cnsa2_like ir8547_2031; do
  curl -sSf --data-binary "@${module}.rego" -H 'Content-Type: text/plain' -X PUT "${OPA_URL}/v1/policies/bench_${module}" > /dev/null
  echo "uploaded ${module}.rego"
done
