# qr_hybrid reference policy for CBOMKit's OPA compliance service (definition: policies/reference_policies.yaml).
# CBOMKit queries /v1/data/policies/qr_hybrid and reads the "findings" set.
package policies.qr_hybrid

import rego.v1

import data.policies.bench_lib

findings := bench_lib.findings_for("qr_hybrid")
