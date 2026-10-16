# qr_strict reference policy for CBOMKit's OPA compliance service (definition: policies/reference_policies.yaml).
# CBOMKit queries /v1/data/policies/qr_strict and reads the "findings" set.
package policies.qr_strict

import rego.v1

import data.policies.bench_lib

findings := bench_lib.findings_for("qr_strict")
