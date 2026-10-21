# cnsa2_like reference policy for CBOMKit's OPA compliance service (definition: policies/reference_policies.yaml).
# CBOMKit queries /v1/data/policies/cnsa2_like and reads the "findings" set.
package policies.cnsa2_like

import rego.v1

import data.policies.bench_lib

findings := bench_lib.findings_for("cnsa2_like")
