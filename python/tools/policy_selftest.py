#!/usr/bin/env python3
"""Self-test for the policy encodings in policies/.

1. Builds a synthetic CycloneDX 1.6 CBOM whose components carry the ground-truth asset names (plus hybrid
   names and names in the styles CBOMKit, cdxgen and cryptobom-forge emit), evaluates it with OPA against
   policies/cbomkit_opa, and compares every finding with the verdict computed by tools/build_ground_truth.py.
2. Re-implements cryptobom-forge's cryptocheck matching and checks policies/cryptobom_forge/*.yml against the
   same verdicts for every asset cryptobom-forge can name.

    python tools/policy_selftest.py [--opa PATH] [--cryptobom-forge PATH_TO_CHECKOUT]   # checkout enables schema validation
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import build_ground_truth as gt  # noqa: E402

POLICY_IDS = {"QR-STRICT": "qr_strict", "QR-HYBRID": "qr_hybrid", "CNSA2-LIKE": "cnsa2_like", "IR8547-2031": "ir8547_2031"}
LABEL = {"compliant": "quantum-safe", "non-compliant": "quantum-vulnerable", "deprecated": "quantum-vulnerable", "unknown": "unknown"}
V = ("compliant", "non-compliant", "deprecated", "unknown")
C, NC, DEP, UNK = V
# Names in the styles the three tools use, with the verdicts they should receive.
TOOL_STYLE = {
    "AES128-GCM": (C, C, NC, C), "RSA-2048": (NC, NC, NC, DEP), "SHA256": (C, C, NC, C), "HMAC-SHA256": (C, C, NC, C),
    "secp384r1": (NC, NC, NC, C), "rsaEncryption": (NC, NC, NC, UNK), "sha-256": (C, C, NC, C), "ml-kem-768": (C, C, NC, C),
    "aes256-GCM": (C, C, C, C), "ecdsaWithSHA256": (NC, NC, NC, UNK), "md5": (NC, NC, NC, NC), "SECP224R1": (NC, NC, NC, DEP),
    "HKDF": (UNK, UNK, UNK, UNK), "X25519MLKEM768": (NC, C, NC, C), "SecP384r1MLKEM1024": (NC, C, C, C), "X-Wing": (NC, C, NC, C),
}


def ground_truth_assets():
    seen = {}
    for path in sorted((ROOT / "ground_truth").glob("h*.json")):
        for item in json.loads(path.read_text())["items"]:
            if "asset" in item:
                seen.setdefault(item["asset"]["name"], item["asset"])
    return seen


def run_opa(opa: str, components: list) -> dict:
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(doc, fh)
    out = subprocess.run([opa, "eval", "--format", "json", "-d", str(ROOT / "policies" / "cbomkit_opa"), "-i", fh.name, "data.policies"],
                         check=True, capture_output=True, text=True).stdout
    value = json.loads(out)["result"][0]["expressions"][0]["value"]
    return {pid: {f["bom-ref"]: f for f in value[pid]["findings"]} for pid in POLICY_IDS.values()}


def check_opa(opa: str) -> int:
    assets = ground_truth_assets()
    expected, components = {}, []
    for name, a in assets.items():
        expected[name] = tuple(gt.verdict(a, p) for p in POLICY_IDS)  # standalone: a CBOM component carries no pairing
        components.append({"type": "cryptographic-asset", "bom-ref": name, "name": name,
                           "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": a["primitive"]}}})
    for name, verdicts in TOOL_STYLE.items():
        expected[f"style:{name}"] = verdicts
        components.append({"type": "cryptographic-asset", "bom-ref": f"style:{name}", "name": name,
                           "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "other"}}})
    components.append({"type": "crypto-asset", "bom-ref": "cbom14:AES-256-GCM", "name": "AES-256-GCM",
                       "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"variant": "AES-256-GCM", "primitive": "block-cipher"}}})
    expected["cbom14:AES-256-GCM"] = (C, C, C, C)
    components.append({"type": "cryptographic-asset", "bom-ref": "key:1", "name": "secret-key",
                       "cryptoProperties": {"assetType": "related-crypto-material"}})
    findings = run_opa(opa, components)
    failures = 0
    for ref, verdicts in expected.items():
        for (policy, pid), v in zip(POLICY_IDS.items(), verdicts):
            got = findings[pid].get(ref)
            if not got or got["result"] != LABEL[v] or not got["rule"].endswith("/" + v):
                failures += 1
                print(f"  OPA MISMATCH {pid:12s} {ref:32s} expected {v:13s} got {got and got['rule']}")
    if any(findings[pid].get("key:1", {}).get("result") != "NA" for pid in POLICY_IDS.values()):
        failures += 1
        print("  OPA MISMATCH non-algorithm component not reported as NA")
    print(f"[policy selftest] OPA: {len(expected)} components x {len(POLICY_IDS)} policies, {failures} mismatch(es)")
    return failures


# ----------------------------------------------------------------------------- cryptocheck (cryptobom-forge)
def _num(f):
    def check(criteria, value):
        try:
            return f(int(value), int(criteria))
        except (TypeError, ValueError):
            return False
    return check


VALIDATORS = {"r": lambda c, v: bool(re.search(c, v, flags=re.IGNORECASE)), "s": lambda c, v: c.lower() in v.lower(),
              "lt": _num(lambda v, c: v < c), "gt": _num(lambda v, c: v > c), "lteq": _num(lambda v, c: v <= c),
              "gteq": _num(lambda v, c: v >= c), "eq": lambda c, v: v == c, "neq": lambda c, v: v != c}
CURVE_VARIANT = {"P-192": "SECP192R1", "P-224": "SECP224R1", "P-256": "SECP256R1", "P-384": "SECP384R1", "P-521": "SECP521R1",
                 "secp256k1": "SECP256K1", "brainpoolP256r1": "BRAINPOOLP256R1", "brainpoolP384r1": "BRAINPOOLP384R1",
                 "brainpoolP512r1": "BRAINPOOLP512R1"}


def cbf_variants(a):
    """Variants cryptobom-forge would emit for an asset, with the verdict that remains decidable from them."""
    fam, prim = a["family"], a["primitive"]
    hash_variant = {"BLAKE2b-512": "BLAKE2B"}.get
    if fam == "AES":
        return [(f"AES-{a['key_bits']}-{a['mode']}" if a.get("key_bits") else f"AES-{a['mode']}", a)]
    if fam == "ChaCha20-Poly1305":
        return [("CHACHA20POLY1305", a)]
    if fam == "SM4":
        return [("SM4-128-CBC", a)]
    if prim == "hash":
        return [(hash_variant(a["name"]) or a["name"].replace("-", "").upper(), a)]
    if fam == "HMAC":
        h = a["hash"]
        return [(hash_variant(h) or h.replace("-", "").upper(), gt.digest(h))]
    if fam == "HKDF":
        return [("HKDF", None)]
    if fam == "RSA":
        return [(f"RSA-{a['key_bits']}" if a.get("key_bits") else "RSA", a)]
    if fam in ("ECDSA", "ECDH", "EC"):
        out = [("ECDSA", {**a, "classical_bits": None})] if fam == "ECDSA" else []
        if a.get("curve") in CURVE_VARIANT:
            out.append((CURVE_VARIANT[a["curve"]], a))
        return out
    if fam == "EdDSA":
        return [("EDDSA", a)]
    return []


def fired(rules, variant):
    parts = variant.split("-")
    value = {"algo": parts[0], "keylen": int(parts[1]) if len(parts) > 1 and parts[1].isnumeric() else None, "mode": "", "padding": ""}
    return {r["detection"]["type"] for r in rules if all(VALIDATORS[t](crit, value[field]) for field, t, crit in r["patterns"])}


def acceptable(verdict, types):
    if verdict == "non-compliant":
        return "error" in types
    if verdict == "deprecated":
        return "warning" in types and "error" not in types
    if verdict == "compliant":
        return not types & {"error", "warning"}
    return "error" not in types


def check_cryptocheck(cbf_checkout: Path | None) -> int:
    schema = None
    if cbf_checkout:
        import jsonschema
        schema = json.loads((cbf_checkout / "cbom" / "resources" / "cryptocheck_schema.json").read_text())
    failures, checked = 0, 0
    assets = ground_truth_assets()
    for policy, pid in POLICY_IDS.items():
        rules = yaml.safe_load((ROOT / "policies" / "cryptobom_forge" / f"{pid}.yml").read_text())
        if schema:
            jsonschema.validate(rules, schema)
        for r in rules:
            r["patterns"] = [ast.literal_eval(p) for p in r["patterns"]]
        for a in assets.values():
            for variant, basis in cbf_variants(a):
                v = gt.verdict(basis, policy) if basis else "unknown"
                checked += 1
                if not acceptable(v, fired(rules, variant)):
                    failures += 1
                    print(f"  CRYPTOCHECK MISMATCH {pid:12s} {variant:20s} expected {v:13s} fired {sorted(fired(rules, variant))}")
    print(f"[policy selftest] cryptocheck: {checked} (variant, policy) cases{' + schema validation' if schema else ''}, {failures} mismatch(es)")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--opa", default="opa")
    parser.add_argument("--cryptobom-forge", type=Path)
    args = parser.parse_args()
    return 1 if check_opa(args.opa) + check_cryptocheck(args.cryptobom_forge) else 0


if __name__ == "__main__":
    raise SystemExit(main())
