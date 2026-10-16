#!/usr/bin/env python3
"""Builds ground_truth/hNN.json and ground_truth/assets.csv.

Two sources are combined: the specification in this file (what each item *is*) and the
`# GT:<id>[/<role>]` markers inside targets/ (where it is).  Configuration files that cannot carry
comments are located by text search.  Verdicts for the four reference policies defined in
policies/reference_policies.yaml are computed by verdict() below.  Re-run after editing a target:

    python tools/build_ground_truth.py
"""
from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import gen_h07 as h7  # noqa: E402

TARGETS, OUT = ROOT / "targets", ROOT / "ground_truth"
MARKER = re.compile(r"GT:([A-Za-z0-9][A-Za-z0-9.\-]*)(?:/([a-z]+))?")
POLICIES = ("QR-STRICT", "QR-HYBRID", "CNSA2-LIKE", "IR8547-2031")
SEVERITY = {"compliant": 0, "unknown": 1, "deprecated": 2, "non-compliant": 3}

# ----------------------------------------------------------------------------- asset vocabulary
CURVES = {"SECP192R1": ("P-192", 96), "SECP224R1": ("P-224", 112), "SECP256R1": ("P-256", 128),
          "SECP384R1": ("P-384", 192), "SECP521R1": ("P-521", 256), "SECP256K1": ("secp256k1", 128),
          "BrainpoolP256R1": ("brainpoolP256r1", 128), "BrainpoolP384R1": ("brainpoolP384r1", 192),
          "BrainpoolP512R1": ("brainpoolP512r1", 256)}
RSA_STRENGTH = {1024: 80, 2048: 112, 3072: 128, 4096: 152}
HASH_BITS = {"MD5": 128, "SHA-1": 160, "SHA-224": 224, "SHA-256": 256, "SHA-384": 384, "SHA-512": 512,
             "SHA3-256": 256, "SHA3-384": 384, "BLAKE2b-512": 512, "SM3": 256}


def _asset(name, family, primitive, **fields):
    return {"name": name, "family": family, "primitive": primitive, **{k: v for k, v in fields.items() if v is not None}}


def _hash_class(h):
    return "classically-broken" if h in ("MD5", "SHA-1") else "short-output" if HASH_BITS[h] < 256 else "quantum-resistant"


def aes(bits, mode, padding=None):
    name = (f"AES-{bits}-{mode}" if bits else f"AES-{mode}") + (f"-{padding}" if padding else "")
    return _asset(name, "AES", "ae" if mode in ("GCM", "SIV", "CCM", "OCB") else "block-cipher", key_bits=bits, mode=mode,
                  padding=padding, quantum="quantum-resistant", nist_qsl={128: 1, 192: 3, 256: 5}.get(bits), classical_bits=bits)


def aes_kw(bits):
    return _asset(f"AES-{bits}-KW", "AES", "block-cipher", key_bits=bits, mode="KW", quantum="quantum-resistant",
                  nist_qsl={128: 1, 192: 3, 256: 5}.get(bits), classical_bits=bits)


def chacha():
    return _asset("ChaCha20-Poly1305", "ChaCha20-Poly1305", "ae", key_bits=256, quantum="quantum-resistant", classical_bits=256)


def xsalsa():
    return _asset("XSalsa20-Poly1305", "XSalsa20-Poly1305", "ae", key_bits=256, quantum="quantum-resistant", classical_bits=256)


def sm4(mode):
    return _asset(f"SM4-128-{mode}", "SM4", "block-cipher", key_bits=128, mode=mode, quantum="quantum-resistant", classical_bits=128)


def digest(h, usage=None):
    family = {"MD5": "MD5", "SHA-1": "SHA-1", "SM3": "SM3"}.get(h) or ("SHA-3" if h.startswith("SHA3") else "BLAKE2" if h.startswith("BLAKE2") else "SHA-2")
    return _asset(h, family, "hash", output_bits=HASH_BITS[h], quantum=_hash_class(h), usage=usage)


def hmac_(h):
    return _asset(f"HMAC-{h}", "HMAC", "mac", hash=h, quantum=_hash_class(h))


def hkdf(h):
    return _asset(f"HKDF-{h}", "HKDF", "kdf", hash=h, quantum=_hash_class(h))


def rsa(bits, scheme=None, h=None):
    name = f"RSA-{bits}" + (f"-{scheme}" if scheme else "") + (f"-{h}" if h else "")
    return _asset(name, "RSA", {"OAEP": "pke", "PSS": "signature"}.get(scheme, "pke"), key_bits=bits, padding=scheme, hash=h,
                  quantum="shor-vulnerable", nist_qsl=0, classical_bits=RSA_STRENGTH.get(bits))


def ecdsa(curve, h):
    cname, bits = CURVES.get(curve, (None, None))
    return _asset(f"ECDSA-{cname or 'unknown-curve'}-{h}", "ECDSA", "signature", curve=cname, hash=h,
                  quantum="shor-vulnerable", nist_qsl=0, classical_bits=bits)


def ecdh(curve):
    cname, bits = CURVES[curve]
    return _asset(f"ECDH-{cname}", "ECDH", "key-agree", curve=cname, quantum="shor-vulnerable", nist_qsl=0, classical_bits=bits)


def ec_key(curve):
    cname, bits = CURVES[curve]
    return _asset(f"EC-{cname}", "EC", "other", curve=cname, quantum="shor-vulnerable", nist_qsl=0, classical_bits=bits)


def ed25519():
    return _asset("Ed25519", "EdDSA", "signature", curve="Ed25519", quantum="shor-vulnerable", nist_qsl=0, classical_bits=128)


def x25519():
    return _asset("X25519", "X25519", "key-agree", curve="Curve25519", quantum="shor-vulnerable", nist_qsl=0, classical_bits=128)


def x448():
    return _asset("X448", "X448", "key-agree", curve="Curve448", quantum="shor-vulnerable", nist_qsl=0, classical_bits=224)


def mlkem(n):
    return _asset(f"ML-KEM-{n}", "ML-KEM", "kem", parameter_set=str(n), quantum="quantum-resistant",
                  nist_qsl={512: 1, 768: 3, 1024: 5}[n], standard="FIPS 203")


def mldsa(n):
    return _asset(f"ML-DSA-{n}", "ML-DSA", "signature", parameter_set=str(n), quantum="quantum-resistant",
                  nist_qsl={44: 2, 65: 3, 87: 5}[n], standard="FIPS 204")


def slhdsa(variant):
    return _asset(f"SLH-DSA-{variant}", "SLH-DSA", "signature", parameter_set=variant, quantum="quantum-resistant",
                  nist_qsl=1, standard="FIPS 205")


def unknown_aead():
    return _asset("unresolved AEAD", "unknown", "ae", quantum="unknown")


# ----------------------------------------------------------------------------- reference policies
CNSA_PQ, CNSA_HASH = {"ML-KEM-1024", "ML-DSA-87"}, {"SHA-384", "SHA-512"}


def verdict(a, policy, partner=None):
    """Verdict for one asset under one reference policy (policies/reference_policies.yaml)."""
    family, q = a["family"], a["quantum"]
    if q == "unknown":
        return "unknown"
    if q == "shor-vulnerable":
        if policy == "QR-STRICT":
            return "non-compliant"
        if policy == "QR-HYBRID":
            return "compliant" if partner else "non-compliant"
        if policy == "CNSA2-LIKE":
            return "compliant" if partner and partner["name"] in CNSA_PQ else "non-compliant"
        bits = a.get("classical_bits")
        return "unknown" if bits is None else "non-compliant" if bits < 112 else "deprecated" if bits < 128 else "compliant"
    if policy == "CNSA2-LIKE":
        if family in ("ML-KEM", "ML-DSA"):
            return "compliant" if a["name"] in CNSA_PQ else "non-compliant"
        if family in ("LMS", "XMSS"):
            return "compliant"
        if family == "AES":
            return {256: "compliant", None: "unknown"}.get(a.get("key_bits"), "non-compliant")
        if a["primitive"] == "hash":
            return "compliant" if a["name"] in CNSA_HASH else "non-compliant"
        if family in ("HMAC", "HKDF"):
            return "compliant" if a.get("hash") in CNSA_HASH else "non-compliant"
        return "non-compliant"
    return "non-compliant" if q in ("classically-broken", "short-output") else "compliant"


def worst(verdicts):
    return max(verdicts, key=SEVERITY.__getitem__)


# ----------------------------------------------------------------------------- specification
SPEC: dict[str, dict] = {}


def target(h, folder, question, notes=""):
    SPEC[h] = {"hypothesis": h, "folder": folder, "question": question, "notes": notes, "items": [], "units": [], "pairs": []}
    item(h, f"{h}-PROBE", digest("SHA-512"), "Positive control: direct SHA-512 digest, identical in every target.",
         marker="PROBE", purpose="positive control (a miss means the scan itself failed)")


def item(h, id_, asset, scenario, *, status="active", runtime="executed", partner=None, library="pyca/cryptography",
         locate=(), marker=None, **extra):
    SPEC[h]["items"].append({"id": id_, "status": status, "runtime": runtime, "scenario": scenario, "asset": asset,
                             "library": library, "partner": partner, "locate": list(locate), "marker": marker or id_, "extra": extra})


def decoy(h, id_, scenario, **extra):
    item(h, id_, None, scenario, status="decoy", runtime="n/a", library=None, **extra)


def unit(h, id_, function, members, rationale):
    SPEC[h]["units"].append({"id": id_, "function": function, "members": members, "rationale": rationale})


def cfg(file, *needles):
    return [{"file": file, "contains": n, "role": "cfg"} for n in needles]


# H0 ------------------------------------------------------------------------------------------------
target("H0", "h00_baseline", "Control: can the tool detect each algorithm/library pair when it is used directly with literal parameters?",
       "Interpret H1-H9 conditionally on H0: a miss in a treatment counts as an effect of the treatment only if the tool "
       "detected the same algorithm from the same library here.  L07/L08 run only with H00_WITH_LIBOQS=1.")
D = "Direct, literal use"
for i, a in [("S01", aes(128, "GCM")), ("S02", aes(192, "GCM")), ("S03", aes(256, "GCM")), ("S04", aes(256, "CBC", "PKCS7")),
             ("S05", chacha()), ("S06", aes_kw(256)), ("S08", sm4("CBC")),
             ("H01", digest("SHA-1")), ("H02", digest("SHA-224")), ("H03", digest("SHA-256")), ("H04", digest("SHA-384")),
             ("H05", digest("SHA3-256")), ("H06", digest("SHA3-384")), ("H07", digest("BLAKE2b-512")),
             ("M01", hmac_("SHA-256")), ("M02", hmac_("SHA-384")), ("M03", hmac_("SHA-1")), ("K01", hkdf("SHA-256")), ("K02", hkdf("SHA-384")),
             ("A01", rsa(2048, "OAEP", "SHA-256")), ("A02", rsa(2048, "PSS", "SHA-256")), ("A03", rsa(3072, "PSS", "SHA-256")),
             ("A04", rsa(3072, "OAEP", "SHA-256")), ("A05", rsa(4096)), ("A06", ecdsa("SECP256R1", "SHA-256")),
             ("A07", ecdsa("SECP384R1", "SHA-384")), ("A08", ecdh("SECP384R1")), ("A09", ecdh("SECP192R1")), ("A10", ecdh("SECP224R1")),
             ("A11", ecdh("SECP256R1")), ("A12", ecdh("SECP521R1")), ("A13", ecdh("SECP256K1")), ("A14", ecdh("BrainpoolP256R1")),
             ("A15", ecdh("BrainpoolP384R1")), ("A16", ecdh("BrainpoolP512R1")), ("A17", ed25519()), ("A18", x25519()),
             ("Q01", mlkem(768)), ("Q02", mlkem(1024)), ("Q03", mldsa(44)), ("Q04", mldsa(65)), ("Q05", mldsa(87))]:
    item("H0", f"H0-{i}", a, D)
item("H0", "H0-S07a", aes(128, "CBC", "PKCS7"), "Fernet recipe: cipher component", recipe="Fernet")
item("H0", "H0-S07b", hmac_("SHA-256"), "Fernet recipe: MAC component", recipe="Fernet")
for i, a in [("T01", digest("SHA-256")), ("T02", digest("MD5", "non-security (usedforsecurity=False)")), ("T03", digest("SHA-1")),
             ("T04", hmac_("SHA-256")), ("T05", hmac_("SHA-1"))]:
    item("H0", f"H0-{i}", a, D, library="Python stdlib (hashlib/hmac)")
for i, a, lib in [("X01", xsalsa(), "PyNaCl"), ("X02a", x25519(), "PyNaCl"), ("X02b", xsalsa(), "PyNaCl"), ("X03", ed25519(), "PyNaCl"),
                  ("X04", hmac_("SHA-256"), "PyJWT (algorithm='HS256')"), ("X05", ecdsa("SECP384R1", "SHA-384"), "PyJWT (algorithm='ES384') + pyca key"),
                  ("X06a", hmac_("SHA-1"), "itsdangerous (explicit digest_method)"), ("X06b", digest("SHA-1", "key derivation"), "itsdangerous"),
                  ("X07", hmac_("SHA-1"), "pyotp (explicit digest)")]:
    item("H0", f"H0-{i}", a, "Third-party library with the algorithm spelled out where the API allows", library=lib)
for i, a, lib, rt in [("L01", mlkem(512), "pqcrypto", "executed"), ("L02", mlkem(768), "pqcrypto", "executed"),
                      ("L03", mldsa(65), "pqcrypto", "executed"), ("L04", slhdsa("SHA2-128s"), "pqcrypto", "executed"),
                      ("L05", mlkem(768), "kyber-py", "executed"), ("L06", mldsa(65), "dilithium-py", "executed"),
                      ("L07", mlkem(768), "liboqs-python", "conditional"), ("L08", mldsa(65), "liboqs-python", "conditional")]:
    item("H0", f"H0-{i}", a, "Alternative post-quantum library (library-coverage probe)", library=lib, runtime=rt)

# H1 ------------------------------------------------------------------------------------------------
target("H1", "h01_metaprogramming", "What if macros (metaprogramming) are used to inject cryptographic elements into source code?",
       "Python has no textual macros; the target uses the closest equivalents.  'def' lines hold the injected identity "
       "(templates, specs, declarations); 'use' lines are where the injected code runs; 'anchor' lines are runtime-only witnesses.")
item("H1", "H1-01", aes(256, "GCM"), "SEAL(...) macro rewritten into an AEAD call by an AST-transforming decorator.",
     technique="AST macro expansion", visibility="string literal (macro template)")
item("H1", "H1-02", mlkem(768), "KEM_KEYPAIR() macro rewritten into key generation by an AST-transforming decorator.",
     technique="AST macro expansion", visibility="string literal (macro template)")
item("H1", "H1-03", hkdf("SHA-384"), "Helper generated from string.Template and exec'd at import time.",
     technique="exec of generated source", visibility="string literals split across template and spec")
item("H1", "H1-04", ecdsa("SECP384R1", "SHA-384"), "Metaclass synthesises __init__/sign from a declarative class attribute.",
     technique="metaclass", visibility="string literals in a class attribute; names resolved with getattr")
item("H1", "H1-05", x25519(), "Implementation located with importlib/getattr from a name assembled from fragments.",
     technique="dynamic import", visibility="fragmented string")
item("H1", "H1-06", chacha(), "Base64-encoded source executed at run time.", technique="encoded payload", visibility="none (encoded)")

# H2 ------------------------------------------------------------------------------------------------
target("H2", "h02_abstraction", "What if cryptographic elements are abstracted behind function calls, making them less visible to static analyzers?")
for i, a, how in [("01", aes(128, "GCM"), "import alias (AESGCM imported as Box)"),
                  ("02", chacha(), "re-export through a local package (vault.Engine)"),
                  ("03", ed25519(), "factory reference stored on a class; registry and polymorphic dispatch"),
                  ("04", hmac_("SHA-256"), "closure in a higher-order pipeline; hash passed in as an argument"),
                  ("05", rsa(3072, "PSS", "SHA-256"), "functools.partial binds padding and hash; signing through an opaque callable"),
                  ("06", digest("SHA3-384"), "dispatch table of classes"),
                  ("07", aes(256, "CBC", "PKCS7"), "context manager/generator; key size fixed by the caller"),
                  ("08", hkdf("SHA-256"), "cached_property: derivation runs on attribute access")]:
    item("H2", f"H2-{i}", a, f"Abstraction: {how}", indirection=how)

# H3 ------------------------------------------------------------------------------------------------
target("H3", "h03_dependencies", "What if cryptographic elements are encapsulated within third-party dependencies?",
       "Visible text at the call site ranges from nothing (library defaults) to a recipe or class name.  H3-09 is vendored "
       "source inside the repository (third_party/), which many scanners exclude by convention.")
for i, a, lib, vis in [("01", xsalsa(), "PyNaCl (libsodium, compiled)", "class name only (SecretBox)"),
                       ("02a", x25519(), "PyNaCl (libsodium, compiled)", "class names only (PrivateKey, Box)"),
                       ("02b", xsalsa(), "PyNaCl (libsodium, compiled)", "class names only (Box)"),
                       ("03", ed25519(), "PyNaCl (libsodium, compiled)", "class name only (SigningKey)"),
                       ("04", hmac_("SHA-256"), "PyJWT", "implicit library default (HS256)"),
                       ("05", ecdsa("SECP384R1", "SHA-384"), "PyJWT + pyca/cryptography key", "JOSE identifier 'ES384'; key generated with pyca"),
                       ("06a", hmac_("SHA-1"), "itsdangerous", "implicit library default"),
                       ("06b", digest("SHA-1", "key derivation"), "itsdangerous", "implicit library default"),
                       ("07", hmac_("SHA-1"), "pyotp", "implicit library default"),
                       ("08a", aes(128, "CBC", "PKCS7"), "pyca/cryptography Fernet recipe", "recipe name only (Fernet)"),
                       ("08b", hmac_("SHA-256"), "pyca/cryptography Fernet recipe", "recipe name only (Fernet)"),
                       ("09", aes_kw(256), "vendored third_party/sealkit (wraps pyca/cryptography)", "vendored source; key size fixed by the application caller")]:
    item("H3", f"H3-{i}", a, f"Dependency: {lib}", library=lib, visibility=vis)

# H4 ------------------------------------------------------------------------------------------------
target("H4", "h04_mixed_classical_pqc", "What if a function contains both quantum-resistant and quantum-vulnerable elements? Compliant or not?",
       "Unit verdicts take the most severe asset verdict.  QR-STRICT and QR-HYBRID differ exactly on correctly combined "
       "hybrids (U1, U2, U7); classical authentication (U3) and fallback paths (U5) stay non-compliant under QR-HYBRID.")
item("H4", "H4-U1-C", x25519(), "U1 classical half of a hybrid key establishment", partner="H4-U1-Q", construction="hybrid KEM (secrets combined in one KDF)")
item("H4", "H4-U1-Q", mlkem(768), "U1 post-quantum half of a hybrid key establishment")
item("H4", "H4-U1-K", hkdf("SHA-256"), "U1 combiner")
item("H4", "H4-U2-Q", mldsa(65), "U2 post-quantum half of a dual signature")
item("H4", "H4-U2-C", ed25519(), "U2 classical half of a dual signature", partner="H4-U2-Q", construction="composite signature (both must verify)")
item("H4", "H4-U3-Q", mlkem(768), "U3 post-quantum key establishment")
item("H4", "H4-U3-A", ecdsa("SECP256R1", "SHA-256"), "U3 classical authentication of the transcript", construction="no post-quantum partner performs authentication")
item("H4", "H4-U3-K", hkdf("SHA-256"), "U3 key derivation")
item("H4", "H4-U4-C", rsa(2048, "OAEP", "SHA-256"), "U4 classical key transport")
item("H4", "H4-U4-S", aes(256, "GCM"), "U4 data encryption")
item("H4", "H4-U5-Q", mlkem(1024), "U5 preferred post-quantum path")
item("H4", "H4-U5-C", rsa(3072, "OAEP", "SHA-256"), "U5 classical fallback path", construction="fallback/downgrade path")
item("H4", "H4-U5-K", hkdf("SHA-384"), "U5 key derivation")
item("H4", "H4-U5-S", aes(256, "GCM"), "U5 data encryption")
item("H4", "H4-U6-Q", mlkem(1024), "U6 post-quantum key establishment")
item("H4", "H4-U6-K", hkdf("SHA-384"), "U6 key derivation")
item("H4", "H4-U6-S", aes(256, "GCM"), "U6 data encryption")
item("H4", "H4-U7-C", ecdh("SECP384R1"), "U7 classical half of a hybrid key establishment", partner="H4-U7-Q", construction="hybrid KEM (secrets combined in one KDF)")
item("H4", "H4-U7-Q", mlkem(1024), "U7 post-quantum half of a hybrid key establishment")
item("H4", "H4-U7-K", hkdf("SHA-384"), "U7 combiner")
unit("H4", "H4-U1", "key_establishment.combined_secret", ["H4-U1-C", "H4-U1-Q", "H4-U1-K"], "Hybrid key establishment; secure if either component holds.")
unit("H4", "H4-U2", "composite.sign_dual / verify_dual", ["H4-U2-Q", "H4-U2-C"], "Composite signature; forging requires breaking both.")
unit("H4", "H4-U3", "key_establishment.authenticated_channel", ["H4-U3-Q", "H4-U3-A", "H4-U3-K"], "Confidentiality is post-quantum, authentication is not.")
unit("H4", "H4-U4", "envelopes.wrapped_envelope", ["H4-U4-C", "H4-U4-S"], "A quantum-resistant cipher whose key is transported with a quantum-vulnerable scheme.")
unit("H4", "H4-U5", "envelopes.negotiated_envelope", ["H4-U5-Q", "H4-U5-C", "H4-U5-K", "H4-U5-S"], "Downgrade path: the classical branch is reachable.")
unit("H4", "H4-U6", "envelopes.pq_envelope", ["H4-U6-Q", "H4-U6-K", "H4-U6-S"], "Control: post-quantum end to end.")
unit("H4", "H4-U7", "key_establishment.combined_secret_high", ["H4-U7-C", "H4-U7-Q", "H4-U7-K"], "Hybrid with CNSA 2.0-grade parameters.")

# H5 ------------------------------------------------------------------------------------------------
target("H5", "h05_misleading_names", "What if a wrapper encapsulates quantum-resistant cryptography under a name that suggests a quantum-vulnerable algorithm?",
       "rsa_compat.py/pq_ready.py and their neutral twins envelope.py/exchange.py have identical bodies, so a difference between "
       "a tool's findings for a pair is attributable to identifiers alone.  Any finding on a decoy line is a false positive.")
M, N, I = "misleading name", "neutral twin", "inverse (name suggests post-quantum)"
for i, a, how in [("A1", mlkem(768), M), ("A2", hkdf("SHA-256"), M), ("A3", aes(256, "GCM"), M), ("B1", mldsa(65), M),
                  ("C1", mlkem(1024), M), ("C2", aes(256, "GCM"), M), ("D1", mlkem(768), M + " (alias RSA_OAEP_SHA256)"),
                  ("N1", mlkem(768), N), ("N2", hkdf("SHA-256"), N), ("N3", aes(256, "GCM"), N), ("N4", mldsa(65), N),
                  ("F1", x25519(), I), ("F2", hkdf("SHA-256"), I), ("G1", rsa(2048, "PSS", "SHA-256"), I),
                  ("M1", x25519(), N), ("M2", hkdf("SHA-256"), N), ("M3", rsa(2048, "PSS", "SHA-256"), N)]:
    item("H5", f"H5-{i}", a, f"Naming condition: {how}", naming=how)
for i, text in [("XA", "rsa_compat / generate_rsa_keypair / rsa_encrypt: no RSA is present"),
                ("XB", "generate_ecdsa_key(curve='P-256') / ecdsa_sign: no ECDSA is present"),
                ("XC", "class LegacyRSAWrapper: no RSA is present"),
                ("XD", "alias RSA_OAEP_SHA256 is bound to the ML-KEM-768 key class"),
                ("XE", "protocol label {'alg': 'RSA-OAEP-256'}: no RSA is present"),
                ("XF", "kyber_keypair / mlkem_encapsulate: the implementation is X25519"),
                ("XG", "class DilithiumSigner: the implementation is RSA-2048-PSS")]:
    decoy("H5", f"H5-{i}", f"Decoy: {text}")
SPEC["H5"]["pairs"] = [
    {"pair": "A", "misleading": ["H5-A1", "H5-A2", "H5-A3"], "neutral": ["H5-N1", "H5-N2", "H5-N3"], "decoy": "H5-XA"},
    {"pair": "B", "misleading": ["H5-B1"], "neutral": ["H5-N4"], "decoy": "H5-XB"},
    {"pair": "F", "misleading": ["H5-F1", "H5-F2"], "neutral": ["H5-M1", "H5-M2"], "decoy": "H5-XF"},
    {"pair": "G", "misleading": ["H5-G1"], "neutral": ["H5-M3"], "decoy": "H5-XG"}]
for uid, fn, members in [("U-A", "rsa_compat.rsa_encrypt", ["H5-A1", "H5-A2", "H5-A3"]), ("U-B", "rsa_compat.ecdsa_sign", ["H5-B1"]),
                         ("U-C", "rsa_compat.LegacyRSAWrapper", ["H5-C1", "H5-C2"]), ("U-D", "rsa_compat.legacy_keypair", ["H5-D1"]),
                         ("U-N1", "envelope.seal_for", ["H5-N1", "H5-N2", "H5-N3"]), ("U-N4", "envelope.sign_blob", ["H5-N4"]),
                         ("U-F", "pq_ready.mlkem_encapsulate", ["H5-F1", "H5-F2"]), ("U-G", "pq_ready.DilithiumSigner", ["H5-G1"]),
                         ("U-M1", "exchange.agree", ["H5-M1", "H5-M2"]), ("U-M3", "exchange.StampSigner", ["H5-M3"])]:
    unit("H5", f"H5-{uid}", fn, members, "Verdict follows the implementation, not the name.")

# H6 ------------------------------------------------------------------------------------------------
target("H6", "h06_external_config", "What if algorithm selection is driven by configuration files (JSON/YAML/XML/TOML/INI) and environment variables?",
       "Run with APP_KEX=X25519 to emulate deploy/docker-compose.yml.  Registry items (status=registry) are capabilities present in "
       "code but not selected by the shipped configuration: score them separately as over-approximation.")
item("H6", "H6-01", aes(256, "GCM"), "AEAD chosen by config/crypto.json", source="config/crypto.json",
     locate=cfg("config/crypto.json", '"family": "AES"', '"key_bits": 256', '"mode": "GCM"'))
item("H6", "H6-02", ecdsa("SECP384R1", "SHA-384"), "Signature scheme chosen by config/signing.yaml", source="config/signing.yaml",
     locate=cfg("config/signing.yaml", "scheme: ECDSA", "curve: SECP384R1", "digest: SHA384"))
item("H6", "H6-03", hkdf("SHA-256"), "KDF chosen by config/kdf.xml", source="config/kdf.xml", locate=cfg("config/kdf.xml", '<kdf name="HKDF"'))
item("H6", "H6-04", rsa(3072, "OAEP", "SHA-256"), "Key-transport parameters from config/transport.toml (family checked in code)",
     source="config/transport.toml", locate=cfg("config/transport.toml", 'scheme = "RSA"', "key_bits = 3072", 'padding = "OAEP"', 'digest = "SHA256"'))
item("H6", "H6-05", hmac_("SHA-384"), "MAC chosen by config/mac.ini", source="config/mac.ini", locate=cfg("config/mac.ini", "algorithm = HMAC", "digest = SHA384"))
item("H6", "H6-06", digest("SHA-224"), "Digest from APP_DIGEST, defaulting to a literal in settings.py", source="environment variable with in-code default")
item("H6", "H6-07", mlkem(1024), "KEM from APP_KEM, supplied by the repository's .env file", source=".env", locate=cfg(".env", "APP_KEM="))
item("H6", "H6-08", x25519(), "Key agreement from APP_KEX, supplied only by deploy/docker-compose.yml", source="deployment manifest",
     runtime="conditional", locate=cfg("deploy/docker-compose.yml", "APP_KEX"))
item("H6", "H6-09", unknown_aead(), "AEAD from APP_SESSION_CIPHER, which no file in the repository defines", status="unresolved",
     runtime="not-executed", source="runtime environment only")
for i, a in [("I01", aes(None, "SIV")), ("I02", chacha()), ("I03", mlkem(768)), ("I04", x448()), ("I05", ed25519())]:
    item("H6", f"H6-{i}", a, "Registry entry not selected by the shipped configuration", status="registry", runtime="not-executed")

# H7 ------------------------------------------------------------------------------------------------
target("H7", "h07_call_depth", "How deeply can a static analyzer traverse nested call hierarchies to identify cryptographic elements and evaluate PQC compliance?",
       "Depth = call boundaries between the entry function (tracks A, E) or the key-size literal (tracks B, C, D) and the API call.  "
       "Tracks B-D need inter-procedural constant propagation to recover the key size; the family (RSA) is visible at every sink.  "
       "Generated by tools/gen_h07.py.")
for d in h7.DEPTHS_A:
    item("H7", f"H7-A-d{d:02d}", ecdh(h7.CURVES_A[d]), f"Track A, depth {d}: key agreement local to the deepest function", track="A", depth=d, requires_propagation=False)
for d in h7.DEPTHS_B:
    item("H7", f"H7-B-d{d:02d}", rsa(h7.SIZES_B[d]), f"Track B, depth {d}: key size passed through {d} call(s) in one module", track="B", depth=d, requires_propagation=d > 0)
for d in h7.DEPTHS_C:
    item("H7", f"H7-C-d{d:02d}", rsa(h7.SIZES_C[d]), f"Track C, depth {d}: key size crosses {d} module boundary(ies)", track="C", depth=d, requires_propagation=True)
for d in h7.DEPTHS_D:
    item("H7", f"H7-D-d{d:02d}", rsa(h7.SIZES_D[d]), f"Track D, depth {d}: key size stored on {d} object(s)", track="D", depth=d, requires_propagation=True)
for d in h7.DEPTHS_E:
    item("H7", f"H7-E-d{d:02d}", mlkem(768), f"Track E, depth {d}: post-quantum key establishment local to the deepest function", track="E", depth=d, requires_propagation=False)

# H8 ------------------------------------------------------------------------------------------------
target("H8", "h08_policy_probe", "How is the PQC compliance policy defined, configured, and communicated to the scanner, if such a mechanism exists?",
       "One unit per function.  The verdict vectors differ for every pair of reference policies, so the default verdicts a tool "
       "emits reveal which reference policy, if any, it implicitly applies.")
for i, a, lib in [("P01", aes(128, "GCM"), None), ("P02", aes(256, "GCM"), None), ("P03", chacha(), None), ("P04", digest("SHA-256"), None),
                  ("P05", digest("SHA-384"), None), ("P06", digest("SHA3-256"), None), ("P07", digest("SHA-1"), None),
                  ("P08", digest("SHA-224"), None), ("P09", hmac_("SHA-256"), None), ("P10", hmac_("SHA-384"), None),
                  ("P11", mlkem(512), "pqcrypto"), ("P12", mlkem(768), None), ("P13", mlkem(1024), None), ("P14", mldsa(44), None),
                  ("P15", mldsa(87), None), ("P16", slhdsa("SHA2-128s"), "pqcrypto"), ("P17", rsa(2048, "PSS", "SHA-256"), None),
                  ("P18", rsa(3072, "OAEP", "SHA-256"), None), ("P19", ecdsa("SECP384R1", "SHA-384"), None), ("P20", ed25519(), None),
                  ("P21", x25519(), None)]:
    item("H8", f"H8-{i}", a, "Policy probe", library=lib or "pyca/cryptography")
    unit("H8", f"H8-{i}", f"{i.lower()}()", [f"H8-{i}"], a["name"])
for p, c, q, k in [("P22", x25519(), mlkem(768), hkdf("SHA-256")), ("P23", ecdh("SECP384R1"), mlkem(1024), hkdf("SHA-384"))]:
    item("H8", f"H8-{p}-C", c, "Policy probe: classical half of a hybrid", partner=f"H8-{p}-Q", construction="hybrid KEM (secrets combined in one KDF)")
    item("H8", f"H8-{p}-Q", q, "Policy probe: post-quantum half of a hybrid")
    item("H8", f"H8-{p}-K", k, "Policy probe: hybrid combiner")
    unit("H8", f"H8-{p}", f"{p.lower()}()", [f"H8-{p}-C", f"H8-{p}-Q", f"H8-{p}-K"], f"Hybrid {c['name']} + {q['name']} ({k['name']})")

# H9 ------------------------------------------------------------------------------------------------
target("H9", "h09_confidence", "Are confidence scores assigned to detected cryptographic assets and PQC compliance findings?",
       "ideal_confidence is an ordinal: 5 = identity certain from literals ... 1 = present but unreachable or dead, 0 = decoy "
       "(no cryptography).  Compare any confidence a tool emits (e.g. CycloneDX evidence.identity[].confidence) with this order.")
for i, a, rank, ev, extra in [
        ("C1", aes(256, "GCM"), 5, "literal parameters at the call", {}),
        ("C2", aes(192, "GCM"), 4, "module-level constant", {}),
        ("C3", rsa(3072), 4, "literal at the only caller, one call away", {}),
        ("C4a", digest("SHA-384"), 3, "one of two path-dependent alternatives (taken only with command-line arguments)", {"runtime": "conditional"}),
        ("C4b", digest("SHA3-256"), 3, "one of two path-dependent alternatives (default path)", {}),
        ("C5", digest("BLAKE2b-512"), 3, "class resolved from a string with getattr", {}),
        ("C6", ecdsa("unknown", "SHA-256"), 2, "curve read from an environment variable with no default", {"status": "unresolved", "runtime": "not-executed"}),
        ("C7", ec_key("SECP256K1"), 1, "function that is never called", {"status": "unreachable", "runtime": "not-executed"}),
        ("C8", sm4("CBC"), 1, "branch guarded by a constant-false flag", {"status": "dead-branch", "runtime": "not-executed"}),
        ("C9", digest("MD5", "non-security (usedforsecurity=False)"), 5, "certain identity, non-security use", {})]:
    item("H9", f"H9-{i}", a, f"Evidence: {ev}", ideal_confidence=rank, evidence=ev, **extra)
for i, text in [("D1", "log message mentioning a key size and algorithm"), ("D2", "local class named like an algorithm, with a sign() method"),
                ("D3", "list of algorithm names used only for display"), ("D4", "function named after a hash that computes a CRC"),
                ("D5", "comment naming algorithms")]:
    decoy("H9", f"H9-{i}", f"Decoy: {text}", ideal_confidence=0)


# ----------------------------------------------------------------------------- build
def scan_markers(folder):
    found = {}
    base = TARGETS / folder
    for path in sorted(base.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        rel = path.relative_to(base).as_posix()
        for no, line in enumerate(path.read_text().splitlines(), 1):
            for m in MARKER.finditer(line):
                found.setdefault(m.group(1), []).append({"file": rel, "line": no, "role": m.group(2) or "use"})
    return found


def locate(folder, spec):
    for no, line in enumerate((TARGETS / folder / spec["file"]).read_text().splitlines(), 1):
        if spec["contains"] in line:
            return {"file": spec["file"], "line": no, "role": spec["role"]}
    raise SystemExit(f"cannot locate {spec}")


def location_text(locs):
    return "; ".join(f"{l['file']}:{l['line']}({l['role']})" for l in locs)


def build() -> int:
    OUT.mkdir(exist_ok=True)
    errors, rows = [], []
    for h, t in SPEC.items():
        markers = scan_markers(t["folder"])
        for unknown in sorted(set(markers) - {i["marker"] for i in t["items"]}):
            errors.append(f"{h}: marker GT:{unknown} has no specification entry")
        by_id = {i["id"]: i for i in t["items"]}
        items = []
        for i in t["items"]:
            locs = sorted(markers.get(i["marker"], []) + [locate(t["folder"], s) for s in i["locate"]], key=lambda l: (l["file"], l["line"]))
            if not locs:
                errors.append(f"{h}: {i['id']} has neither a marker nor a located line")
            rec = {"id": i["id"], "status": i["status"], "runtime": i["runtime"], "scenario": i["scenario"]}
            if i["asset"]:
                partner = by_id[i["partner"]]["asset"] if i["partner"] else None
                rec.update(asset=i["asset"], library=i["library"], verdicts={p: verdict(i["asset"], p, partner) for p in POLICIES})
            if i["partner"]:
                rec["hybrid_partner"] = i["partner"]
            rec.update(i["extra"])
            rec["locations"] = locs
            items.append(rec)
            a = i["asset"] or {}
            rows.append({"hypothesis": h, "target": t["folder"], "id": i["id"], "status": i["status"], "runtime": i["runtime"],
                         "name": a.get("name", ""), "family": a.get("family", ""), "primitive": a.get("primitive", ""),
                         "parameter": a.get("key_bits") or a.get("parameter_set") or a.get("curve") or a.get("output_bits") or "",
                         "mode": a.get("mode", ""), "padding": a.get("padding", ""), "hash": a.get("hash", ""),
                         "quantum": a.get("quantum", ""), "nist_qsl": a.get("nist_qsl", ""), "library": i["library"] or "",
                         **{p: rec.get("verdicts", {}).get(p, "") for p in POLICIES},
                         "locations": location_text(locs), "scenario": i["scenario"]})
        index = {r["id"]: r for r in items}
        units = [{**u, "verdicts": {p: worst([index[m]["verdicts"][p] for m in u["members"]]) for p in POLICIES}} for u in t["units"]]
        doc = {"schema": "pqc-cbom-benchmark/ground-truth/1", "hypothesis": h, "target": f"targets/{t['folder']}",
               "question": t["question"], "notes": t["notes"], "policies": list(POLICIES), "items": items}
        if units:
            doc["units"] = units
        if t["pairs"]:
            doc["pairs"] = t["pairs"]
        (OUT / f"{t['folder'][:3]}.json").write_text(json.dumps(doc, indent=2) + "\n")
    with open(OUT / "assets.csv", "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    for e in errors:
        print("ERROR", e)
    print(f"[ground truth] {len(rows)} items across {len(SPEC)} targets -> {OUT.relative_to(ROOT)}/")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(build())
