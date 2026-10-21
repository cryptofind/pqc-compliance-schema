# Shared helpers for the benchmark reference policies (CBOMKit OPA integration).
# Classification uses component names (plus variant, parameter set and curve), so the same policies also run with
# `opa eval` over CBOMs from other tools: CycloneDX 1.6 ("cryptographic-asset") and IBM CBOM 1.4 ("crypto-asset").
package policies.bench_lib

import rego.v1

is_crypto_component(c) if c.type in {"cryptographic-asset", "crypto-asset"}

is_algorithm(c) if {
	is_crypto_component(c)
	c.cryptoProperties.assetType == "algorithm"
}

text(c, path) := v if {
	v := object.get(c, path, "")
	is_string(v)
} else := ""

descriptor(c) := lower(regex.replace(concat("", [
	text(c, ["name"]),
	text(c, ["cryptoProperties", "algorithmProperties", "variant"]),
	text(c, ["cryptoProperties", "algorithmProperties", "parameterSetIdentifier"]),
	text(c, ["cryptoProperties", "algorithmProperties", "curve"]),
]), "[^A-Za-z0-9]", ""))

pqc_re := `mlkem|kyber|mldsa|dilithium|slhdsa|sphincs|falcon|fndsa|xmss|lms|hqc|frodokem|mceliece|ntru`

classical_re := `rsa|ecdsa|ecdh|eddsa|ed25519|ed448|x25519|x448|curve25519|curve448|ffdh|diffiehellman|secp|sect[0-9]|brainpool|prime256|ecmqv|^dsa|^dh|^p(192|224|256|384|521)`

broken_re := `md5|md4|md2|sha1|rc4|arc4|tripledes|3des|desede|^des|blowfish|cast5|^idea|^seed`

determinate_hash_re := `sha(256|384|512)|sha3(256|384|512)|blake2b|sm3|shake256`

cnsa_pq_re := `mlkem1024|kyber1024|mldsa87|dilithium5|xmss|lms`

# component class
klass(d) := "hybrid" if {
	regex.match(pqc_re, d)
	regex.match(classical_re, d)
} else := "hybrid" if {
	contains(d, "xwing")
} else := "pqc" if {
	regex.match(pqc_re, d)
} else := "classical-pk" if {
	regex.match(classical_re, d)
} else := "broken" if {
	regex.match(broken_re, d)
} else := "short-hash" if {
	regex.match(`sha224|sha3224|sha512224`, d)
} else := "symmetric" if {
	regex.match(`aes|chacha|salsa|sm4|camellia|aria|fernet`, d)
} else := "hash-family" if {
	regex.match(`sha|blake2|sm3|hmac|hkdf|pbkdf|kdf|poly1305|kmac|shake`, d)
} else := "other"

# rules shared by QR-STRICT, QR-HYBRID and IR8547-2031 for non-public-key classes (S2-S6)
qr_common(k, d) := "compliant" if {
	k in {"pqc", "symmetric"}
} else := "non-compliant" if {
	k in {"broken", "short-hash"}
} else := "compliant" if {
	k == "hash-family"
	regex.match(determinate_hash_re, d)
} else := "unknown"

qr_strict_of(k, _) := "non-compliant" if k in {"hybrid", "classical-pk"}

qr_strict_of(k, d) := v if {
	not k in {"hybrid", "classical-pk"}
	v := qr_common(k, d)
}

qr_hybrid_of(k, _) := "compliant" if k == "hybrid"

qr_hybrid_of(k, _) := "non-compliant" if k == "classical-pk"

qr_hybrid_of(k, d) := v if {
	not k in {"hybrid", "classical-pk"}
	v := qr_common(k, d)
}

ir_classical(d) := "non-compliant" if {
	regex.match(`rsa(512|768|1024)([^0-9]|$)|secp192|p192|prime192`, d)
} else := "deprecated" if {
	regex.match(`rsa2048|secp224|p224|dh2048`, d)
} else := "compliant" if {
	regex.match(`rsa(3072|4096|6144|7680|8192|15360)|secp256|secp384|secp521|p256|p384|p521|prime256|brainpoolp(256|320|384|512)|ed25519|ed448|x25519|x448|curve25519|curve448`, d)
} else := "unknown"

ir8547_of(k, _) := "compliant" if k == "hybrid"

ir8547_of(k, d) := v if {
	k == "classical-pk"
	v := ir_classical(d)
}

ir8547_of(k, d) := v if {
	not k in {"hybrid", "classical-pk"}
	v := qr_common(k, d)
}

cnsa_symmetric(d) := "compliant" if {
	contains(d, "aes256")
} else := "unknown" if {
	contains(d, "aes")
	not regex.match(`aes(128|192|256)`, d)
} else := "non-compliant"

cnsa_hash(d) := "compliant" if {
	regex.match(`sha(384|512)`, d)
	not regex.match(`sha3(224|256|384|512)|sha512(224|256)`, d)
} else := "non-compliant" if {
	regex.match(determinate_hash_re, d)
} else := "unknown"

cnsa2_of(k, d) := "compliant" if {
	k in {"hybrid", "pqc"}
	regex.match(cnsa_pq_re, d)
}

cnsa2_of(k, d) := "non-compliant" if {
	k in {"hybrid", "pqc"}
	not regex.match(cnsa_pq_re, d)
}

cnsa2_of(k, _) := "non-compliant" if k in {"classical-pk", "broken", "short-hash"}

cnsa2_of(k, d) := v if {
	k == "symmetric"
	v := cnsa_symmetric(d)
}

cnsa2_of(k, d) := v if {
	k == "hash-family"
	v := cnsa_hash(d)
}

cnsa2_of(k, _) := "unknown" if k == "other"

verdict(policy, c) := v if {
	d := descriptor(c)
	k := klass(d)
	v := policy_of(policy, k, d)
}

policy_of(policy, k, d) := qr_strict_of(k, d) if policy == "qr_strict"

policy_of(policy, k, d) := qr_hybrid_of(k, d) if policy == "qr_hybrid"

policy_of(policy, k, d) := cnsa2_of(k, d) if policy == "cnsa2_like"

policy_of(policy, k, d) := ir8547_of(k, d) if policy == "ir8547_2031"

# CBOMKit understands quantum-safe | quantum-vulnerable | unknown | NA; 'deprecated' maps to quantum-vulnerable
# and stays visible in the rule name.
result(v) := "quantum-safe" if {
	v == "compliant"
} else := "quantum-vulnerable" if {
	v in {"non-compliant", "deprecated"}
} else := "unknown"

findings_for(policy) := {f |
	some c in input.components
	is_algorithm(c)
	v := verdict(policy, c)
	f := {"bom-ref": c["bom-ref"], "result": result(v), "rule": sprintf("%s/%s", [policy, v]), "property": "name", "value": text(c, ["name"])}
} | {f |
	some c in input.components
	is_crypto_component(c)
	not is_algorithm(c)
	f := {"bom-ref": c["bom-ref"], "result": "NA", "rule": sprintf("%s/not-an-algorithm", [policy]), "property": "cryptoProperties.assetType", "value": text(c, ["cryptoProperties", "assetType"])}
}
