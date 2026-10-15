
#!/usr/bin/env python3
"""Generate a controlled Python cryptographic asset benchmark.

The generator creates source-code fixtures and a ground-truth JSON manifest.
It does not execute the generated fixtures or perform network operations.
"""

import argparse
import json
import textwrap
from pathlib import Path


CASES = [
    {
        "id": "TC001",
        "file": "tc001_sha256.py",
        "category": "hashing",
        "technique": "direct_api",
        "assets": ["SHA-256"],
        "difficulty": "easy",
        "source": r'''
import hashlib

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
'''
    },
    {
        "id": "TC002",
        "file": "tc002_sha1.py",
        "category": "hashing",
        "technique": "direct_api",
        "assets": ["SHA-1"],
        "difficulty": "easy",
        "source": r'''
import hashlib

def digest(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()
'''
    },
    {
        "id": "TC003",
        "file": "tc003_aes_gcm.py",
        "category": "symmetric_encryption",
        "technique": "direct_api",
        "assets": ["AES-GCM", "AES-128"],
        "difficulty": "easy",
        "source": r'''
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(data: bytes):
    key = AESGCM.generate_key(bit_length=128)
    nonce = b"0123456789ab"
    return AESGCM(key).encrypt(nonce, data, None)
'''
    },
    {
        "id": "TC004",
        "file": "tc004_chacha.py",
        "category": "symmetric_encryption",
        "technique": "direct_api",
        "assets": ["ChaCha20-Poly1305"],
        "difficulty": "easy",
        "source": r'''
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def encrypt(data: bytes):
    key = ChaCha20Poly1305.generate_key()
    nonce = b"0123456789ab"
    return ChaCha20Poly1305(key).encrypt(nonce, data, None)
'''
    },
    {
        "id": "TC005",
        "file": "tc005_rsa.py",
        "category": "public_key",
        "technique": "direct_api",
        "assets": ["RSA"],
        "difficulty": "easy",
        "source": r'''
from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
'''
    },
    {
        "id": "TC006",
        "file": "tc006_ecdsa.py",
        "category": "signature",
        "technique": "direct_api",
        "assets": ["ECDSA", "P-256", "SHA-256"],
        "difficulty": "easy",
        "source": r'''
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

key = ec.generate_private_key(ec.SECP256R1())
signature = key.sign(b"message", ec.ECDSA(hashes.SHA256()))
'''
    },
    {
        "id": "TC007",
        "file": "tc007_ed25519.py",
        "category": "signature",
        "technique": "direct_api",
        "assets": ["Ed25519"],
        "difficulty": "easy",
        "source": r'''
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

key = Ed25519PrivateKey.generate()
signature = key.sign(b"message")
'''
    },
    {
        "id": "TC008",
        "file": "tc008_hmac.py",
        "category": "authentication",
        "technique": "direct_api",
        "assets": ["HMAC", "SHA-256"],
        "difficulty": "easy",
        "source": r'''
import hashlib
import hmac

def authenticate(key: bytes, message: bytes):
    return hmac.new(key, message, hashlib.sha256).digest()
'''
    },
    {
        "id": "TC009",
        "file": "tc009_ecdh.py",
        "category": "key_agreement",
        "technique": "direct_api",
        "assets": ["ECDH", "P-256"],
        "difficulty": "easy",
        "source": r'''
from cryptography.hazmat.primitives.asymmetric import ec

private_key = ec.generate_private_key(ec.SECP256R1())
peer_key = ec.generate_private_key(ec.SECP256R1()).public_key()
shared_secret = private_key.exchange(ec.ECDH(), peer_key)
'''
    },
    {
        "id": "TC010",
        "file": "tc010_import_alias.py",
        "category": "aliasing",
        "technique": "import_alias",
        "assets": ["SHA-512"],
        "difficulty": "medium",
        "source": r'''
from hashlib import sha512 as digest

def checksum(data: bytes):
    return digest(data).hexdigest()
'''
    },
    {
        "id": "TC011",
        "file": "tc011_class_alias.py",
        "category": "aliasing",
        "technique": "class_alias",
        "assets": ["AES-GCM"],
        "difficulty": "medium",
        "source": r'''
from cryptography.hazmat.primitives.ciphers.aead import AESGCM as ImportedCipher

Cipher = ImportedCipher

def create_cipher(key: bytes):
    return Cipher(key)
'''
    },
    {
        "id": "TC012",
        "file": "tc012_wrapper.py",
        "category": "wrappers",
        "technique": "helper_function",
        "assets": ["SHA-256"],
        "difficulty": "medium",
        "source": r'''
import hashlib

def digest_bytes(data: bytes):
    return hashlib.sha256(data).digest()

def process_record(record: bytes):
    return digest_bytes(record)
'''
    },
    {
        "id": "TC013",
        "file": "tc013_call_chain.py",
        "category": "call_graph",
        "technique": "nested_wrappers",
        "assets": ["SHA-256"],
        "difficulty": "medium",
        "source": r'''
import hashlib

def layer_three(data):
    return hashlib.sha256(data).digest()

def layer_two(data):
    return layer_three(data)

def layer_one(data):
    return layer_two(data)

def application_entry(data):
    return layer_one(data)
'''
    },
    {
        "id": "TC014",
        "file": "tc014_decorator.py",
        "category": "metaprogramming",
        "technique": "decorator",
        "assets": ["SHA-256"],
        "difficulty": "medium",
        "source": r'''
import functools
import hashlib

def audited(function):
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        hashlib.sha256(repr(args).encode()).digest()
        return function(*args, **kwargs)
    return wrapper

@audited
def process(value):
    return value.strip()
'''
    },
    {
        "id": "TC015",
        "file": "tc015_reflection.py",
        "category": "reflection",
        "technique": "getattr",
        "assets": ["AES-GCM"],
        "difficulty": "hard",
        "source": r'''
import cryptography.hazmat.primitives.ciphers.aead as aead

def create_cipher(key):
    algorithm_name = "AES" + "GCM"
    cipher_type = getattr(aead, algorithm_name)
    return cipher_type(key)
'''
    },
    {
        "id": "TC016",
        "file": "tc016_dynamic_import.py",
        "category": "dynamic_import",
        "technique": "importlib",
        "assets": ["Ed25519"],
        "difficulty": "hard",
        "source": r'''
import importlib

module = importlib.import_module(
    "cryptography.hazmat.primitives.asymmetric.ed25519"
)
key_type = getattr(module, "Ed25519PrivateKey")
private_key = key_type.generate()
'''
    },
    {
        "id": "TC017",
        "file": "tc017_exec.py",
        "category": "dynamic_code",
        "technique": "exec",
        "assets": ["SHA-256"],
        "difficulty": "hard",
        "source": r'''
import hashlib

generated_source = (
    "def generated_digest(data):\n"
    "    return hashlib.sha256(data).hexdigest()\n"
)
exec(generated_source, {"hashlib": hashlib})
'''
    },
    {
        "id": "TC018",
        "file": "tc018_ast_compile.py",
        "category": "metaprogramming",
        "technique": "ast_compile_exec",
        "assets": ["SHA-256"],
        "difficulty": "hard",
        "source": r'''
import ast
import hashlib

tree = ast.parse(
    "def generated_digest(data):\n"
    "    return hashlib.sha256(data).hexdigest()\n"
)
compiled = compile(tree, "<generated>", "exec")
namespace = {"hashlib": hashlib}
exec(compiled, namespace)
'''
    },
    {
        "id": "TC019",
        "file": "tc019_metaclass.py",
        "category": "metaprogramming",
        "technique": "metaclass_generated_method",
        "assets": ["SHA-256"],
        "difficulty": "hard",
        "source": r'''
import hashlib

class CryptoMeta(type):
    def __new__(mcls, name, bases, namespace):
        namespace["fingerprint"] = (
            lambda self, data: hashlib.sha256(data).hexdigest()
        )
        return super().__new__(mcls, name, bases, namespace)

class Record(metaclass=CryptoMeta):
    pass
'''
    },
    {
        "id": "TC020",
        "file": "tc020_monkey_patch.py",
        "category": "runtime_mutation",
        "technique": "monkey_patch",
        "assets": ["SHA-256"],
        "difficulty": "hard",
        "source": r'''
import hashlib

class Record:
    pass

def fingerprint(self, data):
    return hashlib.sha256(data).hexdigest()

Record.fingerprint = fingerprint
'''
    },
    {
        "id": "TC021",
        "file": "tc021_config.py",
        "category": "configuration",
        "technique": "dictionary_configuration",
        "assets": ["AES-GCM"],
        "difficulty": "medium",
        "source": r'''
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

config = {
    "crypto": {
        "algorithm": "AES-GCM",
        "key_bits": 128
    }
}

def create_cipher(key):
    if config["crypto"]["algorithm"] == "AES-GCM":
        return AESGCM(key)
    raise ValueError("Unsupported algorithm")
'''
    },
    {
        "id": "TC022",
        "file": "tc022_environment.py",
        "category": "configuration",
        "technique": "environment_variable",
        "assets": ["AES-GCM"],
        "difficulty": "hard",
        "source": r'''
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def create_cipher(key):
    algorithm = os.getenv("APP_CRYPTO_ALGORITHM", "AES-GCM")
    if algorithm == "AES-GCM":
        return AESGCM(key)
    raise ValueError("Unsupported algorithm")
'''
    },
    {
        "id": "TC023",
        "file": "tc023_tls.py",
        "category": "transport_security",
        "technique": "protocol_configuration",
        "assets": ["TLS", "TLS 1.2", "TLS 1.3"],
        "difficulty": "medium",
        "source": r'''
import ssl

context = ssl.create_default_context()
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.maximum_version = ssl.TLSVersion.TLSv1_3
'''
    },
    {
        "id": "TC024",
        "file": "tc024_x509.py",
        "category": "pki",
        "technique": "certificate_api",
        "assets": ["X.509", "RSA"],
        "difficulty": "medium",
        "source": r'''
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
certificate_builder = x509.CertificateBuilder()
'''
    },
    {
        "id": "TC025",
        "file": "tc025_hardcoded_key.py",
        "category": "key_management",
        "technique": "hard_coded_key",
        "assets": ["AES-GCM", "hard-coded key"],
        "difficulty": "medium",
        "source": r'''
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Intentionally insecure benchmark fixture. Never reuse this key.
KEY = b"0123456789abcdef"

def encrypt(data):
    return AESGCM(KEY).encrypt(
        b"0123456789ab", data, None
    )
'''
    },
    {
        "id": "TC026",
        "file": "tc026_nonce.py",
        "category": "randomness",
        "technique": "nonce_generation",
        "assets": ["AES-GCM", "nonce"],
        "difficulty": "medium",
        "source": r'''
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(key, data):
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, data, None)
    return nonce, ciphertext
'''
    },
    {
        "id": "TC027",
        "file": "tc027_pqc_identifiers.py",
        "category": "pqc_discovery",
        "technique": "algorithm_identifiers",
        "assets": ["ML-KEM", "ML-DSA", "SLH-DSA", "HQC"],
        "difficulty": "medium",
        "source": r'''
# Identifier discovery fixture; strings alone do not prove API use.
KEM_ALGORITHM = "ML-KEM"
SIGNATURE_ALGORITHM = "ML-DSA"
HASH_SIGNATURE_ALGORITHM = "SLH-DSA"
ALTERNATE_KEM = "HQC"

def configured_algorithms():
    return [
        KEM_ALGORITHM,
        SIGNATURE_ALGORITHM,
        HASH_SIGNATURE_ALGORITHM,
        ALTERNATE_KEM,
    ]
'''
    },
    {
        "id": "TC028",
        "file": "tc028_pqc_provider.py",
        "category": "pqc_abstraction",
        "technique": "provider_interface",
        "assets": ["ML-KEM"],
        "difficulty": "hard",
        "source": r'''
# Illustrative interface, not a real provider implementation.
class CryptoProvider:
    def get_kem(self, algorithm_name):
        raise NotImplementedError

def create_kem(provider):
    return provider.get_kem("ML-KEM")
'''
    },
    {
        "id": "TC029",
        "file": "tc029_split_identifier.py",
        "category": "string_analysis",
        "technique": "constant_concatenation",
        "assets": ["AES-GCM"],
        "difficulty": "hard",
        "source": r'''
algorithm = "-".join(("AES", "GCM"))

def selected_algorithm():
    return algorithm
'''
    },
    {
        "id": "TC030",
        "file": "tc030_generic_facade.py",
        "category": "semantic_normalization",
        "technique": "generic_wrapper",
        "assets": ["AES-GCM"],
        "difficulty": "hard",
        "source": r'''
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_payload(primitive, key, nonce, payload):
    return primitive(key).encrypt(nonce, payload, None)

def application_operation(key, nonce, payload):
    return encrypt_payload(AESGCM, key, nonce, payload)
'''
    },
]


def generate(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest = []

    for case in CASES:
        filename = case["file"]
        source = textwrap.dedent(case["source"]).lstrip()
        (output_dir / filename).write_text(source, encoding="utf-8")

        manifest.append({
            "case_id": case["id"],
            "source_path": filename,
            "category": case["category"],
            "technique": case["technique"],
            "expected_assets": case["assets"],
            "difficulty": case["difficulty"],
            "ground_truth_status": "expected_present",
            "execution_required": False,
        })

    manifest_data = {
        "benchmark": "PQC/SAST Cryptographic Asset Discovery",
        "schema_version": "1.0",
        "fixture_count": len(manifest),
        "cases": manifest,
        "notes": [
            "Expected assets are benchmark labels, not proof of compliance.",
            "Algorithm names in strings/comments are weaker evidence than API use.",
            "Classical cryptography is not post-quantum cryptography.",
            "Scanner detection expectations depend on documented tool scope.",
        ],
    }

    (output_dir / "ground_truth.json").write_text(
        json.dumps(manifest_data, indent=2) + "\n",
        encoding="utf-8",
    )

    readme = """# PQC/SAST Benchmark Corpus

Generated Python source fixtures for cryptographic asset discovery.

## Contents

- 30 Python test-case files
- ground_truth.json
- README.md

## Evaluation

1. Scan each fixture independently.
2. Export findings as SARIF, JSON, or native output.
3. Normalize results into a common schema.
4. Compare detected assets with ground_truth.json.
5. Record true positives, false positives, false negatives and recall.
6. Review results manually, especially string-only PQC identifiers.

## Important

ML-KEM, ML-DSA and SLH-DSA are NIST-standardized PQC algorithm families.
HQC is included as a discovery target, not as a claim that every library
supports it. AES, RSA, ECDSA, ECDH and Ed25519 are classical algorithms.

Fixtures involving exec, AST compilation and dynamic imports are intended
for static-analysis testing. The generator does not execute them.
"""
    (output_dir / "README.md").write_text(readme, encoding="utf-8")

    print(f"Generated {len(manifest)} test cases.")
    print(f"Corpus directory: {output_dir.resolve()}")
    print(f"Ground truth: {(output_dir / 'ground_truth.json').resolve()}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate a controlled PQC/SAST benchmark corpus."
    )
    parser.add_argument(
        "--output-dir",
        default="pqc_sast_corpus",
        help="Directory for generated fixtures",
    )
    args = parser.parse_args()
    generate(Path(args.output_dir))


if __name__ == "__main__":
    main()
