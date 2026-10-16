"""Name-to-implementation registry used by configuration-driven services."""
import os

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mlkem, x25519, x448
from cryptography.hazmat.primitives.ciphers import aead
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

AEADS = {
    ("AES", "GCM"): aead.AESGCM,  # GT:H6-01/def
    ("AES", "SIV"): aead.AESSIV,  # GT:H6-I01/registry
    ("CHACHA20", "POLY1305"): aead.ChaCha20Poly1305,  # GT:H6-I02/registry
}
KEMS = {
    "ML-KEM-768": mlkem.MLKEM768PrivateKey,  # GT:H6-I03/registry
    "ML-KEM-1024": mlkem.MLKEM1024PrivateKey,  # GT:H6-07/def
}
KEXS = {
    "X25519": x25519.X25519PrivateKey,  # GT:H6-08/def
    "X448": x448.X448PrivateKey,  # GT:H6-I04/registry
}
SIGNATURE_FAMILIES = {
    "ECDSA": ec,  # GT:H6-02/def
    "ED25519": ed25519,  # GT:H6-I05/registry
}
KDFS = {"HKDF": HKDF}  # GT:H6-03/def
MACS = {"HMAC": hmac.HMAC}  # GT:H6-05/def


def digest(name: str):
    return getattr(hashes, name.upper())()  # GT:H6-02/def GT:H6-03/def GT:H6-04/def GT:H6-05/def GT:H6-06/def


def make_aead(family: str, mode: str, key_bits: int):
    impl = AEADS[(family.upper(), mode.upper())]
    return impl(os.urandom(int(key_bits) // 8))  # GT:H6-01/keygen GT:H6-09/keygen


def make_signer(scheme: str, curve: str, digest_name: str):
    family = SIGNATURE_FAMILIES[scheme.upper()]
    if family is ec:
        key = ec.generate_private_key(getattr(ec, curve.upper())())  # GT:H6-02/keygen
        algorithm = ec.ECDSA(digest(digest_name))  # GT:H6-02/def
        return lambda data: key.sign(data, algorithm)  # GT:H6-02/op
    key = family.Ed25519PrivateKey.generate()  # GT:H6-I05/registry
    return key.sign
