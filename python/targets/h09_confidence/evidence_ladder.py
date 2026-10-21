"""Findings whose identity is established with decreasing certainty (benchmark target H9)."""
import hashlib
import os
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_BITS = 192  # GT:H9-C2/src
LEGACY_MODE = False  # GT:H9-C8/src


def c1_literal(data: bytes) -> bytes:
    return AESGCM(AESGCM.generate_key(bit_length=256)).encrypt(os.urandom(12), data, None)  # GT:H9-C1


def c2_constant(data: bytes) -> bytes:
    return AESGCM(AESGCM.generate_key(bit_length=KEY_BITS)).encrypt(os.urandom(12), data, None)  # GT:H9-C2


def _issue(bits: int):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)  # GT:H9-C3


def c3_single_caller():
    return _issue(3072)  # GT:H9-C3/src


def c4_path_dependent(data: bytes) -> bytes:
    algorithm = hashes.SHA384() if len(sys.argv) > 1 else hashes.SHA3_256()  # GT:H9-C4a GT:H9-C4b
    ctx = hashes.Hash(algorithm)  # GT:H9-C4a/op GT:H9-C4b/op
    ctx.update(data)
    return ctx.finalize()


def c5_string_resolved(data: bytes) -> bytes:
    ctx = hashes.Hash(getattr(hashes, "BLAKE2b")(64))  # GT:H9-C5
    ctx.update(data)
    return ctx.finalize()


def c6_external(data: bytes):
    name = os.environ.get("H9_CURVE")
    if not name:
        return None
    key = ec.generate_private_key(getattr(ec, name)())  # GT:H9-C6/keygen
    return key.sign(data, ec.ECDSA(hashes.SHA256()))  # GT:H9-C6/op


def _retired_rotation():
    return ec.generate_private_key(ec.SECP256K1())  # GT:H9-C7


def c8_dead_branch(data: bytes):
    if LEGACY_MODE:
        enc = Cipher(algorithms.SM4(os.urandom(16)), modes.CBC(os.urandom(16))).encryptor()  # GT:H9-C8
        return enc.update(data.ljust(16, b"\0")) + enc.finalize()
    return data


def c9_non_security(data: bytes) -> str:
    return hashlib.md5(data, usedforsecurity=False).hexdigest()  # GT:H9-C9
