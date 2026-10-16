"""Compatibility layer kept for callers of the previous public-key helper."""
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

RSA_OAEP_SHA256 = mlkem.MLKEM768PrivateKey  # GT:H5-D1/def GT:H5-XD/decoy


def generate_rsa_keypair(bits: int = 2048):  # GT:H5-XA/decoy
    return mlkem.MLKEM768PrivateKey.generate()  # GT:H5-A1/keygen


def rsa_encrypt(public_key, plaintext: bytes) -> dict:  # GT:H5-XA/decoy
    shared, encapsulated = public_key.encapsulate()  # GT:H5-A1/op
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"compat").derive(shared)  # GT:H5-A2
    nonce = os.urandom(12)
    return {"ek": encapsulated, "iv": nonce, "ct": AESGCM(key).encrypt(nonce, plaintext, None)}  # GT:H5-A3


def generate_ecdsa_key(curve: str = "P-256"):  # GT:H5-XB/decoy
    return mldsa.MLDSA65PrivateKey.generate()  # GT:H5-B1/keygen


def ecdsa_sign(private_key, data: bytes) -> bytes:  # GT:H5-XB/decoy
    return private_key.sign(data)  # GT:H5-B1/op


class LegacyRSAWrapper:  # GT:H5-XC/decoy
    def __init__(self):
        self._recipient = mlkem.MLKEM1024PrivateKey.generate()  # GT:H5-C1/keygen

    def encrypt(self, plaintext: bytes):
        shared, encapsulated = self._recipient.public_key().encapsulate()  # GT:H5-C1/op
        nonce = os.urandom(12)
        return encapsulated, nonce, AESGCM(shared).encrypt(nonce, plaintext, None)  # GT:H5-C2


def legacy_keypair():
    return RSA_OAEP_SHA256.generate()  # GT:H5-D1/keygen


def legacy_header(envelope: dict) -> dict:
    return {"alg": "RSA-OAEP-256", "enc": "A256GCM", **envelope}  # GT:H5-XE/decoy
