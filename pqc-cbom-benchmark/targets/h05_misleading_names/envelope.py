"""Envelope helpers with neutral names; bodies are identical to the compatibility layer."""
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def new_recipient(size: int = 2048):
    return mlkem.MLKEM768PrivateKey.generate()  # GT:H5-N1/keygen


def seal_for(public_key, plaintext: bytes) -> dict:
    shared, encapsulated = public_key.encapsulate()  # GT:H5-N1/op
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"compat").derive(shared)  # GT:H5-N2
    nonce = os.urandom(12)
    return {"ek": encapsulated, "iv": nonce, "ct": AESGCM(key).encrypt(nonce, plaintext, None)}  # GT:H5-N3


def new_signer(profile: str = "default"):
    return mldsa.MLDSA65PrivateKey.generate()  # GT:H5-N4/keygen


def sign_blob(private_key, data: bytes) -> bytes:
    return private_key.sign(data)  # GT:H5-N4/op
