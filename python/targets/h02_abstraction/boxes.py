"""Persistence helper."""
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM as Box  # GT:H2-01/def


def store(payload: bytes) -> bytes:
    key = Box.generate_key(bit_length=128)  # GT:H2-01/keygen
    nonce = os.urandom(12)
    return nonce + Box(key).encrypt(nonce, payload, None)  # GT:H2-01/op
