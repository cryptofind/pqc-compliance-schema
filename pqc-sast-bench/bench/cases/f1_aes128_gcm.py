"""Encrypt records with AES-128-GCM (acceptable to NIST, not to CNSA 2.0)."""
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def seal(record: bytes) -> bytes:
    key = AESGCM.generate_key(bit_length=128)
    return AESGCM(key).encrypt(os.urandom(12), record, None)
