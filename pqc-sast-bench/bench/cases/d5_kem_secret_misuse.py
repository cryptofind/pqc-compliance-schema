"""ML-KEM shared secret used directly as an AES key, and one KEM key pair reused for every session."""
import os
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_KEM = oqs.KeyEncapsulation("ML-KEM-768")
_PUBLIC = _KEM.generate_keypair()          # generated once, reused for all sessions

def open_session(ciphertext: bytes, message: bytes) -> bytes:
    secret = _KEM.decap_secret(ciphertext)
    return AESGCM(secret).encrypt(os.urandom(12), message, None)   # no KDF, no context binding
