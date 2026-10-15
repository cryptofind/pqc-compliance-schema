"""Deprecated code path kept for reference; never called."""
from cryptography.hazmat.primitives.asymmetric import rsa

ENABLE_LEGACY = False

def _legacy_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

if ENABLE_LEGACY:
    _legacy_key()
