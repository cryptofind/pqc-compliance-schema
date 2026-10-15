"""Sign audit-log entries with Ed25519."""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def sign_entry(entry: bytes) -> bytes:
    return Ed25519PrivateKey.generate().sign(entry)
