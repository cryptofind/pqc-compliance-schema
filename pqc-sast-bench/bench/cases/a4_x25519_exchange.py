"""Session key agreement with X25519 followed by HKDF."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def agree(peer_public_key):
    ours = X25519PrivateKey.generate()
    shared = ours.exchange(peer_public_key)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"session").derive(shared), ours.public_key()
