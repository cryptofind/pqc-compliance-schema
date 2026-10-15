"""Wrap a data key for a partner using their RSA public key loaded from PEM (no key generation)."""
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def wrap_for_partner(pem: bytes, data_key: bytes) -> bytes:
    partner = serialization.load_pem_public_key(pem)
    return partner.encrypt(data_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                   algorithm=hashes.SHA256(), label=None))
