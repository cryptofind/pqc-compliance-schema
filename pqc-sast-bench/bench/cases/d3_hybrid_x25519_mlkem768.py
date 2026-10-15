"""Hybrid key establishment: X25519 and ML-KEM-768 secrets combined with HKDF (PQ/T hybrid)."""
import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def hybrid_establish(peer_x25519_public, peer_mlkem_key: bytes):
    ecdh_secret = X25519PrivateKey.generate().exchange(peer_x25519_public)
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        ciphertext, kem_secret = kem.encap_secret(peer_mlkem_key)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=b"hybrid-x25519-mlkem768").derive(kem_secret + ecdh_secret)
    return ciphertext, key
