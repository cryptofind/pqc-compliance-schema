"""X25519MLKEM768-style hybrid built from pyca/cryptography primitives and combined with HKDF."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def client_share(server_mlkem_pub: MLKEM768PublicKey, server_x25519_pub):
    kem_secret, ciphertext = server_mlkem_pub.encapsulate()
    ecdh_secret = X25519PrivateKey.generate().exchange(server_x25519_pub)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"X25519MLKEM768").derive(kem_secret + ecdh_secret)
    return ciphertext, key
