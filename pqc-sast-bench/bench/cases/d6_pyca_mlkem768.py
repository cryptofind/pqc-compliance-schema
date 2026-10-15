"""ML-KEM-768 through pyca/cryptography's native API (cryptography >= 47)."""
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey

def establish():
    receiver = MLKEM768PrivateKey.generate()
    shared_secret, ciphertext = receiver.public_key().encapsulate()
    assert receiver.decapsulate(ciphertext) == shared_secret
    return ciphertext
