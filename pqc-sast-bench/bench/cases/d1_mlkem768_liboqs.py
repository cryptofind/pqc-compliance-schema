"""Key establishment with ML-KEM-768 through liboqs-python."""
import oqs

def establish(peer_encapsulation_key: bytes):
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        ciphertext, shared_secret = kem.encap_secret(peer_encapsulation_key)
    return ciphertext, shared_secret
