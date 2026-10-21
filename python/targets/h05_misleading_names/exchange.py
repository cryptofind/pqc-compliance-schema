"""Key agreement and signing helpers with neutral names; bodies are identical to pq_ready."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def new_party():
    return x25519.X25519PrivateKey.generate()  # GT:H5-M1/keygen


def agree(peer_public_key):
    ephemeral = x25519.X25519PrivateKey.generate()  # GT:H5-M1/keygen
    shared = ephemeral.exchange(peer_public_key)  # GT:H5-M1/op
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"agree").derive(shared)  # GT:H5-M2
    return ephemeral.public_key(), key


class StampSigner:
    def __init__(self):
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # GT:H5-M3/keygen

    def sign(self, data: bytes) -> bytes:
        scheme = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)  # GT:H5-M3/padding
        return self._key.sign(data, scheme, hashes.SHA256())  # GT:H5-M3/op
