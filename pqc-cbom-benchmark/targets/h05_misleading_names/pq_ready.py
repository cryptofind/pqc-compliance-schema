"""Helpers named after the migration target state."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def kyber_keypair():  # GT:H5-XF/decoy
    return x25519.X25519PrivateKey.generate()  # GT:H5-F1/keygen


def mlkem_encapsulate(peer_public_key):  # GT:H5-XF/decoy
    ephemeral = x25519.X25519PrivateKey.generate()  # GT:H5-F1/keygen
    shared = ephemeral.exchange(peer_public_key)  # GT:H5-F1/op
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"agree").derive(shared)  # GT:H5-F2
    return ephemeral.public_key(), key


class DilithiumSigner:  # GT:H5-XG/decoy
    def __init__(self):
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # GT:H5-G1/keygen

    def sign(self, data: bytes) -> bytes:
        scheme = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)  # GT:H5-G1/padding
        return self._key.sign(data, scheme, hashes.SHA256())  # GT:H5-G1/op
