"""Envelope encryption variants (benchmark target H4)."""
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def wrapped_envelope(data: bytes):
    """Unit U4: classical key transport protecting a symmetric data key."""
    recipient = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # GT:H4-U4-C/keygen
    data_key = AESGCM.generate_key(bit_length=256)  # GT:H4-U4-S/keygen
    nonce = os.urandom(12)
    body = AESGCM(data_key).encrypt(nonce, data, None)  # GT:H4-U4-S/op
    scheme = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)  # GT:H4-U4-C/padding
    wrapped = recipient.public_key().encrypt(data_key, scheme)  # GT:H4-U4-C/op
    return wrapped, nonce, body


def negotiated_envelope(data: bytes, peer_supports_pq: bool = True):
    """Unit U5: preferred post-quantum path with a classical fallback for older peers."""
    if peer_supports_pq:
        receiver = mlkem.MLKEM1024PrivateKey.generate()  # GT:H4-U5-Q/keygen
        secret, encapsulated = receiver.public_key().encapsulate()  # GT:H4-U5-Q/op
    else:
        legacy = rsa.generate_private_key(public_exponent=65537, key_size=3072)  # GT:H4-U5-C/keygen
        secret = os.urandom(32)
        scheme = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)  # GT:H4-U5-C/padding
        encapsulated = legacy.public_key().encrypt(secret, scheme)  # GT:H4-U5-C/op
    key = HKDF(algorithm=hashes.SHA384(), length=32, salt=None, info=b"u5").derive(secret)  # GT:H4-U5-K
    nonce = os.urandom(12)
    return encapsulated, nonce, AESGCM(key).encrypt(nonce, data, None)  # GT:H4-U5-S


def pq_envelope(data: bytes):
    """Unit U6: post-quantum key establishment end to end (control)."""
    receiver = mlkem.MLKEM1024PrivateKey.generate()  # GT:H4-U6-Q/keygen
    secret, encapsulated = receiver.public_key().encapsulate()  # GT:H4-U6-Q/op
    key = HKDF(algorithm=hashes.SHA384(), length=32, salt=None, info=b"u6").derive(secret)  # GT:H4-U6-K
    nonce = os.urandom(12)
    return encapsulated, nonce, AESGCM(key).encrypt(nonce, data, None)  # GT:H4-U6-S
