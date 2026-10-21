"""Document approval workflow."""
from functools import partial

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def approver():
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)  # GT:H2-05/keygen
    scheme = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)  # GT:H2-05/def
    return partial(key.sign, padding=scheme, algorithm=hashes.SHA256())  # GT:H2-05/def


def approve(document: bytes, stamp) -> bytes:
    return stamp(document)  # GT:H2-05/op
