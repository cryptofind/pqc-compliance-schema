"""Session object with lazily derived traffic keys."""
from functools import cached_property

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class Session:
    def __init__(self, secret: bytes):
        self._secret = secret

    @cached_property
    def traffic_key(self) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"traffic").derive(self._secret)  # GT:H2-08
