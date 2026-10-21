"""Pluggable signer registry."""
from abc import ABC, abstractmethod

from cryptography.hazmat.primitives.asymmetric import ed25519


class Signer(ABC):
    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        """Return a signature over data."""


class _Primary(Signer):
    _factory = staticmethod(ed25519.Ed25519PrivateKey.generate)  # GT:H2-03/def

    def __init__(self):
        self._key = self._factory()  # GT:H2-03/keygen

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data)  # GT:H2-03/op


_REGISTRY = {"primary": _Primary}


def make_signer(kind: str = "primary") -> Signer:
    return _REGISTRY[kind]()
