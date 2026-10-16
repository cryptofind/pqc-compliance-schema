"""Metaclass that synthesises behaviour from declarative class attributes."""
import importlib


class Declarative(type):
    def __new__(mcls, name, bases, namespace):
        cls = super().__new__(mcls, name, bases, namespace)
        spec = namespace.get("__scheme__")
        if spec:
            family, group, digest_name = spec
            asym = importlib.import_module("cryptography.hazmat.primitives.asymmetric." + family)
            digests = importlib.import_module("cryptography.hazmat.primitives.hashes")
            group_cls = getattr(asym, group)
            scheme_cls = getattr(asym, family.upper() + "DSA")  # GT:H1-04/def
            digest_cls = getattr(digests, digest_name)

            def __init__(self):
                self._key = asym.generate_private_key(group_cls())  # GT:H1-04/keygen

            def sign(self, payload: bytes) -> bytes:
                return self._key.sign(payload, scheme_cls(digest_cls()))  # GT:H1-04/op

            cls.__init__ = __init__
            cls.sign = sign
        return cls


class LedgerEntrySigner(metaclass=Declarative):
    __scheme__ = ("ec", "SECP384R1", "SHA384")  # GT:H1-04/def
