"""Resolves a key-agreement implementation by name at run time."""
import importlib

_PACKAGE = ("cryptography", "hazmat", "primitives", "asymmetric")
_VARIANT = "x" + "25519"  # GT:H1-05/def


def agree() -> bool:
    module = importlib.import_module(".".join(_PACKAGE + (_VARIANT,)))
    impl = getattr(module, _VARIANT.upper() + "PrivateKey")  # GT:H1-05/def
    mine, theirs = impl.generate(), impl.generate()  # GT:H1-05/keygen
    return mine.exchange(theirs.public_key()) == theirs.exchange(mine.public_key())  # GT:H1-05/op
