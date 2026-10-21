"""Content fingerprints keyed by purpose."""
from cryptography.hazmat.primitives import hashes

_PURPOSES = {"fingerprint": hashes.SHA3_384}  # GT:H2-06/def


def fingerprint(data: bytes, purpose: str = "fingerprint") -> bytes:
    ctx = hashes.Hash(_PURPOSES[purpose]())  # GT:H2-06/op
    ctx.update(data)
    return ctx.finalize()
