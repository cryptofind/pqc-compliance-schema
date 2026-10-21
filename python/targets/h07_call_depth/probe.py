"""Scan sanity probe (positive control); identical in every target."""
from cryptography.hazmat.primitives import hashes


def probe(data: bytes = b"benchmark-probe") -> bytes:
    ctx = hashes.Hash(hashes.SHA512())  # GT:PROBE
    ctx.update(data)
    return ctx.finalize()
