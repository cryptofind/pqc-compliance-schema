"""Composable byte-processing pipeline."""
import base64
from functools import reduce

from cryptography.hazmat.primitives import hashes, hmac


def tagger(key: bytes, algorithm):
    def _step(blob: bytes) -> bytes:
        mac = hmac.HMAC(key, algorithm)  # GT:H2-04/op
        mac.update(blob)
        return blob + mac.finalize()

    return _step


def run(blob: bytes, steps) -> bytes:
    return reduce(lambda acc, step: step(acc), steps, blob)


def default_steps(key: bytes):
    return [bytes.strip, tagger(key, hashes.SHA256()), base64.b64encode]  # GT:H2-04/def
