"""Archival using the vault package."""
import os

from vault import Engine


def archive(blob: bytes) -> bytes:
    key = Engine.generate_key()  # GT:H2-02/keygen
    nonce = os.urandom(12)
    return nonce + Engine(key).encrypt(nonce, blob, None)  # GT:H2-02/op
