"""sealkit core routines."""
from cryptography.hazmat.primitives import keywrap


def wrap_key(kek: bytes, key: bytes) -> bytes:
    return keywrap.aes_key_wrap(kek, key)  # GT:H3-09/vendored


def unwrap_key(kek: bytes, wrapped: bytes) -> bytes:
    return keywrap.aes_key_unwrap(kek, wrapped)  # GT:H3-09/vendored
