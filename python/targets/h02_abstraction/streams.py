"""Streaming writer that transparently protects data at rest."""
import os
from contextlib import contextmanager

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


@contextmanager
def protected_writer(sink: list, key: bytes):
    iv = os.urandom(16)
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()  # GT:H2-07/op
    pad = padding.PKCS7(128).padder()  # GT:H2-07/padding
    chunks = []
    yield chunks.append
    data = pad.update(b"".join(chunks)) + pad.finalize()
    sink.append(iv + enc.update(data) + enc.finalize())


def archive_lines(lines) -> list:
    sink = []
    key = os.urandom(32)  # GT:H2-07/src
    with protected_writer(sink, key) as write:
        for line in lines:
            write(line)
    return sink
