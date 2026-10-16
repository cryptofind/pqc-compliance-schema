"""Blob protection using a high-level recipe."""
from cryptography.fernet import Fernet


def protect_blob(blob: bytes) -> bytes:
    return Fernet(Fernet.generate_key()).encrypt(blob)  # GT:H3-08a GT:H3-08b
