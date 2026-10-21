"""Backend selection for the vault package."""
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 as Engine  # GT:H2-02/def

__all__ = ["Engine"]
