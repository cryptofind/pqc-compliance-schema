"""Policy probe: symmetric primitives."""
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

DATA = b"h08 policy probe"


def p01():
    return AESGCM(AESGCM.generate_key(bit_length=128)).encrypt(os.urandom(12), DATA, None)  # GT:H8-P01


def p02():
    return AESGCM(AESGCM.generate_key(bit_length=256)).encrypt(os.urandom(12), DATA, None)  # GT:H8-P02


def p03():
    return ChaCha20Poly1305(ChaCha20Poly1305.generate_key()).encrypt(os.urandom(12), DATA, None)  # GT:H8-P03
