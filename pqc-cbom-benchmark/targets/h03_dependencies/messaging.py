"""Messaging helpers built on a high-level library."""
from nacl.public import Box, PrivateKey
from nacl.secret import SecretBox
from nacl.signing import SigningKey
from nacl.utils import random


def seal_local(message: bytes) -> bytes:
    return SecretBox(random(SecretBox.KEY_SIZE)).encrypt(message)  # GT:H3-01


def seal_for_peer(message: bytes) -> bytes:
    ours, theirs = PrivateKey.generate(), PrivateKey.generate()  # GT:H3-02a/keygen
    return Box(ours, theirs.public_key).encrypt(message)  # GT:H3-02a GT:H3-02b


def endorse(message: bytes) -> bytes:
    return SigningKey.generate().sign(message)  # GT:H3-03
