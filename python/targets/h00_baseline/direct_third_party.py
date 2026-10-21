"""H0 control: third-party libraries, with every algorithm choice spelled out where the API allows it."""
import hashlib
import secrets

import jwt
import pyotp
from cryptography.hazmat.primitives.asymmetric import ec
from itsdangerous import URLSafeTimedSerializer
from nacl.public import Box, PrivateKey
from nacl.secret import SecretBox
from nacl.signing import SigningKey
from nacl.utils import random as nacl_random

DATA = b"h00 baseline payload"


def x01():
    return SecretBox(nacl_random(SecretBox.KEY_SIZE)).encrypt(DATA)  # GT:H0-X01


def x02():
    ours, theirs = PrivateKey.generate(), PrivateKey.generate()  # GT:H0-X02a/keygen
    return Box(ours, theirs.public_key).encrypt(DATA)  # GT:H0-X02a GT:H0-X02b


def x03():
    return SigningKey.generate().sign(DATA)  # GT:H0-X03


def x04():
    return jwt.encode({"sub": "h00"}, secrets.token_urlsafe(48), algorithm="HS256")  # GT:H0-X04


def x05():
    key = ec.generate_private_key(ec.SECP384R1())  # GT:H0-X05/keygen
    return jwt.encode({"sub": "h00"}, key, algorithm="ES384")  # GT:H0-X05


def x06():
    return URLSafeTimedSerializer(secrets.token_urlsafe(32), signer_kwargs={"digest_method": hashlib.sha1}).dumps({"sub": "h00"})  # GT:H0-X06a GT:H0-X06b


def x07():
    return pyotp.TOTP(pyotp.random_base32(), digest=hashlib.sha1).now()  # GT:H0-X07


def run():
    for fn in (x01, x02, x03, x04, x05, x06, x07):
        fn()
