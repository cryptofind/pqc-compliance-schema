"""Configuration-driven cryptographic services."""
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import crypto_factory


def protect(cfg: dict, data: bytes) -> bytes:
    spec = cfg["aead"]
    primitive = crypto_factory.make_aead(spec["family"], spec["mode"], spec["key_bits"])  # GT:H6-01/op
    nonce = os.urandom(12)
    return nonce + primitive.encrypt(nonce, data, None)  # GT:H6-01/op


def sign(cfg: dict, data: bytes) -> bytes:
    spec = cfg["signing"]
    return crypto_factory.make_signer(spec["scheme"], spec["curve"], spec["digest"])(data)  # GT:H6-02/op


def derive(cfg: dict, secret: bytes) -> bytes:
    spec = cfg["kdf"]
    kdf = crypto_factory.KDFS[spec["name"]](algorithm=crypto_factory.digest(spec["digest"]), length=int(spec["length"]), salt=None, info=spec["info"].encode())  # GT:H6-03/op
    return kdf.derive(secret)


def transport(cfg: dict, secret: bytes) -> bytes:
    spec = cfg["transport"]
    if spec["scheme"].upper() != "RSA" or spec["padding"].upper() != "OAEP":  # GT:H6-04/def
        raise ValueError("unsupported key transport configuration")
    key = rsa.generate_private_key(public_exponent=65537, key_size=int(spec["key_bits"]))  # GT:H6-04/keygen
    scheme = padding.OAEP(mgf=padding.MGF1(algorithm=crypto_factory.digest(spec["digest"])), algorithm=crypto_factory.digest(spec["digest"]), label=None)  # GT:H6-04/padding
    return key.public_key().encrypt(secret, scheme)  # GT:H6-04/op


def authenticate(cfg: dict, key: bytes, data: bytes) -> bytes:
    spec = cfg["mac"]
    mac = crypto_factory.MACS[spec["algorithm"].upper()](key, crypto_factory.digest(spec["digest"]))  # GT:H6-05/op
    mac.update(data)
    return mac.finalize()


def fingerprint(cfg: dict, data: bytes) -> bytes:
    ctx = hashes.Hash(crypto_factory.digest(cfg["digest"]))  # GT:H6-06/op
    ctx.update(data)
    return ctx.finalize()


def encapsulate(cfg: dict) -> bool:
    impl = crypto_factory.KEMS[cfg["kem"].upper()]
    receiver = impl.generate()  # GT:H6-07/keygen
    shared, encapsulated = receiver.public_key().encapsulate()  # GT:H6-07/op
    return receiver.decapsulate(encapsulated) == shared


def agree(cfg: dict):
    if not cfg["kex"]:
        return None
    impl = crypto_factory.KEXS[cfg["kex"].upper()]
    mine, theirs = impl.generate(), impl.generate()  # GT:H6-08/keygen
    return mine.exchange(theirs.public_key())  # GT:H6-08/op


def session_seal(cfg: dict, data: bytes):
    name = cfg["session_cipher"]
    if not name:
        return None
    family, mode, bits = name.upper().split("-")
    primitive = crypto_factory.make_aead(family, mode, int(bits))  # GT:H6-09/op
    nonce = os.urandom(12)
    return nonce + primitive.encrypt(nonce, data, None)  # GT:H6-09/op
