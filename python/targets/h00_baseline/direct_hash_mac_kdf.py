"""H0 control: direct, literal use of hash, MAC and KDF primitives (one asset per function)."""
import os

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

DATA = b"h00 baseline payload"
KEY = os.urandom(32)


def h01():
    ctx = hashes.Hash(hashes.SHA1())  # GT:H0-H01
    ctx.update(DATA)
    return ctx.finalize()


def h02():
    ctx = hashes.Hash(hashes.SHA224())  # GT:H0-H02
    ctx.update(DATA)
    return ctx.finalize()


def h03():
    ctx = hashes.Hash(hashes.SHA256())  # GT:H0-H03
    ctx.update(DATA)
    return ctx.finalize()


def h04():
    ctx = hashes.Hash(hashes.SHA384())  # GT:H0-H04
    ctx.update(DATA)
    return ctx.finalize()


def h05():
    ctx = hashes.Hash(hashes.SHA3_256())  # GT:H0-H05
    ctx.update(DATA)
    return ctx.finalize()


def h06():
    ctx = hashes.Hash(hashes.SHA3_384())  # GT:H0-H06
    ctx.update(DATA)
    return ctx.finalize()


def h07():
    ctx = hashes.Hash(hashes.BLAKE2b(64))  # GT:H0-H07
    ctx.update(DATA)
    return ctx.finalize()


def m01():
    mac = hmac.HMAC(KEY, hashes.SHA256())  # GT:H0-M01
    mac.update(DATA)
    return mac.finalize()


def m02():
    mac = hmac.HMAC(KEY, hashes.SHA384())  # GT:H0-M02
    mac.update(DATA)
    return mac.finalize()


def m03():
    mac = hmac.HMAC(KEY, hashes.SHA1())  # GT:H0-M03
    mac.update(DATA)
    return mac.finalize()


def k01():
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"h00").derive(KEY)  # GT:H0-K01


def k02():
    return HKDF(algorithm=hashes.SHA384(), length=32, salt=None, info=b"h00").derive(KEY)  # GT:H0-K02


def run():
    for fn in (h01, h02, h03, h04, h05, h06, h07, m01, m02, m03, k01, k02):
        fn()
