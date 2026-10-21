"""Policy probe: hashing and message authentication."""
import os

from cryptography.hazmat.primitives import hashes, hmac

DATA = b"h08 policy probe"
KEY = os.urandom(32)


def p04():
    ctx = hashes.Hash(hashes.SHA256())  # GT:H8-P04
    ctx.update(DATA)
    return ctx.finalize()


def p05():
    ctx = hashes.Hash(hashes.SHA384())  # GT:H8-P05
    ctx.update(DATA)
    return ctx.finalize()


def p06():
    ctx = hashes.Hash(hashes.SHA3_256())  # GT:H8-P06
    ctx.update(DATA)
    return ctx.finalize()


def p07():
    ctx = hashes.Hash(hashes.SHA1())  # GT:H8-P07
    ctx.update(DATA)
    return ctx.finalize()


def p08():
    ctx = hashes.Hash(hashes.SHA224())  # GT:H8-P08
    ctx.update(DATA)
    return ctx.finalize()


def p09():
    mac = hmac.HMAC(KEY, hashes.SHA256())  # GT:H8-P09
    mac.update(DATA)
    return mac.finalize()


def p10():
    mac = hmac.HMAC(KEY, hashes.SHA384())  # GT:H8-P10
    mac.update(DATA)
    return mac.finalize()
