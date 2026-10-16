"""H0 control: direct use of standard-library hashing and MAC functions."""
import hashlib
import hmac
import os

DATA = b"h00 baseline payload"
KEY = os.urandom(32)


def t01():
    return hashlib.sha256(DATA).digest()  # GT:H0-T01


def t02():
    return hashlib.md5(DATA, usedforsecurity=False).hexdigest()  # GT:H0-T02


def t03():
    return hashlib.sha1(DATA).digest()  # GT:H0-T03


def t04():
    return hmac.new(KEY, DATA, hashlib.sha256).digest()  # GT:H0-T04


def t05():
    return hmac.new(KEY, DATA, hashlib.sha1).digest()  # GT:H0-T05


def run():
    for fn in (t01, t02, t03, t04, t05):
        fn()
