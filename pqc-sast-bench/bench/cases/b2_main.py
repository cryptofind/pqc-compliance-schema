"""Caller injects the algorithm module into the shared helper."""
from cryptography.hazmat.primitives.asymmetric import rsa as _alg
from b2_keyutil import make_key

SIGNING_BITS = 3072

def bootstrap():
    return make_key(_alg, SIGNING_BITS)
