"""Curve selected at deploy time through an environment variable (default P-256)."""
import os
from cryptography.hazmat.primitives.asymmetric import ec

def signing_key():
    curve = getattr(ec, os.environ.get("SIGNING_CURVE", "SECP256R1"))()
    return ec.generate_private_key(curve)
