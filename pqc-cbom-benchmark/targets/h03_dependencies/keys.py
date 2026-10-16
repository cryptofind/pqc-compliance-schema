"""Issuer key material, generated at start-up for the benchmark run."""
from cryptography.hazmat.primitives.asymmetric import ec


def issuer_key():
    return ec.generate_private_key(ec.SECP384R1())  # GT:H3-05/keygen
