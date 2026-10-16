"""H7 track C sinks."""
from cryptography.hazmat.primitives.asymmetric import rsa


def c_d01(bits):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)  # GT:H7-C-d01


def c_d02(bits):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)  # GT:H7-C-d02


def c_d04(bits):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)  # GT:H7-C-d04


def c_d08(bits):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)  # GT:H7-C-d08
