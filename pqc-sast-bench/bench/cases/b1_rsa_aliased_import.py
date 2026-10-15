"""Same operation as a1, written with an aliased module and positional arguments."""
from cryptography.hazmat.primitives.asymmetric import rsa as asym

def new_signing_key():
    return asym.generate_private_key(65537, 2048)
