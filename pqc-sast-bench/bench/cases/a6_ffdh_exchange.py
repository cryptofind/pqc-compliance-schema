"""Finite-field Diffie-Hellman key agreement for a legacy peer."""
from cryptography.hazmat.primitives.asymmetric import dh

def agree(peer_public_key):
    params = dh.generate_parameters(generator=2, key_size=2048)
    ours = params.generate_private_key()
    return ours.exchange(peer_public_key)
