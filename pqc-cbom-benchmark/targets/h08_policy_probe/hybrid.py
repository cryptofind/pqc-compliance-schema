"""Policy probe: classical and post-quantum secrets combined in one derivation."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, mlkem, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def p22() -> bytes:
    party_a, party_b = x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()  # GT:H8-P22-C/keygen
    classical = party_a.exchange(party_b.public_key())  # GT:H8-P22-C/op
    receiver = mlkem.MLKEM768PrivateKey.generate()  # GT:H8-P22-Q/keygen
    post_quantum, encapsulated = receiver.public_key().encapsulate()  # GT:H8-P22-Q/op
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=encapsulated).derive(post_quantum + classical)  # GT:H8-P22-K


def p23() -> bytes:
    party_a, party_b = ec.generate_private_key(ec.SECP384R1()), ec.generate_private_key(ec.SECP384R1())  # GT:H8-P23-C/keygen
    classical = party_a.exchange(ec.ECDH(), party_b.public_key())  # GT:H8-P23-C/op
    receiver = mlkem.MLKEM1024PrivateKey.generate()  # GT:H8-P23-Q/keygen
    post_quantum, encapsulated = receiver.public_key().encapsulate()  # GT:H8-P23-Q/op
    return HKDF(algorithm=hashes.SHA384(), length=32, salt=None, info=encapsulated).derive(post_quantum + classical)  # GT:H8-P23-K
