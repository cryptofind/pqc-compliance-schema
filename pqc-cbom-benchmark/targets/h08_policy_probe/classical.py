"""Policy probe: classical public-key primitives."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, x25519

DATA = b"h08 policy probe"


def p17():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # GT:H8-P17/keygen
    return key.sign(DATA, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())  # GT:H8-P17/op


def p18():
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)  # GT:H8-P18/keygen
    return key.public_key().encrypt(DATA, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))  # GT:H8-P18/op


def p19():
    key = ec.generate_private_key(ec.SECP384R1())  # GT:H8-P19/keygen
    return key.sign(DATA, ec.ECDSA(hashes.SHA384()))  # GT:H8-P19/op


def p20():
    key = ed25519.Ed25519PrivateKey.generate()  # GT:H8-P20/keygen
    return key.sign(DATA)  # GT:H8-P20/op


def p21():
    mine, peer = x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()  # GT:H8-P21/keygen
    return mine.exchange(peer.public_key())  # GT:H8-P21/op
