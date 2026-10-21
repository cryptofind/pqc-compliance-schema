"""H0 control: direct, literal use of classical public-key primitives (one asset per function)."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, x25519

DATA = b"h00 baseline payload"


def a01():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # GT:H0-A01/keygen
    return key.public_key().encrypt(DATA, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))  # GT:H0-A01/op


def a02():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # GT:H0-A02/keygen
    return key.sign(DATA, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())  # GT:H0-A02/op


def a03():
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)  # GT:H0-A03/keygen
    return key.sign(DATA, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())  # GT:H0-A03/op


def a04():
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)  # GT:H0-A04/keygen
    return key.public_key().encrypt(DATA, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))  # GT:H0-A04/op


def a05():
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)  # GT:H0-A05/keygen


def a06():
    key = ec.generate_private_key(ec.SECP256R1())  # GT:H0-A06/keygen
    return key.sign(DATA, ec.ECDSA(hashes.SHA256()))  # GT:H0-A06/op


def a07():
    key = ec.generate_private_key(ec.SECP384R1())  # GT:H0-A07/keygen
    return key.sign(DATA, ec.ECDSA(hashes.SHA384()))  # GT:H0-A07/op


def a08():
    mine, peer = ec.generate_private_key(ec.SECP384R1()), ec.generate_private_key(ec.SECP384R1())  # GT:H0-A08/keygen
    return mine.exchange(ec.ECDH(), peer.public_key())  # GT:H0-A08/op


def a09():
    mine, peer = ec.generate_private_key(ec.SECP192R1()), ec.generate_private_key(ec.SECP192R1())  # GT:H0-A09/keygen
    return mine.exchange(ec.ECDH(), peer.public_key())  # GT:H0-A09/op


def a10():
    mine, peer = ec.generate_private_key(ec.SECP224R1()), ec.generate_private_key(ec.SECP224R1())  # GT:H0-A10/keygen
    return mine.exchange(ec.ECDH(), peer.public_key())  # GT:H0-A10/op


def a11():
    mine, peer = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())  # GT:H0-A11/keygen
    return mine.exchange(ec.ECDH(), peer.public_key())  # GT:H0-A11/op


def a12():
    mine, peer = ec.generate_private_key(ec.SECP521R1()), ec.generate_private_key(ec.SECP521R1())  # GT:H0-A12/keygen
    return mine.exchange(ec.ECDH(), peer.public_key())  # GT:H0-A12/op


def a13():
    mine, peer = ec.generate_private_key(ec.SECP256K1()), ec.generate_private_key(ec.SECP256K1())  # GT:H0-A13/keygen
    return mine.exchange(ec.ECDH(), peer.public_key())  # GT:H0-A13/op


def a14():
    mine, peer = ec.generate_private_key(ec.BrainpoolP256R1()), ec.generate_private_key(ec.BrainpoolP256R1())  # GT:H0-A14/keygen
    return mine.exchange(ec.ECDH(), peer.public_key())  # GT:H0-A14/op


def a15():
    mine, peer = ec.generate_private_key(ec.BrainpoolP384R1()), ec.generate_private_key(ec.BrainpoolP384R1())  # GT:H0-A15/keygen
    return mine.exchange(ec.ECDH(), peer.public_key())  # GT:H0-A15/op


def a16():
    mine, peer = ec.generate_private_key(ec.BrainpoolP512R1()), ec.generate_private_key(ec.BrainpoolP512R1())  # GT:H0-A16/keygen
    return mine.exchange(ec.ECDH(), peer.public_key())  # GT:H0-A16/op


def a17():
    key = ed25519.Ed25519PrivateKey.generate()  # GT:H0-A17/keygen
    return key.sign(DATA)  # GT:H0-A17/op


def a18():
    mine, peer = x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()  # GT:H0-A18/keygen
    return mine.exchange(peer.public_key())  # GT:H0-A18/op


def run():
    for fn in (a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11, a12, a13, a14, a15, a16, a17, a18):
        fn()
