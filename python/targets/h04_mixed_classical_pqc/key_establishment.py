"""Key-establishment routines (benchmark target H4)."""
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mlkem, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def combined_secret() -> bytes:
    """Unit U1: two independent secrets fed into one derivation; either one alone protects the result."""
    party_a = x25519.X25519PrivateKey.generate()  # GT:H4-U1-C/keygen
    party_b = x25519.X25519PrivateKey.generate()  # GT:H4-U1-C/keygen
    classical = party_a.exchange(party_b.public_key())  # GT:H4-U1-C/op
    receiver = mlkem.MLKEM768PrivateKey.generate()  # GT:H4-U1-Q/keygen
    post_quantum, encapsulated = receiver.public_key().encapsulate()  # GT:H4-U1-Q/op
    assert receiver.decapsulate(encapsulated) == post_quantum
    transcript = encapsulated + party_b.public_key().public_bytes_raw()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=transcript).derive(post_quantum + classical)  # GT:H4-U1-K


def authenticated_channel() -> bytes:
    """Unit U3: post-quantum key establishment, classical authentication of the transcript."""
    identity = ec.generate_private_key(ec.SECP256R1())  # GT:H4-U3-A/keygen
    receiver = mlkem.MLKEM768PrivateKey.generate()  # GT:H4-U3-Q/keygen
    shared, encapsulated = receiver.public_key().encapsulate()  # GT:H4-U3-Q/op
    proof = identity.sign(encapsulated, ec.ECDSA(hashes.SHA256()))  # GT:H4-U3-A/op
    identity.public_key().verify(proof, encapsulated, ec.ECDSA(hashes.SHA256()))  # GT:H4-U3-A/op
    assert receiver.decapsulate(encapsulated) == shared
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"u3").derive(shared)  # GT:H4-U3-K


def combined_secret_high() -> bytes:
    """Unit U7: as U1, with larger parameter sets throughout."""
    party_a = ec.generate_private_key(ec.SECP384R1())  # GT:H4-U7-C/keygen
    party_b = ec.generate_private_key(ec.SECP384R1())  # GT:H4-U7-C/keygen
    classical = party_a.exchange(ec.ECDH(), party_b.public_key())  # GT:H4-U7-C/op
    receiver = mlkem.MLKEM1024PrivateKey.generate()  # GT:H4-U7-Q/keygen
    post_quantum, encapsulated = receiver.public_key().encapsulate()  # GT:H4-U7-Q/op
    assert receiver.decapsulate(encapsulated) == post_quantum
    point = party_b.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return HKDF(algorithm=hashes.SHA384(), length=32, salt=None, info=encapsulated + point).derive(post_quantum + classical)  # GT:H4-U7-K
