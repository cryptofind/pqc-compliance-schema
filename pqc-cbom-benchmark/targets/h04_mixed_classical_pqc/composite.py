"""Unit U2: dual signature that verifies only when both component signatures verify."""
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa


def sign_dual(message: bytes):
    post_quantum = mldsa.MLDSA65PrivateKey.generate()  # GT:H4-U2-Q/keygen
    classical = ed25519.Ed25519PrivateKey.generate()  # GT:H4-U2-C/keygen
    bundle = (post_quantum.sign(message), classical.sign(message))  # GT:H4-U2-Q/op GT:H4-U2-C/op
    return bundle, post_quantum.public_key(), classical.public_key()


def verify_dual(message: bytes, bundle, pq_public, classical_public) -> bool:
    pq_signature, classical_signature = bundle
    pq_public.verify(pq_signature, message)  # GT:H4-U2-Q/op
    classical_public.verify(classical_signature, message)  # GT:H4-U2-C/op
    return True
