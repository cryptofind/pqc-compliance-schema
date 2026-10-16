"""Policy probe: post-quantum primitives."""
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem
from pqcrypto.kem import ml_kem_512
from pqcrypto.sign import slh_dsa_sha2_128s

DATA = b"h08 policy probe"


def p11():
    public, private = ml_kem_512.keygen()  # GT:H8-P11/keygen
    ciphertext, shared = ml_kem_512.encaps(public)  # GT:H8-P11/op
    return ml_kem_512.decaps(private, ciphertext) == shared  # GT:H8-P11/op


def p12():
    key = mlkem.MLKEM768PrivateKey.generate()  # GT:H8-P12/keygen
    shared, ciphertext = key.public_key().encapsulate()  # GT:H8-P12/op
    return key.decapsulate(ciphertext) == shared


def p13():
    key = mlkem.MLKEM1024PrivateKey.generate()  # GT:H8-P13/keygen
    shared, ciphertext = key.public_key().encapsulate()  # GT:H8-P13/op
    return key.decapsulate(ciphertext) == shared


def p14():
    key = mldsa.MLDSA44PrivateKey.generate()  # GT:H8-P14/keygen
    return key.sign(DATA)  # GT:H8-P14/op


def p15():
    key = mldsa.MLDSA87PrivateKey.generate()  # GT:H8-P15/keygen
    return key.sign(DATA)  # GT:H8-P15/op


def p16():
    public, private = slh_dsa_sha2_128s.keygen()  # GT:H8-P16/keygen
    signature = slh_dsa_sha2_128s.sign(private, DATA)  # GT:H8-P16/op
    slh_dsa_sha2_128s.verify(public, DATA, signature)  # GT:H8-P16/op
    return signature
