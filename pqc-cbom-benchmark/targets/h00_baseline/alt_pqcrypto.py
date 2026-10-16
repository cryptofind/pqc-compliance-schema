"""H0 library-coverage probe: a second post-quantum library (compiled bindings)."""
from pqcrypto.kem import ml_kem_512, ml_kem_768
from pqcrypto.sign import ml_dsa_65, slh_dsa_sha2_128s

DATA = b"h00 baseline payload"


def l01():
    public, private = ml_kem_512.keygen()  # GT:H0-L01/keygen
    ciphertext, shared = ml_kem_512.encaps(public)  # GT:H0-L01/op
    return ml_kem_512.decaps(private, ciphertext) == shared  # GT:H0-L01/op


def l02():
    public, private = ml_kem_768.keygen()  # GT:H0-L02/keygen
    ciphertext, shared = ml_kem_768.encaps(public)  # GT:H0-L02/op
    return ml_kem_768.decaps(private, ciphertext) == shared  # GT:H0-L02/op


def l03():
    public, private = ml_dsa_65.keygen()  # GT:H0-L03/keygen
    signature = ml_dsa_65.sign(private, DATA)  # GT:H0-L03/op
    ml_dsa_65.verify(public, DATA, signature)  # GT:H0-L03/op
    return signature


def l04():
    public, private = slh_dsa_sha2_128s.keygen()  # GT:H0-L04/keygen
    signature = slh_dsa_sha2_128s.sign(private, DATA)  # GT:H0-L04/op
    slh_dsa_sha2_128s.verify(public, DATA, signature)  # GT:H0-L04/op
    return signature


def run():
    for fn in (l01, l02, l03, l04):
        fn()
