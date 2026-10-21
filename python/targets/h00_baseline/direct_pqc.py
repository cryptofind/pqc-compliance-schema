"""H0 control: direct use of the post-quantum primitives exposed by the primary library."""
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem

DATA = b"h00 baseline payload"


def q01():
    key = mlkem.MLKEM768PrivateKey.generate()  # GT:H0-Q01/keygen
    shared, ciphertext = key.public_key().encapsulate()  # GT:H0-Q01/op
    return key.decapsulate(ciphertext) == shared  # GT:H0-Q01/op


def q02():
    key = mlkem.MLKEM1024PrivateKey.generate()  # GT:H0-Q02/keygen
    shared, ciphertext = key.public_key().encapsulate()  # GT:H0-Q02/op
    return key.decapsulate(ciphertext) == shared  # GT:H0-Q02/op


def q03():
    key = mldsa.MLDSA44PrivateKey.generate()  # GT:H0-Q03/keygen
    return key.sign(DATA)  # GT:H0-Q03/op


def q04():
    key = mldsa.MLDSA65PrivateKey.generate()  # GT:H0-Q04/keygen
    return key.sign(DATA)  # GT:H0-Q04/op


def q05():
    key = mldsa.MLDSA87PrivateKey.generate()  # GT:H0-Q05/keygen
    return key.sign(DATA)  # GT:H0-Q05/op


def run():
    for fn in (q01, q02, q03, q04, q05):
        fn()
