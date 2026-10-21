"""H0 library-coverage probe: pure-Python reference implementations."""
from dilithium_py.ml_dsa import ML_DSA_65
from kyber_py.ml_kem import ML_KEM_768

DATA = b"h00 baseline payload"


def l05():
    encaps_key, decaps_key = ML_KEM_768.keygen()  # GT:H0-L05/keygen
    shared, ciphertext = ML_KEM_768.encaps(encaps_key)  # GT:H0-L05/op
    return ML_KEM_768.decaps(decaps_key, ciphertext) == shared  # GT:H0-L05/op


def l06():
    public, private = ML_DSA_65.keygen()  # GT:H0-L06/keygen
    signature = ML_DSA_65.sign(private, DATA)  # GT:H0-L06/op
    return ML_DSA_65.verify(public, DATA, signature)  # GT:H0-L06/op


def run():
    for fn in (l05, l06):
        fn()
