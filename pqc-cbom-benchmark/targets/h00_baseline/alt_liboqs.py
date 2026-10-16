"""H0 library-coverage probe: liboqs bindings (imported only when H00_WITH_LIBOQS=1)."""
import oqs

DATA = b"h00 baseline payload"


def l07():
    with oqs.KeyEncapsulation("ML-KEM-768") as receiver:  # GT:H0-L07/keygen
        public = receiver.generate_keypair()  # GT:H0-L07/keygen
        with oqs.KeyEncapsulation("ML-KEM-768") as sender:  # GT:H0-L07/op
            ciphertext, shared = sender.encap_secret(public)  # GT:H0-L07/op
        return receiver.decap_secret(ciphertext) == shared  # GT:H0-L07/op


def l08():
    with oqs.Signature("ML-DSA-65") as signer:  # GT:H0-L08/keygen
        public = signer.generate_keypair()  # GT:H0-L08/keygen
        signature = signer.sign(DATA)  # GT:H0-L08/op
    with oqs.Signature("ML-DSA-65") as verifier:  # GT:H0-L08/op
        return verifier.verify(DATA, signature, public)  # GT:H0-L08/op


def run():
    for fn in (l07, l08):
        fn()
