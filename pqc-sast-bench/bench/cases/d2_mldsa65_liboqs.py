"""Sign release artefacts with ML-DSA-65 through liboqs-python."""
import oqs

def sign_release(artifact: bytes):
    with oqs.Signature("ML-DSA-65") as signer:
        public_key = signer.generate_keypair()
        return public_key, signer.sign(artifact)
