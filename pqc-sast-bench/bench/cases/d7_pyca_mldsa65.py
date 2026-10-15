"""ML-DSA-65 signatures with a domain-separation context through pyca/cryptography."""
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

def sign_firmware(image: bytes) -> bytes:
    key = MLDSA65PrivateKey.generate()
    return key.sign(image, context=b"firmware-v1")
