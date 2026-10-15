"""Sign firmware manifests with ECDSA over P-256."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

def sign_manifest(manifest: bytes) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.sign(manifest, ec.ECDSA(hashes.SHA256()))
