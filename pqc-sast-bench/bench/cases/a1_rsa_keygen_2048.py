"""Issue and sign a service token with an RSA-2048 key (pyca/cryptography)."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

def issue_token(claims: bytes) -> bytes:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.sign(claims, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
