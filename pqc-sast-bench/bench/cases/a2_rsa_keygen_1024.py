"""Legacy device enrolment still generates RSA-1024 keys (classically weak control case)."""
from cryptography.hazmat.primitives.asymmetric import rsa

def enrol_device():
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)
