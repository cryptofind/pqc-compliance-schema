"""Unit-test fixture: RSA key used only in tests."""
from cryptography.hazmat.primitives.asymmetric import rsa

def test_fixture_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert key.key_size == 2048
