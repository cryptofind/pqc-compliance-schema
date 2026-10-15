"""Document signing with PyCryptodome RSA-3072 and PKCS#1 v1.5."""
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

def sign_document(doc: bytes) -> bytes:
    key = RSA.generate(3072)
    return pkcs1_15.new(key).sign(SHA256.new(doc))
