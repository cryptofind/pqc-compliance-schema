"""Application code written against the macro layer."""
from macro_engine import KEM_KEYPAIR, SEAL, expand


@expand
def protect(record: bytes) -> bytes:
    return SEAL(record)  # GT:H1-01


@expand
def agree_session() -> bool:
    keypair = KEM_KEYPAIR()  # GT:H1-02
    shared, ciphertext = keypair.public_key().encapsulate()  # GT:H1-02/op
    return keypair.decapsulate(ciphertext) == shared
