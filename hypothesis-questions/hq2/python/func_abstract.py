#!/usr/bin/env python3
"""
Test fixture: cryptographic operations abstracted behind function calls.

Requires: pip install cryptography   (only for the AES-GCM section)

GROUND TRUTH (for scoring the static analyzer):
  id  primitive            library        abstraction layers
  --  -------------------  -------------  ---------------------------------------
  C1  SHA-256              hashlib        hash_bytes -> _DIGEST_REGISTRY["sha256"]
  C2  MD5 (weak)           hashlib        hash_bytes -> _DIGEST_REGISTRY["md5"]
  C3  HMAC-SHA256          hmac           sign_message -> _mac_impl (alias)
  C4  AES-256-GCM          cryptography   seal/open_sealed -> _AEAD_FACTORY
  C5  CSPRNG (token)       secrets        make_key -> _rng (lambda alias)
  C6  Hash via getattr     hashlib        hash_by_name -> getattr(hashlib, name)
"""

import hashlib
import hmac as _hmac_module
import secrets as _rng_module
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---- C1, C2: digest layer -------------------------------------------------

_DIGEST_REGISTRY = {
    "sha256": hashlib.sha256,
    "md5": hashlib.md5,
}

def hash_bytes(algorithm: str, data: bytes) -> bytes:
    """Hash data using a named algorithm from the registry."""
    return _DIGEST_REGISTRY[algorithm](data).digest()


# ---- C3: MAC layer (aliased import) ---------------------------------------

_mac_impl = _hmac_module.new

def sign_message(key: bytes, message: bytes) -> bytes:
    """Authenticate a message with HMAC-SHA256."""
    return _mac_impl(key, message, "sha256").digest()


# ---- C4: AEAD layer (factory indirection) ----------------------------------

_AEAD_FACTORY = AESGCM

def seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Encrypt and authenticate."""
    return _AEAD_FACTORY(key).encrypt(nonce, plaintext, aad)

def open_sealed(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    """Decrypt and verify."""
    return _AEAD_FACTORY(key).decrypt(nonce, ciphertext, aad)


# ---- C5: randomness layer (lambda alias) -----------------------------------

_rng = lambda n: _rng_module.token_bytes(n)

def make_key(size: int = 32) -> bytes:
    """Generate a random key."""
    return _rng(size)


# ---- C6: dynamic name resolution -------------------------------------------

def hash_by_name(name: str, data: bytes) -> bytes:
    """Resolve a hash constructor by name at runtime."""
    constructor = getattr(hashlib, name)
    return constructor(data).digest()


# ---- Driver ----------------------------------------------------------------

def main() -> None:
    key = make_key(32)
    nonce = make_key(12)
    message = b"test message"

    digest = hash_bytes("sha256", message)
    weak = hash_bytes("md5", message)
    tag = sign_message(key, message)
    ct = seal(key, nonce, message, b"aad")
    pt = open_sealed(key, nonce, ct, b"aad")
    dyn = hash_by_name("sha3_256", message)

    assert pt == message, "AEAD round-trip failed"
    assert len(digest) == 32 and len(weak) == 16 and len(tag) == 32
    assert len(dyn) == 32
    print("All operations completed; round-trip OK.")


if __name__ == "__main__":
    main()