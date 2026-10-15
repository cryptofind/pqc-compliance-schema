#!/usr/bin/env python3
"""
Test fixture: cryptographic operations encapsulated within third-party dependencies.

The cryptographic primitives are never written out in this file. Each one is
reached through a call into a third-party library, so the primitive exists only
in the dependency's source or compiled code.

Requires (pins are suggestions; any recent versions that expose these APIs work):
    pip install PyJWT==2.9.0 PyNaCl==1.5.0 bcrypt==4.2.0 itsdangerous==2.2.0

GROUND TRUTH (for scoring the static analyzer):
  id  primitive                library       where the primitive actually lives
  --  -----------------------  ------------  ----------------------------------------------
  D1  HMAC-SHA256 (JWT HS256)  PyJWT         jwt.api_jws -> hmac.new(..., sha256)
  D2  XSalsa20-Poly1305 AEAD   PyNaCl        nacl.secret.SecretBox -> libsodium C code
  D3  bcrypt (Blowfish KDF)    bcrypt        bcrypt C extension (hashpw / checkpw)
  D4  HMAC-SHA1 (default!)     itsdangerous  Signer.default_digest_method = sha1 (weak default)
  D5  CSPRNG                   PyNaCl        nacl.utils.random -> libsodium randombytes
"""

import nacl.secret
import nacl.utils
import bcrypt
import jwt
from itsdangerous import URLSafeSerializer


# ---- First-party wrappers (the code a static analyzer sees) ---------------
# None of these methods names a primitive. They only forward to dependencies.

class TokenService:
    """Signs and verifies tokens via PyJWT (D1)."""

    @staticmethod
    def issue(claims: dict, key: bytes) -> str:
        return jwt.encode(claims, key, algorithm="HS256")

    @staticmethod
    def verify(token: str, key: bytes) -> dict:
        return jwt.decode(token, key, algorithms=["HS256"])


class VaultService:
    """Authenticated encryption via PyNaCl SecretBox (D2)."""

    def __init__(self, key: bytes):
        self._box = nacl.secret.SecretBox(key)

    def seal(self, plaintext: bytes) -> bytes:
        return bytes(self._box.encrypt(plaintext))

    def unseal(self, ciphertext: bytes) -> bytes:
        return self._box.decrypt(ciphertext)


class PasswordService:
    """Password hashing via bcrypt (D3)."""

    @staticmethod
    def hash(password: str) -> bytes:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

    @staticmethod
    def verify(password: str, hashed: bytes) -> bool:
        return bcrypt.checkpw(password.encode(), hashed)


class CookieService:
    """Signed cookie payloads via itsdangerous, default settings (D4)."""

    def __init__(self, secret: str):
        self._s = URLSafeSerializer(secret)

    def dumps(self, obj) -> str:
        return self._s.dumps(obj)

    def loads(self, token: str):
        return self._s.loads(token)


class Entropy:
    """Random byte generation via PyNaCl (D5)."""

    @staticmethod
    def new_key(size: int = 32) -> bytes:
        return nacl.utils.random(size)


# ---- Driver ----------------------------------------------------------------

def main() -> None:
    key = Entropy.new_key(32)

    token = TokenService.issue({"sub": "user-1"}, key)
    claims = TokenService.verify(token, key)

    vault = VaultService(key)
    ct = vault.seal(b"test secret")
    pt = vault.unseal(ct)

    hashed = PasswordService.hash("correct horse")
    pw_ok = PasswordService.verify("correct horse", hashed)

    cookies = CookieService("app-secret")
    cookie = cookies.dumps({"uid": 1})
    cookie_obj = cookies.loads(cookie)

    assert claims["sub"] == "user-1", "JWT round-trip failed"
    assert pt == b"test secret", "SecretBox round-trip failed"
    assert pw_ok, "bcrypt verify failed"
    assert cookie_obj == {"uid": 1}, "itsdangerous round-trip failed"
    print("All operations completed; round-trips OK.")


if __name__ == "__main__":
    main()