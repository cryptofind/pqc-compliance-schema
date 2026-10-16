"""H0 control: direct, literal use of symmetric primitives (one asset per function)."""
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import keywrap, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

DATA = b"h00 baseline payload"


def s01():
    return AESGCM(AESGCM.generate_key(bit_length=128)).encrypt(os.urandom(12), DATA, None)  # GT:H0-S01


def s02():
    return AESGCM(AESGCM.generate_key(bit_length=192)).encrypt(os.urandom(12), DATA, None)  # GT:H0-S02


def s03():
    return AESGCM(AESGCM.generate_key(bit_length=256)).encrypt(os.urandom(12), DATA, None)  # GT:H0-S03


def s04():
    enc = Cipher(algorithms.AES(os.urandom(32)), modes.CBC(os.urandom(16))).encryptor()  # GT:H0-S04
    pad = padding.PKCS7(128).padder()  # GT:H0-S04/padding
    return enc.update(pad.update(DATA) + pad.finalize()) + enc.finalize()


def s05():
    return ChaCha20Poly1305(ChaCha20Poly1305.generate_key()).encrypt(os.urandom(12), DATA, None)  # GT:H0-S05


def s06():
    return keywrap.aes_key_wrap(os.urandom(32), os.urandom(32))  # GT:H0-S06


def s07():
    return Fernet(Fernet.generate_key()).encrypt(DATA)  # GT:H0-S07a GT:H0-S07b


def s08():
    enc = Cipher(algorithms.SM4(os.urandom(16)), modes.CBC(os.urandom(16))).encryptor()  # GT:H0-S08
    return enc.update(DATA.ljust(32, b"\0")) + enc.finalize()


def run():
    for fn in (s01, s02, s03, s04, s05, s06, s07, s08):
        fn()
