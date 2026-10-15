"""Wire format assumes 256-byte signatures and 294-byte public keys (sized for RSA-2048)."""
import struct

SIG_LEN = 256
PUBKEY_DER_LEN = 294
FRAME = struct.Struct(f"!I{PUBKEY_DER_LEN}s{SIG_LEN}s")

def pack_frame(seq: int, public_key_der: bytes, signature: bytes) -> bytes:
    if len(signature) != SIG_LEN:
        raise ValueError("unexpected signature length")
    return FRAME.pack(seq, public_key_der, signature)
