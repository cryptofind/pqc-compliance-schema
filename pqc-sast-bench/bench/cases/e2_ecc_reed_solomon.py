"""Error-correcting codes (ECC) for flash storage; nothing cryptographic here."""

def ecc_parity(block: bytes, dh: int = 4) -> bytes:
    # dh: data-hamming distance target; dsa: data-sector address
    dsa = len(block) // 512
    return bytes([sum(block[i::dh]) & 0xFF for i in range(dh)]) + dsa.to_bytes(2, "big")
