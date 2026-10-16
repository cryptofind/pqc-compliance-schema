"""Text that resembles cryptography but performs none (benchmark target H9)."""
import logging
import zlib

log = logging.getLogger("h09")

SUPPORTED_ALGORITHMS = ["AES-128-CBC", "RSA-2048", "SHA-1", "MD5"]  # GT:H9-D3/decoy


class ECDSA:  # GT:H9-D2/decoy
    """Engineering Change Document Sign-off Approval record."""

    def __init__(self, document: str):
        self.document = document
        self.approvals = []

    def sign(self, approver: str) -> dict:  # GT:H9-D2/decoy
        self.approvals.append(approver)
        return {"document": self.document, "approvers": list(self.approvals)}


def sha256_digest(data: bytes) -> int:  # GT:H9-D4/decoy
    return zlib.crc32(data)


def rotate_keys() -> None:
    log.info("rotating RSA-4096 keys for tenant %s", "demo")  # GT:H9-D1/decoy


# Next quarter: move session keys from X25519 to ML-KEM-768.  GT:H9-D5/decoy
def describe() -> list:
    return list(SUPPORTED_ALGORITHMS)
