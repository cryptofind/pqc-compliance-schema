"""Migration notes. TODO: replace RSA-2048 and ECDSA P-256 with ML-DSA; Diffie-Hellman is gone.

This module contains no cryptography; it only formats migration status messages.
"""

def status_line(service: str, done: bool) -> str:
    # e.g. "billing: RSA removed" -- purely a log string
    return f"{service}: {'RSA removed' if done else 'RSA still present'}"
