"""Integrity digests with SHA-256 (acceptable to NIST; CNSA 2.0 requires SHA-384 or SHA-512)."""
import hashlib

def digest(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()
