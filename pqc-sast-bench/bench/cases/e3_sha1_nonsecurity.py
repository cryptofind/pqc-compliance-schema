"""SHA-1 used only for cache keys, explicitly marked as not security-relevant."""
import hashlib

def cache_key(path: str) -> str:
    return hashlib.sha1(path.encode(), usedforsecurity=False).hexdigest()
