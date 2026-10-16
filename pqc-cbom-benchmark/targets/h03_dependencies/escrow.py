"""Key escrow through a vendored helper library."""
import os

from third_party.sealkit import wrap_key


def escrow(data_key: bytes) -> bytes:
    return wrap_key(os.urandom(32), data_key)  # GT:H3-09
