"""Benchmark target H3: cryptography encapsulated in third-party dependencies."""
import base64
import os
import secrets

import escrow
import messaging
import probe
import storage
import tokens


def main() -> int:
    probe.probe()
    messaging.seal_local(b"h03 note")
    messaging.seal_for_peer(b"h03 note")
    messaging.endorse(b"h03 note")
    tokens.session_token({"sub": "h03"}, secrets.token_urlsafe(48))
    tokens.service_token({"sub": "h03"})
    tokens.signed_cookie({"sub": "h03"}, secrets.token_urlsafe(32))
    tokens.one_time_code(base64.b32encode(os.urandom(20)).decode())
    storage.protect_blob(b"h03 blob")
    escrow.escrow(os.urandom(32))
    print("[h03] done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
