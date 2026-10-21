"""Benchmark target H6: algorithm selection from external configuration and the environment."""
import os

import probe
import services
import settings


def main() -> int:
    probe.probe()
    cfg = settings.load()
    services.protect(cfg, b"h06 record")
    services.sign(cfg, b"h06 statement")
    secret = services.derive(cfg, os.urandom(32))
    services.transport(cfg, secret)
    services.authenticate(cfg, secret, b"h06 message")
    services.fingerprint(cfg, b"h06 content")
    services.encapsulate(cfg)
    services.agree(cfg)
    services.session_seal(cfg, b"h06 session")
    print("[h06] done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
