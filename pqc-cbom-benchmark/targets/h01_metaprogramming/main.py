"""Benchmark target H1: cryptography injected through metaprogramming."""
import os

import codegen
import dynload
import meta
import payload
import probe
import records


def main() -> int:
    probe.probe()
    records.protect(b"h01 record")
    records.agree_session()
    codegen.derive_session(os.urandom(32))  # GT:H1-03/anchor
    meta.LedgerEntrySigner().sign(b"h01 ledger entry")
    dynload.agree()
    payload.run(b"h01 payload")
    print("[h01] done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
