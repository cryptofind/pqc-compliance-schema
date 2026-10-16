"""Benchmark target H2: cryptography behind abstraction layers."""
import os

import archive
import boxes
import dispatch
import documents
import pipeline
import probe
import sessions
import signers
import streams


def main() -> int:
    probe.probe()
    boxes.store(b"h02 record")
    archive.archive(b"h02 blob")
    signers.make_signer("primary").sign(b"h02 statement")
    pipeline.run(b" h02 message ", pipeline.default_steps(os.urandom(32)))
    documents.approve(b"h02 document", documents.approver())
    dispatch.fingerprint(b"h02 content")
    streams.archive_lines([b"alpha", b"beta"])
    _ = sessions.Session(os.urandom(32)).traffic_key
    print("[h02] done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
