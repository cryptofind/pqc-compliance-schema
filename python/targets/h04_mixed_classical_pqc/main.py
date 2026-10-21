"""Benchmark target H4: functions that mix quantum-vulnerable and quantum-resistant primitives."""
import composite
import envelopes
import key_establishment
import probe


def main() -> int:
    probe.probe()
    key_establishment.combined_secret()
    bundle, pq_public, classical_public = composite.sign_dual(b"h04 statement")
    composite.verify_dual(b"h04 statement", bundle, pq_public, classical_public)
    key_establishment.authenticated_channel()
    envelopes.wrapped_envelope(b"h04 record")
    envelopes.negotiated_envelope(b"h04 record", peer_supports_pq=True)
    envelopes.negotiated_envelope(b"h04 record", peer_supports_pq=False)
    envelopes.pq_envelope(b"h04 record")
    key_establishment.combined_secret_high()
    print("[h04] done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
