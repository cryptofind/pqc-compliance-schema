"""Benchmark target H5: identifiers that misdescribe the cryptography they wrap."""
import envelope
import exchange
import pq_ready
import probe
import rsa_compat  # GT:H5-XA/decoy


def main() -> int:
    probe.probe()
    recipient = rsa_compat.generate_rsa_keypair()
    sealed = rsa_compat.rsa_encrypt(recipient.public_key(), b"h05 message")
    rsa_compat.legacy_header(sealed)
    rsa_compat.ecdsa_sign(rsa_compat.generate_ecdsa_key(), b"h05 message")
    rsa_compat.LegacyRSAWrapper().encrypt(b"h05 message")
    rsa_compat.legacy_keypair()
    twin = envelope.new_recipient()
    envelope.seal_for(twin.public_key(), b"h05 message")
    envelope.sign_blob(envelope.new_signer(), b"h05 message")
    peer = pq_ready.kyber_keypair()
    pq_ready.mlkem_encapsulate(peer.public_key())
    pq_ready.DilithiumSigner().sign(b"h05 message")
    other = exchange.new_party()
    exchange.agree(other.public_key())
    exchange.StampSigner().sign(b"h05 message")
    print("[h05] done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
