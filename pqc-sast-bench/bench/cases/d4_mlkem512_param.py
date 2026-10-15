"""ML-KEM-512: approved in FIPS 203 but below the CNSA 2.0 parameter set."""
import oqs

def establish_low_power(peer_key: bytes):
    with oqs.KeyEncapsulation("ML-KEM-512") as kem:
        return kem.encap_secret(peer_key)
