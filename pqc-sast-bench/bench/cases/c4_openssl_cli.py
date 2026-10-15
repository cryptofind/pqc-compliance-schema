"""Certificate bootstrap shells out to the OpenSSL command-line tool."""
import subprocess

def make_csr_key(path: str):
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072",
                    "-out", path], check=True)
