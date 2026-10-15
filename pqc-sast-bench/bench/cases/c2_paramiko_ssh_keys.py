"""Provision SSH host keys for edge gateways with Paramiko."""
import paramiko

def provision_host_keys():
    rsa_key = paramiko.RSAKey.generate(bits=3072)
    ecdsa_key = paramiko.ECDSAKey.generate()
    return rsa_key, ecdsa_key
