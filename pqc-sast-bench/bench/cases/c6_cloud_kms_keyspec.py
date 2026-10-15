"""Create a signing key in a cloud KMS; the algorithm is a request parameter."""
import boto3

def create_signing_key():
    kms = boto3.client("kms")
    return kms.create_key(KeySpec="RSA_3072", KeyUsage="SIGN_VERIFY", Description="release signing")
