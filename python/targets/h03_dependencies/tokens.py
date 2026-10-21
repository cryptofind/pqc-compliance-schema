"""Token issuance helpers built on third-party libraries."""
import jwt
import pyotp
from itsdangerous import URLSafeTimedSerializer

from keys import issuer_key


def session_token(claims: dict, secret: str) -> str:
    return jwt.encode(claims, secret)  # GT:H3-04


def service_token(claims: dict) -> str:
    return jwt.encode(claims, issuer_key(), algorithm="ES384")  # GT:H3-05


def signed_cookie(value: dict, secret: str) -> str:
    return URLSafeTimedSerializer(secret).dumps(value)  # GT:H3-06a GT:H3-06b


def one_time_code(secret_b32: str) -> str:
    return pyotp.TOTP(secret_b32).now()  # GT:H3-07
