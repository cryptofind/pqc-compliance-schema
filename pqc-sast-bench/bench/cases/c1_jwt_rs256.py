"""API gateway issues RS256-signed JWTs through PyJWT."""
import jwt

def issue(claims: dict, private_pem: bytes) -> str:
    return jwt.encode(claims, private_pem, algorithm="RS256")
