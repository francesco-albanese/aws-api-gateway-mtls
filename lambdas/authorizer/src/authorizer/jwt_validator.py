"""JWT validation utilities for Cognito tokens."""

import jwt
from jwt import PyJWKClient

# Global JWKS client (cached across invocations)
_jwks_client: PyJWKClient | None = None


def get_jwks_client(region: str, user_pool_id: str) -> PyJWKClient:
    """Get cached JWKS client for Cognito user pool."""
    global _jwks_client
    if _jwks_client is None:
        jwks_url = (
            f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}/.well-known/jwks.json"
        )
        _jwks_client = PyJWKClient(jwks_url)
    return _jwks_client


def validate_jwt(
    token: str, region: str, user_pool_id: str, client_id: str
) -> dict[str, str | int | list[str]] | None:
    """Validate Cognito JWT and return claims if valid."""
    try:
        jwks_client = get_jwks_client(region, user_pool_id)
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}",
            options={
                "verify_aud": False,  # client_credentials tokens use 'client_id' not 'aud'
            },
        )

        # Verify client_id for M2M tokens
        if claims.get("client_id") != client_id:
            return None

        return claims
    except jwt.exceptions.PyJWTError:
        return None
