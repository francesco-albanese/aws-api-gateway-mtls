"""Cognito token exchange for client_credentials flow."""

import base64
import json
import urllib.error
import urllib.parse
import urllib.request

from .types import CognitoTokenResponse


def exchange_for_cognito_token(
    domain: str, client_id: str, client_secret: str, scope: str = "mtls-api/access"
) -> CognitoTokenResponse | None:
    """Exchange client credentials for Cognito JWT.

    Args:
        domain: Cognito domain (e.g., test-domain.auth.us-east-1.amazoncognito.com)
        client_id: Cognito app client ID
        client_secret: Cognito app client secret
        scope: OAuth scope (default: mtls-api/access)

    Returns:
        CognitoTokenResponse with access_token, token_type, expires_in
        None if exchange fails
    """
    token_url = f"https://{domain}/oauth2/token"

    data = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "scope": scope,
        }
    ).encode("utf-8")

    credentials = f"{client_id}:{client_secret}"
    auth_header = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Basic {auth_header}",
    }

    try:
        req = urllib.request.Request(token_url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, json.JSONDecodeError):
        return None
