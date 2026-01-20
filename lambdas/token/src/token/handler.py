"""Token exchange Lambda handler - exchanges mTLS client cert for JWT."""

import os

from .cert_metadata import lookup_cert_metadata
from .cert_validator import validate_cert_status
from .cognito_exchange import exchange_for_cognito_token
from .types import APIGatewayProxyEventV2, APIGatewayProxyResponseV2, LambdaContext
from .utils import extract_serial_number, json_response


def handler(event: APIGatewayProxyEventV2, context: LambdaContext) -> APIGatewayProxyResponseV2:
    """Exchange mTLS client certificate for JWT access token.

    Flow:
    1. Extract serialNumber from mTLS client cert
    2. Lookup cert in DynamoDB (validate not revoked/expired)
    3. Exchange for Cognito JWT via client_credentials grant
    4. Return access_token
    """
    serial_number = extract_serial_number(event)

    if not serial_number:
        return json_response(
            401, {"error": "unauthorized", "message": "Missing client certificate"}
        )

    table_name = os.environ.get("DYNAMODB_TABLE_NAME", "mtls-clients-metadata")
    cognito_domain = os.environ.get("COGNITO_DOMAIN", "")
    cognito_client_id = os.environ.get("COGNITO_CLIENT_ID", "")
    cognito_client_secret = os.environ.get("COGNITO_CLIENT_SECRET", "")

    metadata = lookup_cert_metadata(serial_number, table_name)
    if not metadata:
        return json_response(404, {"error": "not_found", "message": "Certificate not registered"})

    valid, reason = validate_cert_status(metadata)
    if not valid:
        return json_response(403, {"error": "forbidden", "message": reason})

    if not cognito_domain or not cognito_client_id or not cognito_client_secret:
        return json_response(500, {"error": "server_error", "message": "Cognito not configured"})

    token_response = exchange_for_cognito_token(
        cognito_domain, cognito_client_id, cognito_client_secret
    )
    if not token_response:
        return json_response(
            500, {"error": "server_error", "message": "Failed to obtain token from Cognito"}
        )

    return json_response(
        200,
        {
            "access_token": token_response["access_token"],
            "token_type": token_response["token_type"],
            "expires_in": token_response["expires_in"],
        },
    )
