"""Token exchange Lambda handler - exchanges mTLS client cert for JWT."""

import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from typing import NotRequired, TypedDict

import boto3
from botocore.exceptions import ClientError


class CertValidity(TypedDict):
    notBefore: str
    notAfter: str


class ClientCert(TypedDict, total=False):
    clientCertPem: str
    subjectDN: str
    issuerDN: str
    serialNumber: str
    validity: CertValidity


class Authentication(TypedDict, total=False):
    clientCert: ClientCert


class RequestContext(TypedDict, total=False):
    authentication: Authentication


class APIGatewayProxyEventV2(TypedDict, total=False):
    """API Gateway HTTP API v2 event (partial, mTLS-relevant fields)."""

    requestContext: RequestContext


class APIGatewayProxyResponseV2(TypedDict):
    """API Gateway HTTP API v2 response."""

    statusCode: int
    headers: NotRequired[dict[str, str]]
    body: NotRequired[str]


class LambdaContext:
    """AWS Lambda context object stub for typing."""

    function_name: str
    memory_limit_in_mb: int
    invoked_function_arn: str
    aws_request_id: str


class CertMetadata(TypedDict):
    """DynamoDB cert metadata item."""

    serialNumber: str
    client_id: str
    clientName: str
    status: str
    issuedAt: str
    expiry: str


class CognitoTokenResponse(TypedDict):
    """Cognito token endpoint response."""

    access_token: str
    token_type: str
    expires_in: int


def _extract_serial_number(event: APIGatewayProxyEventV2) -> str | None:
    """Extract certificate serial number from mTLS context."""
    request_context = event.get("requestContext", {})
    authentication = request_context.get("authentication", {})
    client_cert = authentication.get("clientCert", {})
    return client_cert.get("serialNumber")


def _json_response(status_code: int, body: dict) -> APIGatewayProxyResponseV2:
    """Build JSON API Gateway response."""
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def _get_dynamodb_client():
    """Get DynamoDB client (extracted for testing)."""
    return boto3.client("dynamodb")


def _lookup_cert_metadata(serial_number: str, table_name: str) -> CertMetadata | None:
    """Lookup certificate metadata from DynamoDB by serial number."""
    dynamodb = _get_dynamodb_client()
    try:
        response = dynamodb.get_item(
            TableName=table_name,
            Key={"serialNumber": {"S": serial_number}},
        )
    except ClientError:
        return None

    item = response.get("Item")
    if not item:
        return None

    return {
        "serialNumber": item["serialNumber"]["S"],
        "client_id": item["client_id"]["S"],
        "clientName": item["clientName"]["S"],
        "status": item["status"]["S"],
        "issuedAt": item["issuedAt"]["S"],
        "expiry": item["expiry"]["S"],
    }


def _validate_cert_status(metadata: CertMetadata) -> tuple[bool, str]:
    """Validate cert is active and not expired. Returns (valid, reason)."""
    if metadata["status"] != "active":
        return False, f"Certificate status is '{metadata['status']}'"

    now = datetime.now(UTC)
    try:
        expiry = datetime.fromisoformat(metadata["expiry"].replace("Z", "+00:00"))
        if now > expiry:
            return False, "Certificate has expired"
    except ValueError:
        return False, "Invalid expiry date format"

    return True, ""


def _exchange_for_cognito_token(
    domain: str, client_id: str, client_secret: str, scope: str = "mtls-api/access"
) -> CognitoTokenResponse | None:
    """Exchange client credentials for Cognito JWT."""
    token_url = f"https://{domain}/oauth2/token"

    # Build request body
    data = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "scope": scope,
        }
    ).encode("utf-8")

    # Build Authorization header (Basic auth with client_id:client_secret)
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


def handler(event: APIGatewayProxyEventV2, context: LambdaContext) -> APIGatewayProxyResponseV2:
    """Exchange mTLS client certificate for JWT access token.

    Flow:
    1. Extract serialNumber from mTLS client cert
    2. Lookup cert in DynamoDB (validate not revoked/expired)
    3. Exchange for Cognito JWT via client_credentials grant
    4. Return access_token
    """
    serial_number = _extract_serial_number(event)

    if not serial_number:
        return _json_response(
            401,
            {"error": "unauthorized", "message": "Missing client certificate"},
        )

    # Get config from environment
    table_name = os.environ.get("DYNAMODB_TABLE_NAME", "mtls-clients-metadata")
    cognito_domain = os.environ.get("COGNITO_DOMAIN", "")
    cognito_client_id = os.environ.get("COGNITO_CLIENT_ID", "")
    cognito_client_secret = os.environ.get("COGNITO_CLIENT_SECRET", "")

    # DynamoDB lookup
    metadata = _lookup_cert_metadata(serial_number, table_name)
    if not metadata:
        return _json_response(
            404,
            {"error": "not_found", "message": "Certificate not registered"},
        )

    # Validate cert status
    valid, reason = _validate_cert_status(metadata)
    if not valid:
        return _json_response(
            403,
            {"error": "forbidden", "message": reason},
        )

    # Exchange for Cognito token
    if not cognito_domain or not cognito_client_id or not cognito_client_secret:
        return _json_response(
            500,
            {"error": "server_error", "message": "Cognito not configured"},
        )

    token_response = _exchange_for_cognito_token(
        cognito_domain, cognito_client_id, cognito_client_secret
    )
    if not token_response:
        return _json_response(
            500,
            {"error": "server_error", "message": "Failed to obtain token from Cognito"},
        )

    return _json_response(
        200,
        {
            "access_token": token_response["access_token"],
            "token_type": token_response["token_type"],
            "expires_in": token_response["expires_in"],
        },
    )
