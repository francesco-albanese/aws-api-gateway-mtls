"""Utility functions for token lambda."""

import json

from .types import APIGatewayProxyEventV2, APIGatewayProxyResponseV2


def extract_serial_number(event: APIGatewayProxyEventV2) -> str | None:
    """Extract certificate serial number from mTLS context.

    Args:
        event: API Gateway event

    Returns:
        Serial number if present, None otherwise
    """
    request_context = event.get("requestContext", {})
    authentication = request_context.get("authentication", {})
    client_cert = authentication.get("clientCert", {})
    return client_cert.get("serialNumber")


def json_response(status_code: int, body: dict) -> APIGatewayProxyResponseV2:
    """Build JSON API Gateway response.

    Args:
        status_code: HTTP status code
        body: Response body dict

    Returns:
        API Gateway response
    """
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }
