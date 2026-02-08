"""Custom authorizer Lambda - validates mTLS client cert via DynamoDB."""

import json
import os

from authorizer.cert_extractor import extract_client_cn, extract_serial_number, extract_validity
from authorizer.cert_metadata import lookup_cert_metadata
from authorizer.cert_validator import validate_cert_status, validate_client_identity
from authorizer.responses import allow_response, deny_response
from authorizer.types import APIGatewayAuthorizerEventV2, AuthorizerResponse, LambdaContext


def _log(level: str, message: str, **kwargs) -> None:
    """Structured JSON log."""
    print(json.dumps({"level": level, "message": message, **kwargs}, default=str))


def handler(event: APIGatewayAuthorizerEventV2, context: LambdaContext) -> AuthorizerResponse:
    """Validate mTLS client cert against DynamoDB metadata.

    Flow:
    1. Extract serial number and CN from mTLS cert context
    2. Lookup cert metadata in DynamoDB
    3. Validate cert status (active, not expired)
    4. Validate client identity (CN matches client_id)
    5. Return allow/deny with cert context
    """
    table_name = os.environ.get("DYNAMODB_TABLE_NAME", "")
    if not table_name:
        _log("error", "DYNAMODB_TABLE_NAME not configured")
        return deny_response()

    # Extract cert info from mTLS context
    serial_number = extract_serial_number(event)
    if not serial_number:
        _log("warn", "No serial number in mTLS context")
        return deny_response()

    client_cn = extract_client_cn(event)
    if not client_cn:
        _log("warn", "No client CN in mTLS context")
        return deny_response()

    validity_not_before, validity_not_after = extract_validity(event)

    # Lookup cert in DynamoDB
    metadata = lookup_cert_metadata(serial_number, table_name)
    if not metadata:
        _log("warn", "Certificate not found in DynamoDB", serialNumber=serial_number)
        return deny_response()

    # Validate cert status
    is_valid, reason = validate_cert_status(metadata)
    if not is_valid:
        _log("warn", "Certificate validation failed", serialNumber=serial_number, reason=reason)
        return deny_response()

    # Validate client identity
    is_valid, reason = validate_client_identity(metadata, client_cn)
    if not is_valid:
        _log("warn", "Client identity mismatch", serialNumber=serial_number, reason=reason)
        return deny_response()

    _log("info", "Authorization granted", serialNumber=serial_number, clientCN=client_cn)
    return allow_response(
        serial_number=serial_number,
        client_cn=client_cn,
        client_id=metadata["client_id"],
        validity_not_before=validity_not_before,
        validity_not_after=validity_not_after,
    )
