"""Tests for token lambda handler."""

import json
import os
from typing import Any
from unittest.mock import MagicMock, patch

from src.token.handler import (
    APIGatewayProxyEventV2,
    APIGatewayProxyResponseV2,
    CertMetadata,
    LambdaContext,
    handler,
)


def parse_response_body(response: APIGatewayProxyResponseV2) -> dict[str, Any]:
    """Parse response body, asserting it exists."""
    body = response.get("body")
    assert body is not None, "Response body should not be None"
    return json.loads(body)


class TestTokenValidCertInDynamoDB:
    """Test handler with valid cert in DynamoDB - token issued."""

    def test_returns_200_status(
        self,
        event_with_serial_number: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
        active_cert_metadata: CertMetadata,
        mock_env_vars: dict[str, str],
        mock_cognito_token_response: dict[str, Any],
        mock_dynamodb_client: MagicMock,
    ) -> None:
        """Handler returns 200 when cert is valid and token issued."""
        mock_dynamodb_client.get_item.return_value = {
            "Item": {
                "serialNumber": {"S": active_cert_metadata["serialNumber"]},
                "client_id": {"S": active_cert_metadata["client_id"]},
                "clientName": {"S": active_cert_metadata["clientName"]},
                "status": {"S": active_cert_metadata["status"]},
                "issuedAt": {"S": active_cert_metadata["issuedAt"]},
                "expiry": {"S": active_cert_metadata["expiry"]},
            }
        }

        with (
            patch.dict(os.environ, mock_env_vars),
            patch(
                "src.token.handler._get_dynamodb_client",
                return_value=mock_dynamodb_client,
            ),
            patch(
                "src.token.handler._exchange_for_cognito_token",
                return_value=mock_cognito_token_response,
            ),
        ):
            response = handler(event_with_serial_number, mock_context)
            assert response["statusCode"] == 200

    def test_returns_access_token(
        self,
        event_with_serial_number: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
        active_cert_metadata: CertMetadata,
        mock_env_vars: dict[str, str],
        mock_cognito_token_response: dict[str, Any],
        mock_dynamodb_client: MagicMock,
    ) -> None:
        """Handler returns access_token in response body."""
        mock_dynamodb_client.get_item.return_value = {
            "Item": {
                "serialNumber": {"S": active_cert_metadata["serialNumber"]},
                "client_id": {"S": active_cert_metadata["client_id"]},
                "clientName": {"S": active_cert_metadata["clientName"]},
                "status": {"S": active_cert_metadata["status"]},
                "issuedAt": {"S": active_cert_metadata["issuedAt"]},
                "expiry": {"S": active_cert_metadata["expiry"]},
            }
        }

        with (
            patch.dict(os.environ, mock_env_vars),
            patch(
                "src.token.handler._get_dynamodb_client",
                return_value=mock_dynamodb_client,
            ),
            patch(
                "src.token.handler._exchange_for_cognito_token",
                return_value=mock_cognito_token_response,
            ),
        ):
            response = handler(event_with_serial_number, mock_context)
            body = parse_response_body(response)
            assert body["access_token"] == mock_cognito_token_response["access_token"]
            assert body["token_type"] == "Bearer"
            assert body["expires_in"] == 3600


class TestTokenCertNotFound:
    """Test handler when cert is not found in DynamoDB - 404 response."""

    def test_returns_404_when_cert_not_found(
        self,
        event_with_serial_number: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
        mock_env_vars: dict[str, str],
        mock_dynamodb_client: MagicMock,
    ) -> None:
        """Handler returns 404 when cert not in DynamoDB."""
        mock_dynamodb_client.get_item.return_value = {}  # No Item

        with (
            patch.dict(os.environ, mock_env_vars),
            patch(
                "src.token.handler._get_dynamodb_client",
                return_value=mock_dynamodb_client,
            ),
        ):
            response = handler(event_with_serial_number, mock_context)
            assert response["statusCode"] == 404

    def test_returns_not_found_error(
        self,
        event_with_serial_number: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
        mock_env_vars: dict[str, str],
        mock_dynamodb_client: MagicMock,
    ) -> None:
        """Handler returns not_found error message."""
        mock_dynamodb_client.get_item.return_value = {}

        with (
            patch.dict(os.environ, mock_env_vars),
            patch(
                "src.token.handler._get_dynamodb_client",
                return_value=mock_dynamodb_client,
            ),
        ):
            response = handler(event_with_serial_number, mock_context)
            body = parse_response_body(response)
            assert body["error"] == "not_found"
            assert "not registered" in body["message"].lower()


class TestTokenCertRevoked:
    """Test handler when cert is revoked - 403 response."""

    def test_returns_403_when_cert_revoked(
        self,
        event_with_serial_number: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
        revoked_cert_metadata: CertMetadata,
        mock_env_vars: dict[str, str],
        mock_dynamodb_client: MagicMock,
    ) -> None:
        """Handler returns 403 when cert status is revoked."""
        mock_dynamodb_client.get_item.return_value = {
            "Item": {
                "serialNumber": {"S": revoked_cert_metadata["serialNumber"]},
                "client_id": {"S": revoked_cert_metadata["client_id"]},
                "clientName": {"S": revoked_cert_metadata["clientName"]},
                "status": {"S": revoked_cert_metadata["status"]},
                "issuedAt": {"S": revoked_cert_metadata["issuedAt"]},
                "expiry": {"S": revoked_cert_metadata["expiry"]},
            }
        }

        with (
            patch.dict(os.environ, mock_env_vars),
            patch(
                "src.token.handler._get_dynamodb_client",
                return_value=mock_dynamodb_client,
            ),
        ):
            response = handler(event_with_serial_number, mock_context)
            assert response["statusCode"] == 403

    def test_returns_forbidden_error(
        self,
        event_with_serial_number: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
        revoked_cert_metadata: CertMetadata,
        mock_env_vars: dict[str, str],
        mock_dynamodb_client: MagicMock,
    ) -> None:
        """Handler returns forbidden error with status reason."""
        mock_dynamodb_client.get_item.return_value = {
            "Item": {
                "serialNumber": {"S": revoked_cert_metadata["serialNumber"]},
                "client_id": {"S": revoked_cert_metadata["client_id"]},
                "clientName": {"S": revoked_cert_metadata["clientName"]},
                "status": {"S": revoked_cert_metadata["status"]},
                "issuedAt": {"S": revoked_cert_metadata["issuedAt"]},
                "expiry": {"S": revoked_cert_metadata["expiry"]},
            }
        }

        with (
            patch.dict(os.environ, mock_env_vars),
            patch(
                "src.token.handler._get_dynamodb_client",
                return_value=mock_dynamodb_client,
            ),
        ):
            response = handler(event_with_serial_number, mock_context)
            body = parse_response_body(response)
            assert body["error"] == "forbidden"
            assert "revoked" in body["message"].lower()


class TestTokenCertExpired:
    """Test handler when cert is expired - 403 response."""

    def test_returns_403_when_cert_expired(
        self,
        event_with_serial_number: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
        expired_cert_metadata: CertMetadata,
        mock_env_vars: dict[str, str],
        mock_dynamodb_client: MagicMock,
    ) -> None:
        """Handler returns 403 when cert has expired."""
        mock_dynamodb_client.get_item.return_value = {
            "Item": {
                "serialNumber": {"S": expired_cert_metadata["serialNumber"]},
                "client_id": {"S": expired_cert_metadata["client_id"]},
                "clientName": {"S": expired_cert_metadata["clientName"]},
                "status": {"S": expired_cert_metadata["status"]},
                "issuedAt": {"S": expired_cert_metadata["issuedAt"]},
                "expiry": {"S": expired_cert_metadata["expiry"]},
            }
        }

        with (
            patch.dict(os.environ, mock_env_vars),
            patch(
                "src.token.handler._get_dynamodb_client",
                return_value=mock_dynamodb_client,
            ),
        ):
            response = handler(event_with_serial_number, mock_context)
            assert response["statusCode"] == 403

    def test_returns_expired_message(
        self,
        event_with_serial_number: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
        expired_cert_metadata: CertMetadata,
        mock_env_vars: dict[str, str],
        mock_dynamodb_client: MagicMock,
    ) -> None:
        """Handler returns message about expiry."""
        mock_dynamodb_client.get_item.return_value = {
            "Item": {
                "serialNumber": {"S": expired_cert_metadata["serialNumber"]},
                "client_id": {"S": expired_cert_metadata["client_id"]},
                "clientName": {"S": expired_cert_metadata["clientName"]},
                "status": {"S": expired_cert_metadata["status"]},
                "issuedAt": {"S": expired_cert_metadata["issuedAt"]},
                "expiry": {"S": expired_cert_metadata["expiry"]},
            }
        }

        with (
            patch.dict(os.environ, mock_env_vars),
            patch(
                "src.token.handler._get_dynamodb_client",
                return_value=mock_dynamodb_client,
            ),
        ):
            response = handler(event_with_serial_number, mock_context)
            body = parse_response_body(response)
            assert body["error"] == "forbidden"
            assert "expired" in body["message"].lower()


class TestTokenCognitoErrorHandling:
    """Test handler when Cognito API fails - 500 response."""

    def test_returns_500_when_cognito_fails(
        self,
        event_with_serial_number: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
        active_cert_metadata: CertMetadata,
        mock_env_vars: dict[str, str],
        mock_dynamodb_client: MagicMock,
    ) -> None:
        """Handler returns 500 when Cognito token exchange fails."""
        mock_dynamodb_client.get_item.return_value = {
            "Item": {
                "serialNumber": {"S": active_cert_metadata["serialNumber"]},
                "client_id": {"S": active_cert_metadata["client_id"]},
                "clientName": {"S": active_cert_metadata["clientName"]},
                "status": {"S": active_cert_metadata["status"]},
                "issuedAt": {"S": active_cert_metadata["issuedAt"]},
                "expiry": {"S": active_cert_metadata["expiry"]},
            }
        }

        with (
            patch.dict(os.environ, mock_env_vars),
            patch(
                "src.token.handler._get_dynamodb_client",
                return_value=mock_dynamodb_client,
            ),
            patch(
                "src.token.handler._exchange_for_cognito_token",
                return_value=None,  # Cognito failure
            ),
        ):
            response = handler(event_with_serial_number, mock_context)
            assert response["statusCode"] == 500

    def test_returns_server_error(
        self,
        event_with_serial_number: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
        active_cert_metadata: CertMetadata,
        mock_env_vars: dict[str, str],
        mock_dynamodb_client: MagicMock,
    ) -> None:
        """Handler returns server_error with Cognito message."""
        mock_dynamodb_client.get_item.return_value = {
            "Item": {
                "serialNumber": {"S": active_cert_metadata["serialNumber"]},
                "client_id": {"S": active_cert_metadata["client_id"]},
                "clientName": {"S": active_cert_metadata["clientName"]},
                "status": {"S": active_cert_metadata["status"]},
                "issuedAt": {"S": active_cert_metadata["issuedAt"]},
                "expiry": {"S": active_cert_metadata["expiry"]},
            }
        }

        with (
            patch.dict(os.environ, mock_env_vars),
            patch(
                "src.token.handler._get_dynamodb_client",
                return_value=mock_dynamodb_client,
            ),
            patch(
                "src.token.handler._exchange_for_cognito_token",
                return_value=None,
            ),
        ):
            response = handler(event_with_serial_number, mock_context)
            body = parse_response_body(response)
            assert body["error"] == "server_error"
            assert "cognito" in body["message"].lower()


class TestTokenMissingClientCert:
    """Test handler when client cert is missing - 401 response."""

    def test_returns_401_without_cert(
        self,
        event_without_serial_number: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        """Handler returns 401 when no client cert present."""
        response = handler(event_without_serial_number, mock_context)
        assert response["statusCode"] == 401

    def test_returns_unauthorized_error(
        self,
        event_without_serial_number: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        """Handler returns unauthorized error message."""
        response = handler(event_without_serial_number, mock_context)
        body = parse_response_body(response)
        assert body["error"] == "unauthorized"
        assert "missing" in body["message"].lower()

    def test_empty_event_returns_401(
        self,
        event_empty: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
    ) -> None:
        """Handler returns 401 for empty event."""
        response = handler(event_empty, mock_context)
        assert response["statusCode"] == 401


class TestTokenCognitoMisconfigured:
    """Test handler when Cognito is not configured - 500 response."""

    def test_returns_500_when_cognito_not_configured(
        self,
        event_with_serial_number: APIGatewayProxyEventV2,
        mock_context: LambdaContext,
        active_cert_metadata: CertMetadata,
        mock_dynamodb_client: MagicMock,
    ) -> None:
        """Handler returns 500 when Cognito env vars missing."""
        mock_dynamodb_client.get_item.return_value = {
            "Item": {
                "serialNumber": {"S": active_cert_metadata["serialNumber"]},
                "client_id": {"S": active_cert_metadata["client_id"]},
                "clientName": {"S": active_cert_metadata["clientName"]},
                "status": {"S": active_cert_metadata["status"]},
                "issuedAt": {"S": active_cert_metadata["issuedAt"]},
                "expiry": {"S": active_cert_metadata["expiry"]},
            }
        }

        # Missing Cognito env vars
        env_vars = {"DYNAMODB_TABLE_NAME": "test-table"}

        with (
            patch.dict(os.environ, env_vars, clear=True),
            patch(
                "src.token.handler._get_dynamodb_client",
                return_value=mock_dynamodb_client,
            ),
        ):
            response = handler(event_with_serial_number, mock_context)
            assert response["statusCode"] == 500
            body = parse_response_body(response)
            assert body["error"] == "server_error"
            assert "configured" in body["message"].lower()
