"""Tests for authorizer Lambda handler."""

from unittest.mock import patch

import pytest

from src.authorizer.handler import (
    APIGatewayAuthorizerEventV2,
    LambdaContext,
    _allow_response,
    _deny_response,
    _extract_bearer_token,
    _extract_serial_number,
    handler,
)


class TestExtractBearerToken:
    """Tests for _extract_bearer_token helper."""

    def test_extracts_token_from_lowercase_header(
        self, base_event: APIGatewayAuthorizerEventV2
    ) -> None:
        base_event["headers"] = {"authorization": "Bearer abc123"}
        assert _extract_bearer_token(base_event) == "abc123"

    def test_extracts_token_from_titlecase_header(
        self, base_event: APIGatewayAuthorizerEventV2
    ) -> None:
        base_event["headers"] = {"Authorization": "Bearer xyz789"}
        assert _extract_bearer_token(base_event) == "xyz789"

    def test_returns_none_when_no_bearer_prefix(
        self, base_event: APIGatewayAuthorizerEventV2
    ) -> None:
        base_event["headers"] = {"authorization": "Basic abc123"}
        assert _extract_bearer_token(base_event) is None

    def test_returns_none_when_no_auth_header(
        self, base_event: APIGatewayAuthorizerEventV2
    ) -> None:
        assert _extract_bearer_token(base_event) is None

    def test_returns_none_when_empty_headers(self, base_event: APIGatewayAuthorizerEventV2) -> None:
        base_event["headers"] = {}
        assert _extract_bearer_token(base_event) is None


class TestExtractSerialNumber:
    """Tests for _extract_serial_number helper."""

    def test_extracts_serial_from_mtls_cert(
        self, event_with_mtls_cert: APIGatewayAuthorizerEventV2
    ) -> None:
        assert _extract_serial_number(event_with_mtls_cert) == "ABC123DEF456"

    def test_returns_none_when_no_mtls_cert(self, base_event: APIGatewayAuthorizerEventV2) -> None:
        assert _extract_serial_number(base_event) is None

    def test_returns_none_when_empty_request_context(
        self, base_event: APIGatewayAuthorizerEventV2
    ) -> None:
        base_event["requestContext"] = {}
        assert _extract_serial_number(base_event) is None


class TestResponseBuilders:
    """Tests for response builder functions."""

    def test_deny_response_structure(self) -> None:
        response = _deny_response()
        assert response["isAuthorized"] is False
        assert "context" not in response

    def test_allow_response_structure(self) -> None:
        response = _allow_response(
            serial_number="ABC123",
            client_id="test-client",
            scopes=["mtls-api/access", "read"],
        )
        assert response["isAuthorized"] is True
        context = response.get("context", {})
        assert context["serialNumber"] == "ABC123"
        assert context["clientId"] == "test-client"
        assert context["scopes"] == "mtls-api/access,read"

    def test_allow_response_empty_scopes(self) -> None:
        response = _allow_response(
            serial_number="ABC123",
            client_id="test-client",
            scopes=[],
        )
        context = response.get("context", {})
        assert context["scopes"] == ""


class TestHandler:
    """Tests for main handler function."""

    def test_denies_when_no_token(
        self,
        base_event: APIGatewayAuthorizerEventV2,
        lambda_context: LambdaContext,
    ) -> None:
        response = handler(base_event, lambda_context)
        assert response["isAuthorized"] is False

    def test_denies_when_missing_cognito_config(
        self,
        base_event: APIGatewayAuthorizerEventV2,
        lambda_context: LambdaContext,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("COGNITO_USER_POOL_ID", raising=False)
        base_event["headers"] = {"authorization": "Bearer test-token"}
        response = handler(base_event, lambda_context)
        assert response["isAuthorized"] is False

    def test_denies_when_jwt_validation_fails(
        self,
        event_with_mtls_cert: APIGatewayAuthorizerEventV2,
        lambda_context: LambdaContext,
    ) -> None:
        event_with_mtls_cert["headers"] = {"authorization": "Bearer invalid.jwt.token"}
        with patch("src.authorizer.handler._validate_jwt", return_value=None):
            response = handler(event_with_mtls_cert, lambda_context)
        assert response["isAuthorized"] is False

    def test_allows_when_jwt_valid(
        self,
        event_with_mtls_cert: APIGatewayAuthorizerEventV2,
        lambda_context: LambdaContext,
    ) -> None:
        event_with_mtls_cert["headers"] = {"authorization": "Bearer valid.jwt.token"}
        mock_claims = {
            "client_id": "test-client-id",
            "scope": "mtls-api/access",
            "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_testpool",
        }
        with patch("src.authorizer.handler._validate_jwt", return_value=mock_claims):
            response = handler(event_with_mtls_cert, lambda_context)
        assert response["isAuthorized"] is True
        context = response.get("context", {})
        assert context["serialNumber"] == "ABC123DEF456"
        assert context["clientId"] == "test-client-id"
        assert context["scopes"] == "mtls-api/access"

    def test_allows_without_mtls_cert(
        self,
        base_event: APIGatewayAuthorizerEventV2,
        lambda_context: LambdaContext,
    ) -> None:
        base_event["headers"] = {"authorization": "Bearer valid.jwt.token"}
        mock_claims = {
            "client_id": "test-client-id",
            "scope": "mtls-api/access",
        }
        with patch("src.authorizer.handler._validate_jwt", return_value=mock_claims):
            response = handler(base_event, lambda_context)
        assert response["isAuthorized"] is True
        context = response.get("context", {})
        assert context["serialNumber"] == ""

    def test_handles_multiple_scopes(
        self,
        event_with_mtls_cert: APIGatewayAuthorizerEventV2,
        lambda_context: LambdaContext,
    ) -> None:
        event_with_mtls_cert["headers"] = {"authorization": "Bearer valid.jwt.token"}
        mock_claims = {
            "client_id": "test-client-id",
            "scope": "mtls-api/access read write",
        }
        with patch("src.authorizer.handler._validate_jwt", return_value=mock_claims):
            response = handler(event_with_mtls_cert, lambda_context)
        context = response.get("context", {})
        assert context["scopes"] == "mtls-api/access,read,write"
