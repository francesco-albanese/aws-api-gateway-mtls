"""Tests for authorizer Lambda handler."""

import json
from unittest.mock import patch

import pytest

from src.authorizer._types import APIGatewayAuthorizerEventV2, CertMetadata, LambdaContext
from src.authorizer.cert_extractor import extract_client_cn, extract_serial_number, extract_validity
from src.authorizer.cert_metadata import lookup_cert_metadata
from src.authorizer.cert_validator import validate_cert_status, validate_client_identity
from src.authorizer.handler import handler
from src.authorizer.responses import allow_response, deny_response


class TestCertExtraction:
    """Tests for certificate field extraction."""

    def test_extract_serial_number(self, event_with_mtls_cert: APIGatewayAuthorizerEventV2) -> None:
        assert extract_serial_number(event_with_mtls_cert) == "ABC123DEF456"

    def test_extract_serial_number_missing(self, base_event: APIGatewayAuthorizerEventV2) -> None:
        assert extract_serial_number(base_event) is None

    def test_extract_serial_number_empty_context(
        self, base_event: APIGatewayAuthorizerEventV2
    ) -> None:
        base_event["requestContext"] = {}
        assert extract_serial_number(base_event) is None

    def test_extract_client_cn(self, event_with_mtls_cert: APIGatewayAuthorizerEventV2) -> None:
        assert extract_client_cn(event_with_mtls_cert) == "test-client"

    def test_extract_client_cn_missing(self, base_event: APIGatewayAuthorizerEventV2) -> None:
        assert extract_client_cn(base_event) is None

    def test_extract_client_cn_empty_subject_dn(
        self, event_with_mtls_cert: APIGatewayAuthorizerEventV2
    ) -> None:
        event_with_mtls_cert["requestContext"]["authentication"]["clientCert"]["subjectDN"] = ""  # type: ignore[reportTypedDictNotRequiredAccess]
        assert extract_client_cn(event_with_mtls_cert) is None

    @pytest.mark.parametrize(
        ("subject_dn", "expected_cn"),
        [
            ("CN=first-cn,O=Org,C=US", "first-cn"),
            ("O=Org,C=US,CN=last-cn", "last-cn"),
            ("O=Org,CN=middle-cn,C=US", "middle-cn"),
            ("CN=has-dash,O=Org", "has-dash"),
            ("CN=has_underscore,O=Org", "has_underscore"),
            ("CN=has.dot,O=Org", "has.dot"),
            ("CN=MixedCase,O=Org", "MixedCase"),
        ],
    )
    def test_cn_extraction_variants(
        self,
        event_with_mtls_cert: APIGatewayAuthorizerEventV2,
        subject_dn: str,
        expected_cn: str,
    ) -> None:
        event_with_mtls_cert["requestContext"]["authentication"]["clientCert"]["subjectDN"] = (  # type: ignore[reportTypedDictNotRequiredAccess]
            subject_dn
        )
        assert extract_client_cn(event_with_mtls_cert) == expected_cn

    def test_extract_validity(self, event_with_mtls_cert: APIGatewayAuthorizerEventV2) -> None:
        not_before, not_after = extract_validity(event_with_mtls_cert)
        assert not_before == "2025-01-01T00:00:00Z"
        assert not_after == "2027-01-01T00:00:00Z"

    def test_extract_validity_missing(self, base_event: APIGatewayAuthorizerEventV2) -> None:
        not_before, not_after = extract_validity(base_event)
        assert not_before == ""
        assert not_after == ""


class TestCertMetadataLookup:
    """Tests for DynamoDB cert metadata lookup."""

    def test_lookup_returns_metadata(self, active_cert_metadata: CertMetadata) -> None:
        with patch("src.authorizer.cert_metadata._dynamodb_client") as mock_client:
            mock_client.get_item.return_value = {
                "Item": {
                    "serialNumber": {"S": active_cert_metadata["serialNumber"]},
                    "client_id": {"S": active_cert_metadata["client_id"]},
                    "clientName": {"S": active_cert_metadata["clientName"]},
                    "status": {"S": active_cert_metadata["status"]},
                    "issuedAt": {"S": active_cert_metadata["issuedAt"]},
                    "expiry": {"S": active_cert_metadata["expiry"]},
                }
            }
            from src.authorizer.cert_metadata import lookup_cert_metadata

            result = lookup_cert_metadata("ABC123DEF456", "test-table")
            assert result is not None
            assert result["serialNumber"] == "ABC123DEF456"
            assert result["client_id"] == "test-client"

    def test_lookup_returns_none_not_found(self) -> None:
        with patch("src.authorizer.cert_metadata._dynamodb_client") as mock_client:
            mock_client.get_item.return_value = {}
            from src.authorizer.cert_metadata import lookup_cert_metadata

            result = lookup_cert_metadata("NONEXISTENT", "test-table")
            assert result is None

    def test_lookup_returns_none_on_client_error(self) -> None:
        from botocore.exceptions import ClientError

        with patch("src.authorizer.cert_metadata._dynamodb_client") as mock_client:
            mock_client.get_item.side_effect = ClientError(
                {"Error": {"Code": "ResourceNotFoundException", "Message": "Table not found"}},
                "GetItem",
            )
            from src.authorizer.cert_metadata import lookup_cert_metadata

            result = lookup_cert_metadata("ABC123", "nonexistent-table")
            assert result is None


class TestCertValidation:
    """Tests for certificate validation logic."""

    def test_active_cert_is_valid(self, active_cert_metadata: CertMetadata) -> None:
        is_valid, reason = validate_cert_status(active_cert_metadata)
        assert is_valid is True
        assert reason == ""

    def test_revoked_cert_is_invalid(self, revoked_cert_metadata: CertMetadata) -> None:
        is_valid, reason = validate_cert_status(revoked_cert_metadata)
        assert is_valid is False
        assert "revoked" in reason

    def test_expired_cert_is_invalid(self, expired_cert_metadata: CertMetadata) -> None:
        is_valid, reason = validate_cert_status(expired_cert_metadata)
        assert is_valid is False
        assert "expired" in reason.lower()

    def test_invalid_expiry_format(self, active_cert_metadata: CertMetadata) -> None:
        active_cert_metadata["expiry"] = "not-a-date"
        is_valid, reason = validate_cert_status(active_cert_metadata)
        assert is_valid is False
        assert "format" in reason.lower()

    def test_identity_matches(self, active_cert_metadata: CertMetadata) -> None:
        is_valid, reason = validate_client_identity(active_cert_metadata, "test-client")
        assert is_valid is True
        assert reason == ""

    def test_identity_mismatch(self, active_cert_metadata: CertMetadata) -> None:
        is_valid, reason = validate_client_identity(active_cert_metadata, "wrong-client")
        assert is_valid is False
        assert "wrong-client" in reason


class TestResponseBuilders:
    """Tests for response builder functions."""

    def test_deny_response(self) -> None:
        response = deny_response()
        assert response["isAuthorized"] is False
        assert "context" not in response

    def test_allow_response(self) -> None:
        response = allow_response(
            serial_number="ABC123",
            client_cn="test-client",
            client_id="test-client",
            validity_not_before="2025-01-01T00:00:00Z",
            validity_not_after="2027-01-01T00:00:00Z",
        )
        assert response["isAuthorized"] is True
        ctx = response.get("context", {})
        assert ctx["serialNumber"] == "ABC123"
        assert ctx["clientCN"] == "test-client"
        assert ctx["clientId"] == "test-client"
        assert ctx["validityNotBefore"] == "2025-01-01T00:00:00Z"
        assert ctx["validityNotAfter"] == "2027-01-01T00:00:00Z"


class TestHandler:
    """Tests for main handler function."""

    def test_denies_when_no_table_name(
        self,
        event_with_mtls_cert: APIGatewayAuthorizerEventV2,
        lambda_context: LambdaContext,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("DYNAMODB_TABLE_NAME", raising=False)
        response = handler(event_with_mtls_cert, lambda_context)
        assert response["isAuthorized"] is False

    def test_denies_when_no_serial_number(
        self,
        base_event: APIGatewayAuthorizerEventV2,
        lambda_context: LambdaContext,
    ) -> None:
        response = handler(base_event, lambda_context)
        assert response["isAuthorized"] is False

    def test_denies_when_no_client_cn(
        self,
        event_with_mtls_cert: APIGatewayAuthorizerEventV2,
        lambda_context: LambdaContext,
    ) -> None:
        event_with_mtls_cert["requestContext"]["authentication"]["clientCert"]["subjectDN"] = ""  # type: ignore[reportTypedDictNotRequiredAccess]
        response = handler(event_with_mtls_cert, lambda_context)
        assert response["isAuthorized"] is False

    def test_denies_when_cert_not_in_dynamodb(
        self,
        event_with_mtls_cert: APIGatewayAuthorizerEventV2,
        lambda_context: LambdaContext,
    ) -> None:
        with patch("src.authorizer.handler.lookup_cert_metadata", return_value=None):
            response = handler(event_with_mtls_cert, lambda_context)
        assert response["isAuthorized"] is False

    def test_denies_when_cert_revoked(
        self,
        event_with_mtls_cert: APIGatewayAuthorizerEventV2,
        lambda_context: LambdaContext,
        revoked_cert_metadata: CertMetadata,
    ) -> None:
        with patch(
            "src.authorizer.handler.lookup_cert_metadata", return_value=revoked_cert_metadata
        ):
            response = handler(event_with_mtls_cert, lambda_context)
        assert response["isAuthorized"] is False

    def test_denies_when_cert_expired(
        self,
        event_with_mtls_cert: APIGatewayAuthorizerEventV2,
        lambda_context: LambdaContext,
        expired_cert_metadata: CertMetadata,
    ) -> None:
        with patch(
            "src.authorizer.handler.lookup_cert_metadata", return_value=expired_cert_metadata
        ):
            response = handler(event_with_mtls_cert, lambda_context)
        assert response["isAuthorized"] is False

    def test_denies_when_cn_mismatch(
        self,
        event_with_mtls_cert: APIGatewayAuthorizerEventV2,
        lambda_context: LambdaContext,
        mismatched_cert_metadata: CertMetadata,
    ) -> None:
        with patch(
            "src.authorizer.handler.lookup_cert_metadata", return_value=mismatched_cert_metadata
        ):
            response = handler(event_with_mtls_cert, lambda_context)
        assert response["isAuthorized"] is False

    def test_allows_valid_cert(
        self,
        event_with_mtls_cert: APIGatewayAuthorizerEventV2,
        lambda_context: LambdaContext,
        active_cert_metadata: CertMetadata,
    ) -> None:
        with patch(
            "src.authorizer.handler.lookup_cert_metadata", return_value=active_cert_metadata
        ):
            response = handler(event_with_mtls_cert, lambda_context)
        assert response["isAuthorized"] is True
        ctx = response.get("context", {})
        assert ctx["serialNumber"] == "ABC123DEF456"
        assert ctx["clientCN"] == "test-client"
        assert ctx["clientId"] == "test-client"
        assert ctx["validityNotBefore"] == "2025-01-01T00:00:00Z"
        assert ctx["validityNotAfter"] == "2027-01-01T00:00:00Z"


class TestMalformedDynamoDBItems:
    """Tests for lookup_cert_metadata with malformed DynamoDB items."""

    def test_missing_client_name_key(self) -> None:
        """Item missing required 'clientName' key returns None (KeyError path)."""
        with patch("src.authorizer.cert_metadata._dynamodb_client") as mock_client:
            mock_client.get_item.return_value = {
                "Item": {
                    "serialNumber": {"S": "ABC123"},
                    "client_id": {"S": "test-client"},
                    "status": {"S": "active"},
                    "issuedAt": {"S": "2025-01-01T00:00:00Z"},
                    "expiry": {"S": "2027-01-01T00:00:00Z"},
                    # clientName intentionally missing
                }
            }
            result = lookup_cert_metadata("ABC123", "test-table")
        assert result is None

    def test_wrong_type_structure(self) -> None:
        """Item with wrong type structure returns None (TypeError path)."""
        with patch("src.authorizer.cert_metadata._dynamodb_client") as mock_client:
            mock_client.get_item.return_value = {
                "Item": {
                    "serialNumber": "not-a-dict",  # should be {"S": "..."}
                    "client_id": {"S": "test-client"},
                    "clientName": {"S": "Test Client"},
                    "status": {"S": "active"},
                    "issuedAt": {"S": "2025-01-01T00:00:00Z"},
                    "expiry": {"S": "2027-01-01T00:00:00Z"},
                }
            }
            result = lookup_cert_metadata("ABC123", "test-table")
        assert result is None

    def test_missing_client_id_falls_back_to_empty(self) -> None:
        """Item without client_id falls back to empty string via .get()."""
        with patch("src.authorizer.cert_metadata._dynamodb_client") as mock_client:
            mock_client.get_item.return_value = {
                "Item": {
                    "serialNumber": {"S": "ABC123"},
                    "clientName": {"S": "Test Client"},
                    "status": {"S": "active"},
                    "issuedAt": {"S": "2025-01-01T00:00:00Z"},
                    "expiry": {"S": "2027-01-01T00:00:00Z"},
                    # client_id intentionally missing
                }
            }
            result = lookup_cert_metadata("ABC123", "test-table")
        assert result is not None
        assert result["client_id"] == ""


class TestMissingCNInSubjectDN:
    """Tests for extract_client_cn with missing/empty CN in subjectDN."""

    def test_subject_dn_without_cn_field(
        self, event_with_mtls_cert: APIGatewayAuthorizerEventV2
    ) -> None:
        """subjectDN with no CN= field returns None."""
        event_with_mtls_cert["requestContext"]["authentication"]["clientCert"]["subjectDN"] = (  # type: ignore[reportTypedDictNotRequiredAccess]
            "O=Org,C=US"
        )
        result = extract_client_cn(event_with_mtls_cert)
        assert result is None

    def test_subject_dn_with_empty_cn_value(
        self, event_with_mtls_cert: APIGatewayAuthorizerEventV2
    ) -> None:
        """subjectDN with 'CN=,O=Org' returns empty string."""
        event_with_mtls_cert["requestContext"]["authentication"]["clientCert"]["subjectDN"] = (  # type: ignore[reportTypedDictNotRequiredAccess]
            "CN=,O=Org"
        )
        result = extract_client_cn(event_with_mtls_cert)
        assert result == ""


class TestCertValidatorUnknownStatuses:
    """Tests for validate_cert_status with unusual status values."""

    def test_suspended_status_is_invalid(self, active_cert_metadata: CertMetadata) -> None:
        active_cert_metadata["status"] = "suspended"
        is_valid, reason = validate_cert_status(active_cert_metadata)
        assert is_valid is False
        assert "suspended" in reason

    def test_empty_status_is_invalid(self, active_cert_metadata: CertMetadata) -> None:
        active_cert_metadata["status"] = ""
        is_valid, reason = validate_cert_status(active_cert_metadata)
        assert is_valid is False

    def test_pending_status_is_invalid(self, active_cert_metadata: CertMetadata) -> None:
        active_cert_metadata["status"] = "pending"
        is_valid, reason = validate_cert_status(active_cert_metadata)
        assert is_valid is False
        assert "pending" in reason


class TestStructuredLogOutput:
    """Tests that handler produces expected structured JSON logs."""

    def test_log_on_missing_table_name(
        self,
        event_with_mtls_cert: APIGatewayAuthorizerEventV2,
        lambda_context: LambdaContext,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.delenv("DYNAMODB_TABLE_NAME", raising=False)
        handler(event_with_mtls_cert, lambda_context)
        captured = capsys.readouterr()
        log = json.loads(captured.out.strip())
        assert log["level"] == "error"
        assert "DYNAMODB_TABLE_NAME" in log["message"]

    def test_log_on_missing_serial_number(
        self,
        base_event: APIGatewayAuthorizerEventV2,
        lambda_context: LambdaContext,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        handler(base_event, lambda_context)
        captured = capsys.readouterr()
        log = json.loads(captured.out.strip())
        assert log["level"] == "warn"
        assert "serial" in log["message"].lower()

    def test_log_on_authorization_granted(
        self,
        event_with_mtls_cert: APIGatewayAuthorizerEventV2,
        lambda_context: LambdaContext,
        active_cert_metadata: CertMetadata,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        with patch(
            "src.authorizer.handler.lookup_cert_metadata", return_value=active_cert_metadata
        ):
            handler(event_with_mtls_cert, lambda_context)
        captured = capsys.readouterr()
        log = json.loads(captured.out.strip())
        assert log["level"] == "info"
        assert "granted" in log["message"].lower()
        assert log["serialNumber"] == "ABC123DEF456"
        assert log["clientCN"] == "test-client"

    def test_log_on_cert_not_found(
        self,
        event_with_mtls_cert: APIGatewayAuthorizerEventV2,
        lambda_context: LambdaContext,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        with patch("src.authorizer.handler.lookup_cert_metadata", return_value=None):
            handler(event_with_mtls_cert, lambda_context)
        captured = capsys.readouterr()
        log = json.loads(captured.out.strip())
        assert log["level"] == "warn"
        assert "not found" in log["message"].lower()
        assert log["serialNumber"] == "ABC123DEF456"
