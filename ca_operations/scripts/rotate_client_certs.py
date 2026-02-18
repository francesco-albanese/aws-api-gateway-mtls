#!/usr/bin/env python3
"""Rotate client certificates — re-issue individual or all active client certs."""

import argparse
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.x509 import CertificateSigningRequestBuilder

from ca_operations.lib.cert_utils import (
    deserialize_certificate,
    deserialize_private_key,
    extract_certificate_metadata,
    serialize_certificate,
    serialize_private_key,
)
from ca_operations.lib.certificate_builder import CertificateBuilder
from ca_operations.lib.config import CAConfig
from ca_operations.lib.dynamodb_client import DynamoDBClient
from ca_operations.lib.logging_config import LOGGER
from ca_operations.lib.models import ClientRotationResult
from ca_operations.lib.ssm_client import SSMClient

ENVIRONMENTS = ["sandbox", "staging", "uat", "production"]
PROJECT_NAME = "apigw-mtls"


def rotate_client_certs(
    environment: str,
    dynamodb_table: str,
    ssm_client: SSMClient,
    dynamodb_client: DynamoDBClient,
    config: CAConfig,
    output_dir: Path,
    project_name: str = PROJECT_NAME,
    client_id_filter: str | None = None,
    dry_run: bool = False,
) -> ClientRotationResult:
    """Rotate client certificates using the current intermediate CA.

    1. Fetch intermediate CA from SSM
    2. Query active certs from DynamoDB
    3. Filter by client_id if specified
    4. For each client: fetch key from SSM, build CSR, issue new cert,
       rotate in DynamoDB, update SSM, write artifacts

    Args:
        environment: Target environment
        dynamodb_table: DynamoDB table name
        ssm_client: SSM client instance
        dynamodb_client: DynamoDB client instance
        config: CA configuration
        output_dir: Directory for output artifacts
        project_name: Project name for SSM paths
        client_id_filter: Optional client ID to rotate (None = all)
        dry_run: If True, don't write to AWS

    Returns:
        ClientRotationResult with counts and details
    """
    # Fetch intermediate CA from SSM
    intermediate_key_pem, intermediate_cert_pem = ssm_client.get_intermediate_ca(
        project_name, environment
    )
    intermediate_key = deserialize_private_key(intermediate_key_pem)
    intermediate_cert = deserialize_certificate(intermediate_cert_pem)
    LOGGER.info("Fetched intermediate CA from SSM")

    # Query active certificates
    active_certs = dynamodb_client.get_active_certificates(dynamodb_table)
    LOGGER.info("Found %d active certificates", len(active_certs))

    # Filter by client_id if specified
    if client_id_filter:
        active_certs = [
            c
            for c in active_certs
            if (c.get("client_id") or c.get("clientName")) == client_id_filter
        ]
        LOGGER.info("Filtered to %d certs for client_id=%s", len(active_certs), client_id_filter)

    if not active_certs:
        LOGGER.info("No active certificates to rotate")
        return ClientRotationResult(
            reissued_count=0, failed_count=0, reissued_serials=[], failed_client_ids=[]
        )

    reissued_serials: list[str] = []
    failed_client_ids: list[str] = []

    for cert_metadata in active_certs:
        old_serial = cert_metadata.get("serialNumber")
        client_name = cert_metadata.get("clientName")
        if not old_serial or not client_name:
            LOGGER.warning("Skipping cert with missing serialNumber/clientName: %s", cert_metadata)
            failed_client_ids.append(client_name or "unknown")
            continue

        client_id = cert_metadata.get("client_id") or client_name

        try:
            # Fetch existing client key + cert from SSM
            client_key_pem, _old_cert_pem = ssm_client.get_client_certificate(
                project_name, environment, client_id
            )
            client_key = deserialize_private_key(client_key_pem)
            old_cert = deserialize_certificate(_old_cert_pem)

            # Build CSR from existing key + existing cert subject
            csr = (
                CertificateSigningRequestBuilder()
                .subject_name(old_cert.subject)
                .sign(client_key, hashes.SHA256())
            )

            # Issue new client certificate
            new_cert = CertificateBuilder.build_client_certificate(
                csr=csr,
                issuer_cert=intermediate_cert,
                issuer_key=intermediate_key,
                validity_days=config.client_validity_days,
            )

            new_cert_pem = serialize_certificate(new_cert)
            new_metadata = extract_certificate_metadata(new_cert, client_id=client_id)
            new_serial = new_metadata["serialNumber"]

            if not dry_run:
                if not dynamodb_client.rotate_certificate(dynamodb_table, old_serial, new_metadata):
                    raise RuntimeError(f"Failed to rotate cert {old_serial} -> {new_serial}")

                ssm_client.put_client_certificate(
                    project_name, environment, client_id, client_key_pem, new_cert_pem
                )

            # Write artifacts for audit
            client_output_dir = output_dir / client_id
            client_output_dir.mkdir(parents=True, exist_ok=True)
            (client_output_dir / "client.pem").write_bytes(new_cert_pem)
            (client_output_dir / "client.key").write_bytes(serialize_private_key(client_key))
            (client_output_dir / "metadata.json").write_text(json.dumps(new_metadata, indent=2))

            reissued_serials.append(new_serial)
            LOGGER.info("Rotated %s: %s -> %s", client_id, old_serial[:20], new_serial[:20])

        except Exception as e:
            LOGGER.error("Failed to rotate %s: %s", client_id, str(e))
            failed_client_ids.append(client_id)

    return ClientRotationResult(
        reissued_count=len(reissued_serials),
        failed_count=len(failed_client_ids),
        reissued_serials=reissued_serials,
        failed_client_ids=failed_client_ids,
    )


def main() -> int:
    """Run client certificate rotation.

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    parser = argparse.ArgumentParser(
        description="Rotate client certificates — re-issue individual or all active certs"
    )
    parser.add_argument(
        "--environment",
        choices=ENVIRONMENTS,
        required=True,
        help="Target environment",
    )
    parser.add_argument(
        "--client-id",
        default=None,
        help="Specific client ID to rotate",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        dest="rotate_all",
        help="Rotate all active client certificates",
    )
    parser.add_argument(
        "--project-name",
        default=PROJECT_NAME,
        help=f"Project name for SSM paths (default: {PROJECT_NAME})",
    )
    parser.add_argument(
        "--dynamodb-table",
        default="mtls-clients-metadata",
        help="DynamoDB table name (default: mtls-clients-metadata)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Output directory for artifacts (default: ca_operations/output/{env}/client-rotation)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview rotation without making AWS changes",
    )
    args = parser.parse_args()

    # Validate mutually exclusive args: exactly one of --client-id or --all
    if not args.client_id and not args.rotate_all:
        parser.error("one of --client-id or --all is required")
    if args.client_id and args.rotate_all:
        parser.error("--client-id and --all are mutually exclusive")

    if not args.output_dir:
        args.output_dir = Path(f"ca_operations/output/{args.environment}/client-rotation")

    try:
        ssm_client = SSMClient()
        dynamodb_client = DynamoDBClient()
        config = CAConfig()

        args.output_dir.mkdir(parents=True, exist_ok=True)

        if args.dry_run:
            LOGGER.info("DRY RUN - no AWS changes will be made")

        result = rotate_client_certs(
            environment=args.environment,
            dynamodb_table=args.dynamodb_table,
            ssm_client=ssm_client,
            dynamodb_client=dynamodb_client,
            config=config,
            output_dir=args.output_dir,
            project_name=args.project_name,
            client_id_filter=args.client_id,
            dry_run=args.dry_run,
        )

        LOGGER.info("Client rotation complete:")
        LOGGER.info("  Re-issued: %d", result.reissued_count)
        LOGGER.info("  Failed: %d", result.failed_count)

        if result.failed_count > 0:
            LOGGER.warning("Failed clients: %s", result.failed_client_ids)
            return 1

        return 0

    except Exception as e:
        LOGGER.error("Client rotation failed: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
