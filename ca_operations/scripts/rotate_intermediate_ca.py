#!/usr/bin/env python3
"""Rotate Intermediate CA - re-issue active client certs and update truststore."""

import argparse
import json
import sys
from pathlib import Path

from ca_operations.lib.cert_utils import (
    create_truststore_bundle,
    deserialize_certificate,
    deserialize_private_key,
    extract_certificate_metadata,
    serialize_certificate,
)
from ca_operations.lib.certificate_builder import CertificateBuilder
from ca_operations.lib.config import CAConfig
from ca_operations.lib.dynamodb_client import DynamoDBClient
from ca_operations.lib.logging_config import LOGGER
from ca_operations.lib.models import RotationResult
from ca_operations.lib.s3_client import S3Client
from ca_operations.lib.ssm_client import SSMClient

ENVIRONMENTS = ["sandbox", "staging", "uat", "production"]
PROJECT_NAME = "apigw-mtls"


def rotate_intermediate_ca(
    environment: str,
    new_intermediate_key_pem: bytes,
    new_intermediate_cert_pem: bytes,
    root_cert_pem: bytes,
    dynamodb_table: str,
    s3_bucket: str,
    ssm_client: SSMClient,
    dynamodb_client: DynamoDBClient,
    s3_client: S3Client,
    config: CAConfig,
    output_dir: Path,
    dry_run: bool = False,
) -> RotationResult:
    """Perform intermediate CA rotation.

    1. Query active certs from DynamoDB
    2. Fetch each client cert from SSM
    3. Re-issue with new intermediate CA
    4. Update DynamoDB: revoke old, add new
    5. Update S3 truststore

    Args:
        environment: Target environment
        new_intermediate_key_pem: New intermediate CA private key PEM
        new_intermediate_cert_pem: New intermediate CA certificate PEM
        root_cert_pem: Root CA certificate PEM (for truststore)
        dynamodb_table: DynamoDB table name
        s3_bucket: S3 bucket for truststore
        ssm_client: SSM client instance
        dynamodb_client: DynamoDB client instance
        s3_client: S3 client instance
        config: CA configuration
        output_dir: Directory for output artifacts
        dry_run: If True, don't write to AWS

    Returns:
        RotationResult with counts and details
    """
    new_intermediate_key = deserialize_private_key(new_intermediate_key_pem)
    new_intermediate_cert = deserialize_certificate(new_intermediate_cert_pem)

    new_intermediate_metadata = extract_certificate_metadata(new_intermediate_cert)
    new_intermediate_serial = new_intermediate_metadata["serialNumber"]

    LOGGER.info("Starting rotation with new intermediate CA: %s", new_intermediate_serial)

    active_certs = dynamodb_client.get_active_certificates(dynamodb_table)
    LOGGER.info("Found %d active certificates to re-issue", len(active_certs))

    reissued_serials: list[str] = []
    failed_client_ids: list[str] = []
    revoked_count = 0

    # Process each active certificate
    for cert_metadata in active_certs:
        client_id = cert_metadata.get("client_id") or cert_metadata["clientName"]
        old_serial = cert_metadata["serialNumber"]

        try:
            # Fetch existing client cert from SSM
            cert_path = f"/{PROJECT_NAME}/{environment}/clients/{client_id}/certificate"
            response = ssm_client.client.get_parameter(Name=cert_path, WithDecryption=False)
            old_cert_pem = response["Parameter"]["Value"].encode("utf-8")
            old_cert = deserialize_certificate(old_cert_pem)

            # Re-issue certificate with new intermediate
            new_cert = CertificateBuilder.reissue_client_certificate(
                original_cert=old_cert,
                new_issuer_cert=new_intermediate_cert,
                new_issuer_key=new_intermediate_key,
                validity_days=config.client_validity_days,
            )

            new_cert_pem = serialize_certificate(new_cert)
            new_metadata = extract_certificate_metadata(new_cert, client_id=client_id)
            new_serial = new_metadata["serialNumber"]

            if not dry_run:
                ssm_client.client.put_parameter(
                    Name=cert_path,
                    Value=new_cert_pem.decode("utf-8"),
                    Type="String",
                    Overwrite=True,
                )

                if not dynamodb_client.revoke_certificate(dynamodb_table, old_serial):
                    raise RuntimeError(f"Failed to revoke old cert {old_serial}")
                revoked_count += 1

                if not dynamodb_client.put_certificate_metadata(dynamodb_table, new_metadata):
                    raise RuntimeError(f"Failed to insert new cert metadata {new_serial}")

            # Write to output dir for audit
            client_output_dir = output_dir / client_id
            client_output_dir.mkdir(parents=True, exist_ok=True)
            (client_output_dir / "client.pem").write_bytes(new_cert_pem)
            (client_output_dir / "metadata.json").write_text(json.dumps(new_metadata, indent=2))

            reissued_serials.append(new_serial)
            LOGGER.info("Re-issued %s: %s -> %s", client_id, old_serial[:20], new_serial[:20])

        except Exception as e:
            LOGGER.error("Failed to re-issue %s: %s", client_id, str(e))
            failed_client_ids.append(client_id)

    truststore_bundle = create_truststore_bundle(new_intermediate_cert_pem, root_cert_pem)
    version_id = ""

    if not dry_run:
        version_id = s3_client.upload_truststore(s3_bucket, truststore_bundle)
        LOGGER.info("Updated truststore in S3: %s (version: %s)", s3_bucket, version_id)

    truststore_path = output_dir / "truststore.pem"
    truststore_path.write_bytes(truststore_bundle)

    return RotationResult(
        reissued_count=len(reissued_serials),
        revoked_count=revoked_count,
        failed_count=len(failed_client_ids),
        new_intermediate_serial=new_intermediate_serial,
        truststore_version_id=version_id,
        reissued_serials=reissued_serials,
        failed_client_ids=failed_client_ids,
    )


def main() -> int:
    """Run intermediate CA rotation.

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    parser = argparse.ArgumentParser(
        description="Rotate intermediate CA - re-issue all active client certs"
    )
    parser.add_argument(
        "--environment",
        choices=ENVIRONMENTS,
        required=True,
        help="Target environment",
    )
    parser.add_argument(
        "--new-intermediate-key",
        type=Path,
        required=True,
        help="Path to new intermediate CA private key PEM",
    )
    parser.add_argument(
        "--new-intermediate-cert",
        type=Path,
        required=True,
        help="Path to new intermediate CA certificate PEM",
    )
    parser.add_argument(
        "--root-cert",
        type=Path,
        required=True,
        help="Path to root CA certificate PEM",
    )
    parser.add_argument(
        "--dynamodb-table",
        default="mtls-clients-metadata",
        help="DynamoDB table name (default: mtls-clients-metadata)",
    )
    parser.add_argument(
        "--s3-bucket",
        required=True,
        help="S3 bucket for truststore",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Output directory for artifacts (default: ca_operations/output/{env}/rotation)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview rotation without making AWS changes",
    )
    args = parser.parse_args()

    if not args.output_dir:
        args.output_dir = Path(f"ca_operations/output/{args.environment}/rotation")

    for path_arg in [args.new_intermediate_key, args.new_intermediate_cert, args.root_cert]:
        if not path_arg.exists():
            LOGGER.error("File not found: %s", path_arg)
            return 1

    try:
        new_intermediate_key_pem = args.new_intermediate_key.read_bytes()
        new_intermediate_cert_pem = args.new_intermediate_cert.read_bytes()
        root_cert_pem = args.root_cert.read_bytes()

        ssm_client = SSMClient()
        dynamodb_client = DynamoDBClient()
        s3_client = S3Client()
        config = CAConfig()

        args.output_dir.mkdir(parents=True, exist_ok=True)

        if args.dry_run:
            LOGGER.info("DRY RUN - no AWS changes will be made")

        result = rotate_intermediate_ca(
            environment=args.environment,
            new_intermediate_key_pem=new_intermediate_key_pem,
            new_intermediate_cert_pem=new_intermediate_cert_pem,
            root_cert_pem=root_cert_pem,
            dynamodb_table=args.dynamodb_table,
            s3_bucket=args.s3_bucket,
            ssm_client=ssm_client,
            dynamodb_client=dynamodb_client,
            s3_client=s3_client,
            config=config,
            output_dir=args.output_dir,
            dry_run=args.dry_run,
        )

        LOGGER.info("Rotation complete:")
        LOGGER.info("  Re-issued: %d", result.reissued_count)
        LOGGER.info("  Revoked: %d", result.revoked_count)
        LOGGER.info("  Failed: %d", result.failed_count)
        LOGGER.info("  New Intermediate Serial: %s", result.new_intermediate_serial)
        if result.truststore_version_id:
            LOGGER.info("  Truststore Version: %s", result.truststore_version_id)

        if result.failed_count > 0:
            LOGGER.warning("Failed clients: %s", result.failed_client_ids)
            return 1

        return 0

    except Exception as e:
        LOGGER.error("Rotation failed: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
