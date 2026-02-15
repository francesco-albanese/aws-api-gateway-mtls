#!/usr/bin/env python3
"""Rotate Intermediate CA - generate new intermediate, re-issue active client certs."""

import argparse
import json
import sys
from datetime import date
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from ca_operations.lib.ca_utils import create_intermediate_ca
from ca_operations.lib.cert_utils import (
    create_truststore_bundle,
    deserialize_certificate,
    deserialize_private_key,
    extract_certificate_metadata,
    serialize_certificate,
    serialize_csr,
    serialize_private_key,
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


def verify_keys_certs_valid(
    new_intermediate_key: RSAPrivateKey, new_key_pem: bytes, new_cert_pem: bytes
):
    """
    Verifies that the new serialized certificate and the new private key
    can be deserialized back into valid objects that match the originals.
    """
    deserialised_new_cert_pem = deserialize_certificate(new_cert_pem)
    public_key = deserialised_new_cert_pem.public_key()
    if not isinstance(public_key, RSAPublicKey):
        raise RuntimeError("Expected RSA public key")
    if public_key.public_numbers() != new_intermediate_key.public_key().public_numbers():
        raise RuntimeError("Key-cert mismatch after serialization")

    deserialised_new_key_pem = deserialize_private_key(new_key_pem)
    if deserialised_new_key_pem.public_key().public_numbers() != public_key.public_numbers():
        raise RuntimeError("Key PEM mismatch after serialization")


def rotate_intermediate_ca(
    environment: str,
    root_key_pem: bytes,
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

    1. Generate new intermediate CA signed by root
    2. Store new intermediate in SSM
    3. Query active certs from DynamoDB
    4. Re-issue each client cert with new intermediate
    5. Update DynamoDB: revoke old, add new
    6. Update S3 truststore

    Args:
        environment: Target environment
        root_key_pem: Root CA private key PEM bytes
        root_cert_pem: Root CA certificate PEM bytes
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
    # Deserialize root CA
    root_key = deserialize_private_key(root_key_pem)
    root_cert = deserialize_certificate(root_cert_pem)

    # Generate new intermediate CA
    cn = f"Francesco Albanese Issuing CA - rotated {date.today().isoformat()}"
    new_intermediate_key, new_intermediate_cert, new_csr = create_intermediate_ca(
        root_cert=root_cert, root_key=root_key, config=config, common_name=cn
    )

    # Serialize new intermediate artifacts
    new_key_pem = serialize_private_key(new_intermediate_key)
    new_cert_pem = serialize_certificate(new_intermediate_cert)

    verify_keys_certs_valid(
        new_intermediate_key=new_intermediate_key,
        new_key_pem=new_key_pem,
        new_cert_pem=new_cert_pem,
    )

    # Store new intermediate CA in SSM
    if not dry_run:
        ssm_client.put_intermediate_ca(PROJECT_NAME, environment, new_key_pem, new_cert_pem)
        LOGGER.info("Stored new intermediate CA in SSM")

    # Write intermediate CA artifacts to output
    intermediate_output_dir = output_dir / "intermediate-ca"
    intermediate_output_dir.mkdir(parents=True, exist_ok=True)
    (intermediate_output_dir / "IntermediateCA.key").write_bytes(new_key_pem)
    (intermediate_output_dir / "IntermediateCA.pem").write_bytes(new_cert_pem)
    (intermediate_output_dir / "IntermediateCA.csr").write_bytes(serialize_csr(new_csr))
    (intermediate_output_dir / "metadata.json").write_text(
        json.dumps(extract_certificate_metadata(new_intermediate_cert), indent=2)
    )

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
        old_serial = cert_metadata.get("serialNumber")
        client_name = cert_metadata.get("clientName")
        if not old_serial or not client_name:
            LOGGER.warning("Skipping cert with missing serialNumber/clientName: %s", cert_metadata)
            failed_client_ids.append(client_name or "unknown")
            continue

        client_id = cert_metadata.get("client_id") or client_name

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

            new_cert_pem_client = serialize_certificate(new_cert)
            new_metadata = extract_certificate_metadata(new_cert, client_id=client_id)
            new_serial = new_metadata["serialNumber"]

            if not dry_run:
                if not dynamodb_client.rotate_certificate(dynamodb_table, old_serial, new_metadata):
                    raise RuntimeError(f"Failed to rotate cert {old_serial} -> {new_serial}")
                revoked_count += 1

                ssm_client.client.put_parameter(
                    Name=cert_path,
                    Value=new_cert_pem_client.decode("utf-8"),
                    Type="String",
                    Overwrite=True,
                )

            # Write to output dir for audit
            client_output_dir = output_dir / client_id
            client_output_dir.mkdir(parents=True, exist_ok=True)
            (client_output_dir / "client.pem").write_bytes(new_cert_pem_client)
            (client_output_dir / "metadata.json").write_text(json.dumps(new_metadata, indent=2))

            reissued_serials.append(new_serial)
            LOGGER.info("Re-issued %s: %s -> %s", client_id, old_serial[:20], new_serial[:20])

        except Exception as e:
            LOGGER.error("Failed to re-issue %s: %s", client_id, str(e))
            failed_client_ids.append(client_id)

    truststore_bundle = create_truststore_bundle(new_cert_pem, root_cert_pem)
    version_id = ""

    if failed_client_ids:
        LOGGER.warning(
            "Skipping truststore update — %d client(s) failed: %s",
            len(failed_client_ids),
            failed_client_ids,
        )
    elif not dry_run:
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

    try:
        ssm_client = SSMClient()
        dynamodb_client = DynamoDBClient()
        s3_client = S3Client()
        config = CAConfig()

        # Fetch root CA from SSM
        root_key_pem, root_cert_pem = ssm_client.get_root_ca(args.project_name, args.environment)
        LOGGER.info("Fetched root CA from SSM for %s/%s", args.project_name, args.environment)

        args.output_dir.mkdir(parents=True, exist_ok=True)

        if args.dry_run:
            LOGGER.info("DRY RUN - no AWS changes will be made")

        result = rotate_intermediate_ca(
            environment=args.environment,
            root_key_pem=root_key_pem,
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
