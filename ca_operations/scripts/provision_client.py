#!/usr/bin/env python3
"""Provision client certificate signed by Intermediate CA from SSM."""

import argparse
import sys
from pathlib import Path

from ca_operations.lib.ca_manager import CAManager
from ca_operations.lib.config import CAConfig
from ca_operations.lib.logging_config import LOGGER
from ca_operations.lib.ssm_client import SSMClient

ENVIRONMENTS = ["sandbox", "staging", "uat", "production"]
PROJECT_NAME = "apigw-mtls"


def main() -> int:
    """Provision client certificate with specified client ID.

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    parser = argparse.ArgumentParser(
        description="Provision client certificate (fetches intermediate CA from SSM)"
    )
    parser.add_argument(
        "--client-id",
        required=True,
        help="Client identifier (used as CN in certificate)",
    )
    parser.add_argument(
        "--environment",
        choices=ENVIRONMENTS,
        required=True,
        help="Target environment (sandbox, staging, uat, production)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Output directory for client artifacts (default: ca_operations/output/{env}/clients)",
    )
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="Skip if client already exists in SSM (idempotency)",
    )
    args = parser.parse_args()

    if not args.output_dir:
        args.output_dir = Path(f"ca_operations/output/{args.environment}/clients")

    try:
        ssm_client = SSMClient()

        if args.skip_existing and ssm_client.client_exists(
            project_name=PROJECT_NAME,
            account=args.environment,
            client_id=args.client_id,
        ):
            LOGGER.info("Client %s already exists in SSM, skipping", args.client_id)
            return 0

        LOGGER.info(
            "Provisioning certificate for %s (env=%s)",
            args.client_id,
            args.environment,
        )

        config = CAConfig()
        ca_manager = CAManager(config)

        result = ca_manager.provision_client_certificate_from_ssm(
            client_id=args.client_id,
            account=args.environment,
            ssm_client=ssm_client,
            output_dir=args.output_dir,
            project_name=PROJECT_NAME,
        )

        LOGGER.info("Client certificate created:")
        LOGGER.info("  Key: %s", result.key_path)
        LOGGER.info("  Cert: %s", result.cert_path)
        LOGGER.info("  Serial: %s", result.serial_number)
        LOGGER.info("  Metadata: %s", result.metadata_path)
        LOGGER.info("Next: Terraform will upload to SSM + DynamoDB")
        return 0

    except ValueError as e:
        LOGGER.error("SSM error: %s", e)
        return 1
    except Exception as e:
        LOGGER.error("Client certificate provisioning failed: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
