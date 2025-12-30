#!/usr/bin/env python3
"""Provision client certificate signed by Intermediate CA."""

import argparse
import sys
from pathlib import Path

from ca_operations.lib.ca_manager import CAManager
from ca_operations.lib.config import CAConfig
from ca_operations.lib.logging_config import LOGGER


def main() -> int:
    """Provision client certificate with specified client ID.

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    parser = argparse.ArgumentParser(description="Provision client certificate")
    parser.add_argument(
        "--client-id",
        required=True,
        help="Client identifier (used as CN in certificate)",
    )
    parser.add_argument(
        "--ca-dir",
        type=Path,
        required=True,
        help="CA base directory containing intermediate-ca/ subdirectory",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("ca-operations/output/clients"),
        help="Output directory for client artifacts (default: ca-operations/output/clients)",
    )
    args = parser.parse_args()

    try:
        config = CAConfig()
        ca_manager = CAManager(config)

        LOGGER.info("Provisioning certificate for: %s", args.client_id)
        result = ca_manager.provision_client_certificate(
            client_id=args.client_id,
            ca_base_dir=args.ca_dir,
            output_dir=args.output_dir,
        )

        LOGGER.info("Client certificate created:")
        LOGGER.info("  Key: %s", result.key_path)
        LOGGER.info("  Cert: %s", result.cert_path)
        LOGGER.info("  Serial: %s", result.serial_number)
        LOGGER.info("  Metadata: %s", result.metadata_path)

        LOGGER.info("Next: Terraform will create DynamoDB record from metadata.json")
        return 0

    except FileNotFoundError as e:
        LOGGER.error("CA file not found: %s", e)
        return 1
    except Exception as e:
        LOGGER.error("Client certificate provisioning failed: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
