#!/usr/bin/env python3
"""Create truststore bundle (Intermediate + Root) for S3 upload."""

import argparse
import sys
from pathlib import Path

from ca_operations.lib.ca_manager import CAManager
from ca_operations.lib.config import CAConfig
from ca_operations.lib.logging_config import LOGGER


def main() -> int:
    """Create truststore bundle from CA certificates.

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    parser = argparse.ArgumentParser(
        description="Create truststore bundle (Intermediate + Root)"
    )
    parser.add_argument(
        "--ca-dir",
        type=Path,
        required=True,
        help="CA base directory containing root-ca/ and intermediate-ca/ subdirectories",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Truststore output path (e.g., ca-operations/output/truststore/truststore.pem)",
    )
    args = parser.parse_args()

    try:
        config = CAConfig()
        ca_manager = CAManager(config)

        LOGGER.info("Creating truststore bundle...")
        truststore_path = ca_manager.create_truststore(args.ca_dir, args.output)

        LOGGER.info("Truststore created: %s", truststore_path)
        LOGGER.info("Next: Terraform will upload to S3")
        return 0

    except FileNotFoundError as e:
        LOGGER.error("CA certificate not found: %s", e)
        return 1
    except Exception as e:
        LOGGER.error("Truststore creation failed: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
