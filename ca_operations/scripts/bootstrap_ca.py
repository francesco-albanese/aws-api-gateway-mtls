#!/usr/bin/env python3
"""Bootstrap CA by generating Root CA and Intermediate CA certificates."""

import argparse
import sys
from pathlib import Path

from ca_operations.lib.ca_manager import CAManager
from ca_operations.lib.config import CAConfig
from ca_operations.lib.logging_config import LOGGER


def main() -> int:
    """Bootstrap Root CA and Intermediate CA.

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    parser = argparse.ArgumentParser(
        description="Bootstrap CA (generate Root + Intermediate)"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("ca-operations/output"),
        help="Output directory for CA artifacts (default: ca-operations/output)",
    )
    args = parser.parse_args()

    try:
        config = CAConfig()
        ca_manager = CAManager(config)

        LOGGER.info("Bootstrapping CA...")
        result = ca_manager.bootstrap_ca(args.output_dir)

        LOGGER.info("Root CA created:")
        LOGGER.info("  Key: %s", result.root_key_path)
        LOGGER.info("  Cert: %s", result.root_cert_path)
        LOGGER.info("  Serial: %s", result.root_serial)

        LOGGER.info("Intermediate CA created:")
        LOGGER.info("  Key: %s", result.intermediate_key_path)
        LOGGER.info("  Cert: %s", result.intermediate_cert_path)
        LOGGER.info("  Serial: %s", result.intermediate_serial)

        LOGGER.info("Bootstrap complete. Next: run create_truststore.py")
        return 0

    except Exception as e:
        LOGGER.error("Bootstrap failed: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
