"""JSON logging configuration for CA operations scripts."""

import logging
from typing import Any

from pythonjsonlogger.json import JsonFormatter


class CustomJsonFormatter(JsonFormatter):
    """Custom JSON formatter with focused field set.

    Includes only 6 fields: timestamp, level, message, exc_info, funcName, lineno.
    Drops verbose fields like module, process, thread, processName, threadName, name.
    """

    def add_fields(
        self,
        log_data: dict[str, Any],
        record: logging.LogRecord,
        message_dict: dict[str, Any],
    ) -> None:
        """Override to include only specified fields.

        Args:
            log_data: Dict to be logged as JSON
            record: LogRecord object from logging framework
            message_dict: Dict containing message and args
        """
        super().add_fields(log_data, record, message_dict)

        # Rename levelname to level for cleaner output
        if "levelname" in log_data:
            log_data["level"] = log_data.pop("levelname")

        # Keep only required fields for readable JSON logs
        allowed_fields = {
            "timestamp",
            "level",
            "message",
            "exc_info",
            "funcName",
            "lineno",
        }

        # Remove all fields not in allowed set
        keys_to_remove = [key for key in log_data if key not in allowed_fields]
        for key in keys_to_remove:
            log_data.pop(key)


def _setup_logger() -> logging.Logger:
    """Initialize and configure singleton logger.

    Returns:
        Configured logger with CustomJsonFormatter
    """
    logger = logging.getLogger("ca_operations")

    # Prevent duplicate handlers if module reloaded
    if logger.handlers:
        return logger

    handler = logging.StreamHandler()
    formatter = CustomJsonFormatter(
        fmt="%(timestamp)s %(levelname)s %(funcName)s %(lineno)d %(message)s",
        timestamp=True,
    )
    handler.setFormatter(formatter)

    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    logger.propagate = False  # Don't propagate to root logger

    return logger


# Singleton logger instance - import this in other modules
LOGGER = _setup_logger()
