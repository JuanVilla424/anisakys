"""
logger.py
~~~~~~~~~

Provides a global logger for the application.
Logs to both stdout and a file with a consistent format.
"""

import logging
import sys
import os
from typing import Optional


def setup_logger(
    name: str, level: int = logging.INFO, log_file: Optional[str] = None
) -> logging.Logger:
    """
    Configures and returns a logger with the specified name and level.
    The logger writes to stdout with a simplified format (message only)
    and optionally logs to a specified file with a detailed format.

    Args:
        name (str): The name of the logger.
        level (int, optional): The logging level (e.g., logging.INFO or logging.DEBUG).
            Defaults to logging.INFO.
        log_file (Optional[str], optional): The path to a file where logs should
            also be written. If None, no file logs are created.

    Returns:
        logging.Logger: The configured logger instance.
    """
    logger_instance = logging.getLogger(name)
    logger_instance.setLevel(level)

    # Create logs directory if it doesn't exist
    os.makedirs("logs", exist_ok=True)

    # Only configure handlers if none exist yet
    if not logger_instance.handlers:
        # 1. StreamHandler for stdout with a simplified formatter
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_formatter = logging.Formatter(fmt="%(message)s")
        stream_handler.setFormatter(stream_formatter)
        logger_instance.addHandler(stream_handler)

        # 2. Optional FileHandler with a detailed formatter
        if log_file:
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_formatter = logging.Formatter(
                fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            file_handler.setFormatter(file_formatter)
            logger_instance.addHandler(file_handler)

    logger_instance.propagate = False
    return logger_instance


# Root logger for the entire system
logger = setup_logger("app", level=logging.DEBUG, log_file="logs/anisakys.log")
