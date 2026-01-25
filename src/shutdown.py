"""
Shared shutdown state for Anisakys Phishing Detection Engine.

Provides a global shutdown flag accessible to all modules without circular imports.
"""

import threading
import os
from src.logger import logger

# Global flag for graceful shutdown
shutdown_requested = False
_shutdown_lock = threading.Lock()


def request_shutdown():
    """Request a graceful shutdown."""
    global shutdown_requested
    with _shutdown_lock:
        shutdown_requested = True


def is_shutdown_requested():
    """Check if shutdown has been requested."""
    return shutdown_requested


def signal_handler(signum, frame):
    """Handle interrupt signals gracefully."""
    request_shutdown()
    logger.info("\n🛑 Interrupt received, shutting down gracefully...")
    logger.info("⏳ Please wait for current operations to complete...")

    # Force exit after 5 seconds if still hanging
    def force_exit():
        logger.error("⚠️ Forced shutdown after timeout")
        os._exit(1)

    timer = threading.Timer(5.0, force_exit)
    timer.daemon = True
    timer.start()
