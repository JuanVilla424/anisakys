"""
Configuration models for Anisakys Phishing Detection Engine.

Contains configuration classes for batch sizing, attachments, and engine modes.
"""

import os
from typing import List, Optional

import psutil

from src.config import settings
from src.logger import logger


class DynamicBatchConfig:
    """Configuration for dynamic batch sizing based on system resources."""

    @staticmethod
    def get_batch_size() -> int:
        """Calculate optimal batch size based on available system resources."""
        try:
            cpus = os.cpu_count() or 1
            return 1000 * cpus
        except Exception as e:
            logger.debug(f"Can't get batch size: {e}")
            mem = psutil.virtual_memory()
            batch = int(mem.available / (10 * 1024 * 1024))
            return max(100, batch)


class AttachmentConfig:
    """Configuration for email attachments."""

    @staticmethod
    def get_attachment() -> Optional[str]:
        """Get a default attachment path from settings."""
        path = getattr(settings, "DEFAULT_ATTACHMENT", None)
        if path and os.path.exists(path):
            abs_path = os.path.abspath(path)
            logger.info(f"📎 Using default attachment from settings: {abs_path}")
            return path
        else:
            if path:
                logger.error(f"❌ DEFAULT_ATTACHMENT file '{path}' does not exist.")
        return None

    @staticmethod
    def get_attachments_from_folder() -> List[str]:
        """
        Get all attachment files from the attachments folder.

        Returns:
            List[str]: List of file paths to attach
        """
        attachments = []

        # Check for attachments folder setting
        attachments_folder = getattr(settings, "ATTACHMENTS_FOLDER", None)
        if (
            attachments_folder
            and os.path.exists(attachments_folder)
            and os.path.isdir(attachments_folder)
        ):
            logger.info(f"📁 Using attachments folder: {attachments_folder}")

            # Get all files from the folder
            for filename in os.listdir(attachments_folder):
                file_path = os.path.join(attachments_folder, filename)
                if os.path.isfile(file_path):
                    # Filter by allowed extensions (optional)
                    allowed_extensions = getattr(
                        settings,
                        "ALLOWED_ATTACHMENT_EXTENSIONS",
                        [".pdf", ".txt", ".doc", ".docx", ".jpg", ".jpeg", ".png", ".zip"],
                    )

                    if any(file_path.lower().endswith(ext) for ext in allowed_extensions):
                        attachments.append(file_path)
                        logger.debug(f"📎 Added attachment: {file_path}")
                    else:
                        logger.debug(f"⏭️ Skipped file (not allowed extension): {file_path}")

            if attachments:
                logger.info(f"📁 Found {len(attachments)} attachment(s) in folder")
            else:
                logger.warning(f"⚠️  No valid attachments found in folder: {attachments_folder}")

        return attachments

    @staticmethod
    def get_all_attachments() -> List[str]:
        """
        Get all attachments (both single file and folder-based).

        Returns:
            List[str]: List of all attachment file paths
        """
        attachments = []

        # First, try to get attachments from the folder
        folder_attachments = AttachmentConfig.get_attachments_from_folder()
        if folder_attachments:
            attachments.extend(folder_attachments)

        # If no folder attachments, try single file attachment
        if not attachments:
            single_attachment = AttachmentConfig.get_attachment()
            if single_attachment:
                attachments.append(single_attachment)

        return attachments


class EngineMode:
    """Determines the operational mode of the engine."""

    def __init__(self, args):
        self.report_mode = args.report is not None
        self.process_reports_mode = args.process_reports
        self.threads_only_mode = args.threads_only
        self.api_mode = getattr(args, "start_api", False)
        self.multi_api_mode = getattr(args, "multi_api_scan", False)
        self.scanning_mode = not (
            self.report_mode
            or self.process_reports_mode
            or self.threads_only_mode
            or args.test_report
            or self.api_mode
            or self.multi_api_mode
        )
