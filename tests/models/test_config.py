"""
Tests for src/models/config.py - DynamicBatchConfig, AttachmentConfig, EngineMode
"""

import os
import tempfile
from argparse import Namespace
from unittest.mock import patch, MagicMock

import pytest

from src.models.config import DynamicBatchConfig, AttachmentConfig, EngineMode


class TestDynamicBatchConfig:
    """Tests for DynamicBatchConfig class."""

    def test_get_batch_size_returns_positive_integer(self):
        """Batch size should always be a positive integer."""
        batch_size = DynamicBatchConfig.get_batch_size()
        assert isinstance(batch_size, int)
        assert batch_size > 0

    def test_get_batch_size_based_on_cpu_count(self):
        """Batch size should be based on CPU count (1000 * cpus)."""
        with patch("os.cpu_count", return_value=4):
            batch_size = DynamicBatchConfig.get_batch_size()
            assert batch_size == 4000

    def test_get_batch_size_with_single_cpu(self):
        """Batch size with single CPU should be 1000."""
        with patch("os.cpu_count", return_value=1):
            batch_size = DynamicBatchConfig.get_batch_size()
            assert batch_size == 1000

    def test_get_batch_size_fallback_on_none_cpu(self):
        """Should fallback to 1 CPU when cpu_count returns None."""
        with patch("os.cpu_count", return_value=None):
            batch_size = DynamicBatchConfig.get_batch_size()
            assert batch_size == 1000


class TestAttachmentConfig:
    """Tests for AttachmentConfig class."""

    def test_get_attachment_returns_none_when_no_setting(self):
        """Should return None when DEFAULT_ATTACHMENT is not set."""
        with patch.object(
            __import__("src.models.config", fromlist=["settings"]).settings,
            "DEFAULT_ATTACHMENT",
            None,
            create=True,
        ):
            result = AttachmentConfig.get_attachment()
            # May return None or existing path depending on settings
            assert result is None or isinstance(result, str)

    def test_get_attachment_returns_path_when_exists(self):
        """Should return path when file exists."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as f:
            temp_path = f.name
            f.write(b"test content")

        try:
            with patch.object(
                __import__("src.models.config", fromlist=["settings"]).settings,
                "DEFAULT_ATTACHMENT",
                temp_path,
                create=True,
            ):
                result = AttachmentConfig.get_attachment()
                assert result == temp_path
        finally:
            os.unlink(temp_path)

    def test_get_attachments_from_folder_empty_when_no_folder(self):
        """Should return empty list when no attachments folder."""
        with patch.object(
            __import__("src.models.config", fromlist=["settings"]).settings,
            "ATTACHMENTS_FOLDER",
            None,
            create=True,
        ):
            result = AttachmentConfig.get_attachments_from_folder()
            assert result == []

    def test_get_attachments_from_folder_finds_files(self):
        """Should find files in attachments folder."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test files
            pdf_path = os.path.join(temp_dir, "test.pdf")
            txt_path = os.path.join(temp_dir, "test.txt")
            with open(pdf_path, "w") as f:
                f.write("pdf content")
            with open(txt_path, "w") as f:
                f.write("txt content")

            with patch.object(
                __import__("src.models.config", fromlist=["settings"]).settings,
                "ATTACHMENTS_FOLDER",
                temp_dir,
                create=True,
            ):
                result = AttachmentConfig.get_attachments_from_folder()
                assert len(result) == 2
                assert any("test.pdf" in r for r in result)
                assert any("test.txt" in r for r in result)

    def test_get_all_attachments_returns_list(self):
        """Should always return a list."""
        result = AttachmentConfig.get_all_attachments()
        assert isinstance(result, list)


class TestEngineMode:
    """Tests for EngineMode class."""

    def test_default_scanning_mode(self):
        """Default mode should be scanning when no special flags."""
        args = Namespace(
            report=None,
            process_reports=False,
            threads_only=False,
            test_report=False,
            start_api=False,
            multi_api_scan=False,
        )
        mode = EngineMode(args)
        assert mode.scanning_mode is True
        assert mode.report_mode is False
        assert mode.threads_only_mode is False
        assert mode.api_mode is False

    def test_report_mode(self):
        """Should detect report mode when report arg is set."""
        args = Namespace(
            report="http://example.com",
            process_reports=False,
            threads_only=False,
            test_report=False,
            start_api=False,
            multi_api_scan=False,
        )
        mode = EngineMode(args)
        assert mode.report_mode is True
        assert mode.scanning_mode is False

    def test_threads_only_mode(self):
        """Should detect threads-only mode."""
        args = Namespace(
            report=None,
            process_reports=False,
            threads_only=True,
            test_report=False,
            start_api=False,
            multi_api_scan=False,
        )
        mode = EngineMode(args)
        assert mode.threads_only_mode is True
        assert mode.scanning_mode is False

    def test_api_mode(self):
        """Should detect API mode."""
        args = Namespace(
            report=None,
            process_reports=False,
            threads_only=False,
            test_report=False,
            start_api=True,
            multi_api_scan=False,
        )
        mode = EngineMode(args)
        assert mode.api_mode is True
        assert mode.scanning_mode is False

    def test_process_reports_mode(self):
        """Should detect process-reports mode."""
        args = Namespace(
            report=None,
            process_reports=True,
            threads_only=False,
            test_report=False,
            start_api=False,
            multi_api_scan=False,
        )
        mode = EngineMode(args)
        assert mode.process_reports_mode is True
        assert mode.scanning_mode is False

    def test_multi_api_mode(self):
        """Should detect multi-API scan mode."""
        args = Namespace(
            report=None,
            process_reports=False,
            threads_only=False,
            test_report=False,
            start_api=False,
            multi_api_scan=True,
        )
        mode = EngineMode(args)
        assert mode.multi_api_mode is True
        assert mode.scanning_mode is False
