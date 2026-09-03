#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for software.software_worker module."""

import unittest
from unittest import mock

from software.tests import base  # noqa: F401
from software.software_worker import SoftwareWorker


class TestSoftwareWorkerStaticMethods(unittest.TestCase):
    """Tests for SoftwareWorker static methods."""

    def test_get_key_empty_dict(self):
        """Test _get_key with empty dict returns 1."""
        self.assertEqual(SoftwareWorker._get_key({}), 1)

    def test_get_key_with_entries(self):
        """Test _get_key returns next integer."""
        self.assertEqual(SoftwareWorker._get_key({"1": {}, "2": {}}), 3)

    def test_get_key_single_entry(self):
        """Test _get_key with single entry."""
        self.assertEqual(SoftwareWorker._get_key({"1": {}}), 2)

    def test_suppress_text_no_match(self):
        """Test _suppress_text with no sensitive data."""
        result = SoftwareWorker._suppress_text("echo hello")
        self.assertEqual(result, "echo hello")

    def test_suppress_text_password(self):
        """Test _suppress_text suppresses password."""
        result = SoftwareWorker._suppress_text(
            "command password=secret123 other")
        self.assertNotIn("secret123", result)
        self.assertIn("xxxxxxx", result)

    def test_join_stdout_stderr_empty(self):
        """Test _join_stdout_stderr with empty list."""
        stdout, stderr = SoftwareWorker._join_stdout_stderr([])
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")

    def test_join_stdout_stderr_mixed(self):
        """Test _join_stdout_stderr with mixed output."""
        output = [
            {"type": "stdout", "output": "line1\n"},
            {"type": "stderr", "output": "error1\n"},
            {"type": "stdout", "output": "line2\n"},
        ]
        stdout, stderr = SoftwareWorker._join_stdout_stderr(output)
        self.assertEqual(stdout, "line1\nline2\n")
        self.assertEqual(stderr, "error1\n")


class TestSoftwareWorkerReadWrite(unittest.TestCase):
    """Tests for SoftwareWorker read/write operations."""

    @mock.patch('os.makedirs')
    def test_read_file_not_found(self, _mock_makedirs):
        """Test _read_file returns empty dict for missing file."""
        with mock.patch('builtins.open',
                        side_effect=FileNotFoundError):
            worker = SoftwareWorker.__new__(SoftwareWorker)
            worker._filename = "/tmp/nonexistent.json"
            result = worker._read_file()
            self.assertEqual(result, {})

    @mock.patch('os.makedirs')
    def test_read_file_invalid_json(self, _mock_makedirs):
        """Test _read_file returns empty dict for invalid JSON."""
        with mock.patch('builtins.open',
                        mock.mock_open(read_data='not json')):
            worker = SoftwareWorker.__new__(SoftwareWorker)
            worker._filename = "/tmp/bad.json"
            result = worker._read_file()
            self.assertEqual(result, {})
