#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for software.deploy_utils module."""

import unittest
from unittest import mock

from software.tests import base  # noqa: F401
from software.deploy_utils import backup_etc
from software.deploy_utils import get_etc_backup_path


class TestGetEtcBackupPath(unittest.TestCase):
    """Tests for get_etc_backup_path."""

    def test_with_commit_id(self):
        """Test path with specific commit ID."""
        path = get_etc_backup_path("abc123")
        self.assertEqual(path, "/sysroot/upgrade/deploy-abc123.bak")

    def test_without_commit_id(self):
        """Test path with wildcard."""
        path = get_etc_backup_path()
        self.assertEqual(path, "/sysroot/upgrade/deploy-*.bak")

    def test_with_none(self):
        """Test path with None uses wildcard."""
        path = get_etc_backup_path(None)
        self.assertEqual(path, "/sysroot/upgrade/deploy-*.bak")


class TestBackupEtc(unittest.TestCase):
    """Tests for backup_etc."""

    @mock.patch('software.deploy_utils.delete_etc_backup')
    @mock.patch('os.path.exists', return_value=False)
    @mock.patch('os.makedirs')
    @mock.patch('shutil.copytree', side_effect=Exception("copy failed"))
    def test_backup_etc_failure(self, _mock_copytree, _mock_makedirs,
                                _mock_exists, _mock_delete):
        """Test etc backup failure raises."""
        with self.assertRaises(Exception):  # noqa: H202
            backup_etc("commit123")
