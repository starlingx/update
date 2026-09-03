#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import subprocess
import unittest
from unittest.mock import patch

from software.tests import base  # noqa: F401
from software.exceptions import APTOSTreeCommandFail
from software import apt_utils


class TestInitializeAptOstree(unittest.TestCase):
    @patch('software.apt_utils.subprocess.run')
    def test_success(self, mock_run):
        apt_utils.initialize_apt_ostree("/feed/dir")
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        self.assertIn("apt-ostree", args)
        self.assertIn("init", args)

    @patch('software.apt_utils.subprocess.run',
           side_effect=subprocess.CalledProcessError(
               1, 'cmd', stderr=b"error"))
    def test_failure(self, _mock_run):
        with self.assertRaises(APTOSTreeCommandFail):
            apt_utils.initialize_apt_ostree("/feed/dir")


class TestPackageListUpload(unittest.TestCase):

    @patch('software.apt_utils.subprocess.run',
           side_effect=subprocess.CalledProcessError(
               1, 'cmd', stderr=b"upload error"))
    def test_failure(self, _mock_run):
        with self.assertRaises(APTOSTreeCommandFail):
            apt_utils.package_list_upload("/feed", "24.09.1", ["pkg1.deb"])


class TestPackageRemove(unittest.TestCase):
    @patch('software.apt_utils.subprocess.run')
    def test_success(self, mock_run):
        apt_utils.package_remove("/feed", "24.09.1", ["pkg1", "pkg2"])
        self.assertEqual(mock_run.call_count, 2)

    @patch('software.apt_utils.subprocess.run',
           side_effect=subprocess.CalledProcessError(
               1, 'cmd', stderr=b"other error"))
    def test_other_error(self, _mock_run):
        with self.assertRaises(APTOSTreeCommandFail):
            apt_utils.package_remove("/feed", "24.09.1", ["pkg1"])


class TestComponentRemove(unittest.TestCase):

    @patch('software.apt_utils.subprocess.run',
           side_effect=subprocess.CalledProcessError(
               1, 'cmd', stderr=b"error"))
    def test_failure(self, _mock_run):
        with self.assertRaises(APTOSTreeCommandFail):
            apt_utils.component_remove("/feed", "24.09.1")


class TestRunInstall(unittest.TestCase):

    @patch('software.apt_utils.subprocess.run',
           side_effect=subprocess.CalledProcessError(
               1, 'cmd', stderr=b"install error"))
    def test_failure(self, _mock_run):
        with self.assertRaises(APTOSTreeCommandFail):
            apt_utils.run_install("/repo", "24.09", "24.09.1", ["pkg1"])


class TestRunRollback(unittest.TestCase):

    @patch('software.apt_utils.subprocess.run',
           side_effect=subprocess.CalledProcessError(
               1, 'cmd', stderr=b"rollback error"))
    def test_failure(self, _mock_run):
        with self.assertRaises(APTOSTreeCommandFail):
            apt_utils.run_rollback("/repo", "abc123")
