#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# pylint: disable=unused-argument,protected-access
import unittest
from unittest.mock import patch, MagicMock  # noqa: H301

from software_client.v1.release import ReleaseManager
from software_client.v1 import deploy_shell
from software_client.common import utils


# ===== deploy_shell remaining =====

class TestDeployShellHostRollback(unittest.TestCase):
    def test_success(self):
        cc = MagicMock()
        resp = MagicMock(status_code=200)
        cc.deploy.host_rollback.return_value = (resp, {"info": "ok"})
        args = MagicMock(debug=False, host="w-0")
        rc = deploy_shell.do_host_rollback(cc, args)
        self.assertEqual(rc, 0)


class TestDeployShellActivateRollback(unittest.TestCase):
    def test_success(self):
        cc = MagicMock()
        resp = MagicMock(status_code=200)
        cc.deploy.activate_rollback.return_value = (resp, {"info": "ok"})
        args = MagicMock(debug=False)
        rc = deploy_shell.do_activate_rollback(cc, args)
        self.assertEqual(rc, 0)


# ===== system_deploy_shell =====

class TestInputWithTimeout(unittest.TestCase):
    @patch('builtins.input', return_value='yes')
    @patch('software_client.common.utils.signal.alarm')
    @patch('software_client.common.utils.signal.signal')
    def test_success(self, mock_sig, mock_alarm, mock_input):
        utils.input_with_timeout("prompt: ", 10)


# ===== release_shell remaining =====


class TestCommitPatchPaths(unittest.TestCase):
    @patch('software_client.v1.release.signal.signal')
    @patch('builtins.print')
    def test_sw_version_without_all(self, mock_print, mock_signal):
        mgr = ReleaseManager.__new__(ReleaseManager)

        class Args:
            sw_version = "24.09"
            all = False
            dry_run = False
            debug = False
            patch = ["P1"]
        rc = mgr.commit_patch(Args())
        self.assertEqual(rc, 1)

    @patch('software_client.v1.release.signal.signal')
    @patch('builtins.print')
    def test_all_empty_list(self, mock_print, mock_signal):
        mgr = ReleaseManager.__new__(ReleaseManager)
        resp_200 = MagicMock(status_code=200)
        mgr._list = MagicMock(return_value=(resp_200, {"sd": {}}))

        class Args:
            sw_version = None
            all = True
            dry_run = False
            debug = False
            patch = []
        rc = mgr.commit_patch(Args())
        self.assertEqual(rc, 0)

    @patch('software_client.v1.release.signal.signal')
    @patch('builtins.print')
    def test_all_500(self, mock_print, mock_signal):
        mgr = ReleaseManager.__new__(ReleaseManager)
        mgr._list = MagicMock(return_value=(MagicMock(status_code=500), {}))

        class Args:
            sw_version = None
            all = True
            dry_run = False
            debug = False
            patch = []
        rc = mgr.commit_patch(Args())
        self.assertEqual(rc, 1)

    @patch('software_client.v1.release.signal.signal')
    @patch('builtins.print')
    def test_no_patches_found(self, mock_print, mock_signal):
        mgr = ReleaseManager.__new__(ReleaseManager)
        resp_200 = MagicMock(status_code=200)
        mgr._list = MagicMock(return_value=(resp_200, {"other": "data"}))

        class Args:
            sw_version = None
            all = False
            dry_run = False
            debug = False
            patch = ["P1"]
        rc = mgr.commit_patch(Args())
        self.assertEqual(rc, 1)

    @patch('software_client.v1.release.signal.signal')
    @patch('builtins.print')
    def test_query_deps_500(self, mock_print, mock_signal):
        mgr = ReleaseManager.__new__(ReleaseManager)
        mgr._list = MagicMock(return_value=(MagicMock(status_code=500), {}))

        class Args:
            sw_version = None
            all = False
            dry_run = False
            debug = False
            patch = ["P1"]
        rc = mgr.commit_patch(Args())
        self.assertEqual(rc, 1)

    @patch('software_client.v1.release.signal.signal')
    @patch('builtins.print')
    def test_dry_run(self, mock_print, mock_signal):
        mgr = ReleaseManager.__new__(ReleaseManager)
        resp_200 = MagicMock(status_code=200)
        mgr._list = MagicMock(return_value=(resp_200, {"patches": ["P1"]}))
        mgr._create = MagicMock(return_value=(resp_200, {"info": "ok"}))

        class Args:
            sw_version = None
            all = False
            dry_run = True
            debug = False
            patch = ["P1"]
        rc = mgr.commit_patch(Args())
        self.assertEqual(rc, 0)

    @patch('software_client.v1.release.signal.signal')
    @patch('builtins.input', return_value='n')
    @patch('builtins.print')
    def test_user_cancels(self, mock_print, mock_input, mock_signal):
        mgr = ReleaseManager.__new__(ReleaseManager)
        resp_200 = MagicMock(status_code=200)
        mgr._list = MagicMock(return_value=(resp_200, {"patches": ["P1"]}))
        mgr._create = MagicMock(return_value=(resp_200, {"info": "ok"}))

        class Args:
            sw_version = None
            all = False
            dry_run = False
            debug = False
            patch = ["P1"]
        rc = mgr.commit_patch(Args())
        self.assertEqual(rc, 1)
