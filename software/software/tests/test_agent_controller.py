#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from unittest.mock import PropertyMock
from unittest.mock import MagicMock
from unittest.mock import patch
import unittest
from software.tests import base  # noqa: F401
from software.software_agent import PatchAgent
from software.software_controller import PatchController
from software import constants
from software.exceptions import InvalidOperation

RC = 'software.software_controller.PatchController.release_collection'


def make_pa():
    pa = PatchAgent.__new__(PatchAgent)
    pa.node_is_patched = False
    pa.node_is_patched_timestamp = 0
    pa.patch_op_counter = 0
    pa.changes = False
    pa.patch_failed = False
    pa.state = 'idle'
    pa.query_id = 0
    pa.latest_sysroot_commit = 'abc'
    pa.latest_feed_commit = 'abc'
    pa.sock_out = None
    pa.install_local = False
    pa.pre_bootstrap = False
    pa.controller_address = '127.0.0.1'
    return pa


def make_sc():
    sc = PatchController.__new__(PatchController)
    sc.db_api_instance = MagicMock()
    sc.hosts = {}
    sc.hosts_lock = MagicMock()
    sc.patch_op_counter = 0
    sc.sock_out = None
    sc.install_local = False
    sc.interim_state = {}
    sc.fm_api = MagicMock()
    sc.base_pkgdata = MagicMock()
    sc.hostname = 'ctrl-0'
    sc.controller_neighbours = {}
    sc.controller_neighbours_lock = MagicMock()
    sc.socket_lock = MagicMock()
    return sc


class TestSetInstallFailed(unittest.TestCase):
    @patch('software.software_agent.setflag')
    def test_set_flags(self, _mock_set):
        pa = make_pa()
        pa.set_install_failed_flags()
        self.assertTrue(pa.patch_failed)
        self.assertEqual(pa.state, constants.PATCH_AGENT_STATE_INSTALL_FAILED)


class TestDeployAbort(unittest.TestCase):
    @patch(RC, new_callable=PropertyMock)
    @patch('software.software_controller.get_instance')
    def test_no_deploy(self, mock_db, _mock_rc):
        sc = make_sc()
        mock_db.return_value.get_deploy_all.return_value = []
        with self.assertRaises(InvalidOperation):
            sc.software_deploy_abort_api()


class TestDeployComplete(unittest.TestCase):
    @patch(RC, new_callable=PropertyMock)
    @patch('software.software_controller.get_instance')
    def test_no_deploy(self, mock_db, _mock_rc):
        sc = make_sc()
        mock_db.return_value.get_deploy_all.return_value = []
        with self.assertRaises(InvalidOperation):
            sc.software_deploy_complete_api()


class TestDeployDelete(unittest.TestCase):
    @patch(RC, new_callable=PropertyMock)
    @patch('software.software_controller.get_instance')
    def test_no_deploy(self, mock_db, _mock_rc):
        sc = make_sc()
        mock_db.return_value.get_deploy_all.return_value = []
        with self.assertRaises(InvalidOperation):
            sc.software_deploy_delete_api()


class TestDeployActivate(unittest.TestCase):
    @patch(RC, new_callable=PropertyMock)
    @patch('software.software_controller.get_instance')
    def test_no_deploy(self, mock_db, _mock_rc):
        sc = make_sc()
        mock_db.return_value.get_deploy_all.return_value = []
        with self.assertRaises(InvalidOperation):
            sc.software_deploy_activate_api()


class TestDeployActivateRollback(unittest.TestCase):
    @patch(RC, new_callable=PropertyMock)
    @patch('software.software_controller.get_instance')
    def test_no_deploy(self, mock_db, _mock_rc):
        sc = make_sc()
        mock_db.return_value.get_deploy_all.return_value = []
        with self.assertRaises(InvalidOperation):
            sc.software_deploy_activate_rollback_api()
