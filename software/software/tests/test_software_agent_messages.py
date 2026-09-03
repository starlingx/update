#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for uncovered lines in software_agent.py."""

import unittest
from unittest.mock import patch
from unittest.mock import MagicMock

from software.tests import base as test_base  # noqa: F401
from software import constants
from software.software_agent import PatchMessageHelloAgent
from software.software_agent import SoftwareMessageDeployDeleteCleanupReq
from software.software_agent import SoftwareMessageDeployDeleteCleanupResp
from software.software_agent import PatchAgent
from software.software_agent import main


class TestPatchMessageHelloAgentHandle(unittest.TestCase):
    """Tests for PatchMessageHelloAgent.handle."""

    @patch('software.software_agent.PatchMessageHelloAgentAck')
    @patch('software.software_agent.pa')
    @patch('software.software_agent.os.path.exists', return_value=True)
    def test_handle_rejected_locked_resets(self, _mock_exists, mock_pa, _mock_ack):
        mock_pa.state = constants.PATCH_AGENT_STATE_INSTALL_REJECTED
        msg = PatchMessageHelloAgent()
        msg.patch_op_counter = 0
        msg.handle(MagicMock(), ["10.0.0.1"])
        self.assertEqual(mock_pa.state, constants.PATCH_AGENT_STATE_IDLE)

    @patch('software.software_agent.PatchMessageHelloAgentAck')
    @patch('software.software_agent.pa')
    @patch('software.software_agent.os.path.exists', return_value=False)
    @patch('software.software_agent.time')
    def test_handle_rejected_timeout_resets(self, mock_time, _mock_exists,
                                            mock_pa, _mock_ack):
        mock_pa.state = constants.PATCH_AGENT_STATE_INSTALL_REJECTED
        mock_pa.rejection_timestamp = 1000.0
        mock_time.time.return_value = 1100.0  # 100 seconds later
        msg = PatchMessageHelloAgent()
        msg.patch_op_counter = 0
        msg.handle(MagicMock(), ["10.0.0.1"])
        self.assertEqual(mock_pa.state, constants.PATCH_AGENT_STATE_IDLE)


class TestDeployDeleteCleanupReq(unittest.TestCase):
    """Tests for SoftwareMessageDeployDeleteCleanupReq."""

    @patch('software.software_agent.SoftwareMessageDeployDeleteCleanupResp')
    @patch('software.software_agent.deploy_utils.delete_etc_backup')
    @patch('software.software_agent.remove_major_release_deployment_flags',
           return_value=True)
    @patch('software.software_agent.ostree_utils.delete_older_deployments',
           return_value=True)
    @patch('software.software_agent.ostree_utils.add_ostree_remote',
           return_value=True)
    @patch('software.software_agent.ostree_utils.delete_temporary_refs_and_remotes',
           return_value=True)
    @patch('software.software_agent.utils.get_platform_conf',
           return_value='controller')
    def test_handle_success(self, _mock_conf, _mock_del_refs, _mock_add_remote,
                            _mock_del_deploy, _mock_rm_flags, _mock_del_etc,
                            mock_resp):
        msg = SoftwareMessageDeployDeleteCleanupReq()
        msg.major_release = "24.09"
        msg.handle(MagicMock(), ["10.0.0.1"])
        mock_resp.return_value.send.assert_called_once()
        self.assertTrue(mock_resp.return_value.success)

    @patch('software.software_agent.SoftwareMessageDeployDeleteCleanupResp')
    @patch('software.software_agent.deploy_utils.delete_etc_backup')
    @patch('software.software_agent.remove_major_release_deployment_flags',
           return_value=False)
    @patch('software.software_agent.ostree_utils.delete_older_deployments',
           return_value=True)
    @patch('software.software_agent.ostree_utils.add_ostree_remote',
           return_value=True)
    @patch('software.software_agent.ostree_utils.delete_temporary_refs_and_remotes',
           return_value=True)
    @patch('software.software_agent.utils.get_platform_conf',
           return_value='controller')
    def test_handle_partial_failure(self, _mock_conf, _mock_del_refs,
                                    _mock_add_remote, _mock_del_deploy,
                                    _mock_rm_flags, _mock_del_etc, mock_resp):
        msg = SoftwareMessageDeployDeleteCleanupReq()
        msg.major_release = "24.09"
        msg.handle(MagicMock(), ["10.0.0.1"])
        self.assertFalse(mock_resp.return_value.success)

    def test_decode(self):
        msg = SoftwareMessageDeployDeleteCleanupReq()
        msg.decode({"major_release": "24.09", "msgtype": 17})
        self.assertEqual(msg.major_release, "24.09")


class TestDeployDeleteCleanupResp(unittest.TestCase):
    """Tests for SoftwareMessageDeployDeleteCleanupResp."""

    def test_encode(self):
        msg = SoftwareMessageDeployDeleteCleanupResp()
        msg.success = True
        msg.encode()
        self.assertTrue(msg.message["success"])


class TestPatchAgentHandleInstallBasic(unittest.TestCase):
    """Tests for PatchAgent.handle_install - basic paths."""

    @patch('software.software_agent.PatchMessageHelloAgentAck')
    @patch('software.software_agent.clearflag')
    @patch('software.software_agent.setflag')
    @patch('software.software_agent.pull_install_scripts_from_controller')
    @patch('subprocess.check_output')
    @patch('software.software_agent.ostree_utils')
    @patch('software.software_agent.utils.get_platform_conf',
           return_value='controller')
    @patch('software.software_agent.check_install_uuid', return_value=True)
    def test_handle_install_no_changes(self, _mock_uuid, _mock_platform,
                                       _mock_ostree, _mock_subproc, _mock_pull,
                                       _mock_set, _mock_clear, _mock_ack):
        pa = PatchAgent.__new__(PatchAgent)
        pa.sock_out = MagicMock()
        pa.install_local = True
        pa.changes = False
        pa.state = constants.PATCH_AGENT_STATE_IDLE
        pa.patch_failed = False
        pa.node_is_patched = False
        pa.latest_feed_commit = None
        pa.latest_sysroot_commit = None

        with patch.object(pa, 'query'):
            result = pa.handle_install()
        self.assertTrue(result)

    @patch('software.software_agent.PatchMessageHelloAgentAck')
    @patch('software.software_agent.clearflag')
    @patch('software.software_agent.setflag')
    @patch('software.software_agent.check_install_uuid', return_value=False)
    def test_handle_install_uuid_fail(self, _mock_uuid, _mock_set,
                                      _mock_clear, _mock_ack):
        pa = PatchAgent.__new__(PatchAgent)
        pa.sock_out = None
        pa.install_local = False
        pa.changes = False
        pa.state = constants.PATCH_AGENT_STATE_IDLE
        pa.patch_failed = False

        with patch.object(pa, 'query'):
            result = pa.handle_install()
        self.assertFalse(result)


class TestPatchAgentHandleBootstrap(unittest.TestCase):
    """Tests for PatchAgent.handle_bootstrap."""

    @patch('software.software_agent.cfg')
    @patch('software.software_agent.PatchMessageHelloAgentAck')
    def test_bootstrap(self, _mock_ack, mock_cfg):
        pa = PatchAgent.__new__(PatchAgent)
        pa.pre_bootstrap = True
        pa.install_local = True
        pa.sock_out = MagicMock()
        pa.sock_in = MagicMock()
        pa.listener = MagicMock()
        pa.setup_socket = MagicMock()
        pa.setup_tcp_socket = MagicMock()
        pa.query = MagicMock()
        pa.handle_install = MagicMock(return_value=True)
        mock_cfg.get_mgmt_ip.return_value = "10.0.0.1"

        pa.handle_bootstrap([])
        self.assertFalse(pa.pre_bootstrap)
        pa.setup_socket.assert_called_once()


class TestPatchAgentMain(unittest.TestCase):
    """Tests for main() function paths."""

    @patch('software.software_agent.PatchAgent')
    @patch('software.software_agent.configure_logging')
    @patch('software.software_agent.cfg')
    @patch('software.software_agent.os.path.isfile', return_value=False)
    @patch('software.software_agent.os.path.exists', return_value=False)
    @patch('software.software_agent.sys')
    def test_main_status_no_changes(self, mock_sys, _mock_exists, _mock_isfile,
                                    _mock_cfg, _mock_log, mock_pa_cls):
        mock_sys.argv = ["software-agent", "--status"]
        mock_pa = MagicMock()
        mock_pa.changes = False
        mock_pa_cls.return_value = mock_pa
        with self.assertRaises(SystemExit) as ctx:
            main()
        self.assertEqual(ctx.exception.code, 0)

    @patch('software.software_agent.PatchAgent')
    @patch('software.software_agent.configure_logging')
    @patch('software.software_agent.cfg')
    @patch('software.software_agent.os.path.isfile', return_value=False)
    @patch('software.software_agent.os.path.exists', return_value=False)
    @patch('software.software_agent.sys')
    def test_main_status_with_changes(self, mock_sys, _mock_exists, _mock_isfile,
                                      _mock_cfg, _mock_log, mock_pa_cls):
        mock_sys.argv = ["software-agent", "--status"]
        mock_pa = MagicMock()
        mock_pa.changes = True
        mock_pa_cls.return_value = mock_pa
        with self.assertRaises(SystemExit) as ctx:
            main()
        self.assertEqual(ctx.exception.code, 1)
