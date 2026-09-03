#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for software_agent.py."""

import os
import tempfile
import unittest
from unittest.mock import patch

from software.tests import base  # noqa: F401
from software import constants
from software.software_agent import setflag
from software.software_agent import clearflag
from software.software_agent import PatchMessageHelloAgent
from software.software_agent import PatchMessageQueryDetailed
from software.software_agent import PatchMessageAgentInstallReq
from software.software_agent import PatchMessageAgentInstallResp
from software.software_agent import SoftwareMessageDeployDeleteCleanupResp
from software.software_agent import SoftwareMessageCheckAgentAliveResp
from software.software_agent import PatchAgent


class TestSetClearFlag(unittest.TestCase):
    def test_setflag(self):
        f = os.path.join(tempfile.gettempdir(), "test_flag_set")
        try:
            setflag(f)
            self.assertTrue(os.path.exists(f))
        finally:
            if os.path.exists(f):
                os.unlink(f)

    def test_clearflag(self):
        f = os.path.join(tempfile.gettempdir(), "test_flag_clear")
        with open(f, 'w') as fh:
            fh.write("")
        clearflag(f)
        self.assertFalse(os.path.exists(f))


class TestMessageClasses(unittest.TestCase):
    def test_hello_agent_encode(self):
        msg = PatchMessageHelloAgent()
        msg.encode()
        self.assertIsNotNone(msg.message)

    def test_query_detailed_encode(self):
        msg = PatchMessageQueryDetailed()
        msg.encode()
        self.assertIsNotNone(msg.message)

    def test_install_req_decode(self):
        msg = PatchMessageAgentInstallReq()
        msg.decode({"force": True, "major_release": None, "commit_id": None})
        self.assertTrue(msg.force)

    def test_install_resp_encode(self):
        msg = PatchMessageAgentInstallResp()
        msg.encode()
        self.assertIsNotNone(msg.message)

    def test_deploy_delete_cleanup_resp_encode(self):
        msg = SoftwareMessageDeployDeleteCleanupResp()
        msg.encode()
        self.assertIsNotNone(msg.message)

    def test_check_alive_resp_encode(self):
        msg = SoftwareMessageCheckAgentAliveResp()
        msg.encode()
        self.assertIsNotNone(msg.message)


@patch('software.software_agent.PatchAgent.__init__', return_value=None)
class TestPatchAgentMisc(unittest.TestCase):

    def test_set_install_failed_flags(self, _mock_init):
        a = PatchAgent()
        a.patch_failed = False
        a.state = constants.PATCH_AGENT_STATE_IDLE
        with patch('software.software_agent.setflag'):
            a.set_install_failed_flags()
        self.assertTrue(a.patch_failed)

    @patch('software.software_agent.cfg')
    def test_update_config_loopback(self, mock_cfg, _mock_init):
        a = PatchAgent()
        a.port = 5497
        a.mcast_addr = None
        a.controller_address = None
        a.agent_address = None
        a.pre_bootstrap = False
        mock_cfg.agent_port = 9999
        mock_cfg.get_mgmt_iface.return_value = constants.LOOPBACK_INTERFACE_NAME
        mock_cfg.get_mgmt_ip.return_value = "127.0.0.1"
        a.update_config()
        self.assertEqual(a.port, 9999)
        self.assertIsNone(a.mcast_addr)

    @patch('software.software_agent.cfg')
    def test_update_config_normal(self, mock_cfg, _mock_init):
        a = PatchAgent()
        a.port = 5497
        a.mcast_addr = None
        a.controller_address = None
        a.agent_address = None
        a.pre_bootstrap = False
        mock_cfg.agent_port = 5497
        mock_cfg.get_mgmt_iface.return_value = "mgmt0"
        mock_cfg.controller_mcast_group = "239.1.1.1"
        mock_cfg.agent_mcast_group = "239.1.1.2"
        a.update_config()
        self.assertEqual(a.controller_address, "239.1.1.1")
