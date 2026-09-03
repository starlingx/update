#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from software import messages
from unittest.mock import MagicMock
from unittest.mock import patch
import unittest
from software.tests import base  # noqa: F401
from software.software_agent import PatchMessageSendLatestFeedCommit
from software.software_agent import PatchMessageHelloAgent
from software import constants
from software.software_agent import PatchMessageHelloAgentAck
from software.software_agent import PatchMessageQueryDetailedResp
from software.software_agent import PatchMessageAgentInstallReq


class TestAgentMessageClasses(unittest.TestCase):
    """Test encode/decode/handle/send for agent message classes."""

    def _mock_pa(self):
        pa = MagicMock()
        pa.changes = False
        pa.node_is_patched = False
        pa.patch_failed = False
        pa.state = 'idle'
        pa.query_id = 1
        pa.latest_sysroot_commit = 'abc'
        pa.latest_feed_commit = 'def'
        pa.controller_address = '127.0.0.1'
        pa.pre_bootstrap = False
        return pa

    @patch('software.software_agent.pa')
    def test_send_latest_feed_commit_decode(self, mock_pa):
        msg = PatchMessageSendLatestFeedCommit()
        msg.decode({'msgtype': messages.PATCHMSG_SEND_LATEST_FEED_COMMIT,
                    'msgversion': 1, 'latest_feed_commit': 'xyz'})
        self.assertEqual(mock_pa.latest_feed_commit, 'xyz')

    @patch('software.software_agent.pa')
    def test_hello_agent_decode(self, _mock_pa):
        msg = PatchMessageHelloAgent()
        msg.decode({'msgtype': messages.PATCHMSG_HELLO_AGENT,
                    'msgversion': 1, 'patch_op_counter': 5})
        self.assertEqual(msg.patch_op_counter, 5)

    @patch('software.software_agent.pa')
    @patch('software.software_agent.time')
    @patch('software.software_agent.os.path.exists', return_value=True)
    def test_hello_agent_handle_rejected_locked(
            self, _mock_exists, _mock_time, mock_pa):
        mock_pa.state = constants.PATCH_AGENT_STATE_INSTALL_REJECTED
        msg = PatchMessageHelloAgent()
        msg.patch_op_counter = 0
        with patch('software.software_agent.PatchMessageHelloAgentAck'):
            msg.handle(MagicMock(), ('127.0.0.1', 1234))
        self.assertEqual(mock_pa.state, constants.PATCH_AGENT_STATE_IDLE)

    @patch('software.software_agent.cfg')
    @patch('software.software_agent.pa')
    def test_hello_agent_ack_encode(self, mock_pa, _mock_cfg):
        mock_pa.pre_bootstrap = False
        mock_pa.query_id = 42
        mock_pa.changes = True
        mock_pa.node_is_patched = False
        mock_pa.patch_failed = False
        mock_pa.state = 'idle'
        msg = PatchMessageHelloAgentAck()
        msg.encode()
        self.assertEqual(msg.message['query_id'], 42)
        self.assertTrue(msg.message['out_of_date'])
        self.assertFalse(msg.message['requires_reboot'])
        self.assertFalse(msg.message['patch_failed'])
        self.assertEqual(msg.message['state'], 'idle')
        # not pre_bootstrap, so the real hostname is used
        self.assertNotEqual(msg.message['hostname'],
                            constants.PREBOOTSTRAP_HOSTNAME)

    @patch('software.software_agent.cfg')
    @patch('software.software_agent.pa')
    def test_hello_agent_ack_encode_pre_bootstrap(self, mock_pa, _mock_cfg):
        """Before bootstrap the placeholder hostname is sent, since the real
        hostname is not yet meaningful.
            """
        mock_pa.pre_bootstrap = True
        mock_pa.query_id = 7
        mock_pa.changes = False
        mock_pa.node_is_patched = False
        mock_pa.patch_failed = False
        mock_pa.state = 'idle'
        msg = PatchMessageHelloAgentAck()
        msg.encode()
        self.assertEqual(msg.message['hostname'],
                         constants.PREBOOTSTRAP_HOSTNAME)

    @patch('software.software_agent.cfg')
    @patch('software.software_agent.pa')
    def test_query_detailed_resp_encode(self, mock_pa, mock_cfg):
        mock_pa.latest_sysroot_commit = 'abc'
        mock_pa.state = 'idle'
        mock_cfg.nodetype = 'controller'
        msg = PatchMessageQueryDetailedResp()
        msg.encode()
        self.assertEqual(msg.message['latest_sysroot_commit'], 'abc')

    @patch('software.software_agent.pa')
    def test_install_req_decode(self, _mock_pa):
        msg = PatchMessageAgentInstallReq()
        msg.decode({'msgtype': messages.PATCHMSG_AGENT_INSTALL_REQ,
                    'msgversion': 1, 'force': True,
                    'major_release': '25.03', 'commit_id': 'abc',
                    'additional_data': {'key': 'val'}})
        self.assertTrue(msg.force)
        self.assertEqual(msg.major_release, '25.03')
        self.assertEqual(msg.commit_id, 'abc')
        self.assertEqual(msg.additional_data, {'key': 'val'})

    @patch('software.software_agent.pa')
    @patch('software.software_agent.os.path.exists', return_value=False)
    def test_install_req_handle_rejected(self, _mock_exists, mock_pa):
        msg = PatchMessageAgentInstallReq()
        msg.force = False
        sock = MagicMock()
        with patch('software.software_agent.PatchMessageAgentInstallResp'):
            with patch('software.software_agent.PatchMessageHelloAgentAck'):
                msg.handle(sock, ('127.0.0.1', 1234))
        self.assertEqual(
            mock_pa.state,
            constants.PATCH_AGENT_STATE_INSTALL_REJECTED)
