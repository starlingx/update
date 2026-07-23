#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import json
import time
import unittest
from unittest.mock import MagicMock
from unittest.mock import patch

from software.tests import base as test_base  # noqa: F401

import software.messages as messages
from software.software_controller import AgentNeighbour
from software.software_controller import ControllerNeighbour
from software.software_controller import PatchMessageAgentInstallReq
from software.software_controller import PatchMessageAgentInstallResp
from software.software_controller import PatchMessageDropHostReq
from software.software_controller import PatchMessageHello
from software.software_controller import PatchMessageHelloAck
from software.software_controller import PatchMessageHelloAgent
from software.software_controller import PatchMessageHelloAgentAck
from software.software_controller import PatchMessageQueryDetailed
from software.software_controller import PatchMessageQueryDetailedResp
from software.software_controller import PatchMessageSendLatestFeedCommit
from software.software_controller import PatchMessageSyncComplete
from software.software_controller import PatchMessageSyncReq
from software.software_controller import SoftwareMessageCheckAgentAliveReq
from software.software_controller import SoftwareMessageCheckAgentAliveResp
from software.software_controller import SoftwareMessageDeployDeleteCleanupReq
from software.software_controller import SoftwareMessageDeployDeleteCleanupResp
from software.software_controller import SoftwareMessageDeployStateUpdate
from software.software_controller import SoftwareMessageDeployStateUpdateAck
from software.software_controller import SoftwareMessageReleaseStateUpdate
from software.software_controller import SWMessageDeployStateChanged
from software.states import DEPLOY_HOST_STATES
from software.states import DEPLOY_STATES
import software.software_controller as sc_mod

FAKE_CONTROLLER_ADDRESS = "127.0.0.1"
FAKE_AGENT_ADDRESS = "127.0.0.2"
FAKE_AGENT_MCAST = "239.1.1.4"
FAKE_HOST_IP = "10.10.10.2"


class FakeSC(object):
    """Minimal stand-in for the sc global used by encode/send."""

    def __init__(self):
        self.patch_op_counter = 1
        self.controller_address = FAKE_CONTROLLER_ADDRESS
        self.agent_address = FAKE_AGENT_ADDRESS
        self.install_local = False


class TestControllerNeighbour(unittest.TestCase):

    def test_init(self):
        cn = ControllerNeighbour()
        self.assertEqual(cn.last_ack, 0)
        self.assertFalse(cn.synced)

    def test_rx_ack(self):
        cn = ControllerNeighbour()
        before = time.time()
        cn.rx_ack()
        after = time.time()
        self.assertGreaterEqual(cn.last_ack, before)
        self.assertLessEqual(cn.last_ack, after)

    def test_get_age(self):
        cn = ControllerNeighbour()
        cn.last_ack = time.time() - 5
        age = cn.get_age()
        self.assertGreaterEqual(age, 4)
        self.assertLessEqual(age, 6)

    def test_rx_synced(self):
        cn = ControllerNeighbour()
        self.assertFalse(cn.get_synced())
        cn.rx_synced()
        self.assertTrue(cn.get_synced())

    def test_clear_synced(self):
        cn = ControllerNeighbour()
        cn.rx_synced()
        cn.clear_synced()
        self.assertFalse(cn.get_synced())


class TestAgentNeighbour(unittest.TestCase):

    def test_init(self):
        an = AgentNeighbour("10.0.0.1")
        self.assertEqual(an.ip, "10.0.0.1")
        self.assertEqual(an.hostname, "n/a")
        self.assertFalse(an.out_of_date)
        self.assertFalse(an.requires_reboot)
        self.assertFalse(an.patch_failed)
        self.assertFalse(an.stale)
        self.assertIsNone(an.latest_sysroot_commit)
        self.assertIsNone(an.nodetype)
        self.assertEqual(an.sw_version, "unknown")
        self.assertEqual(an.subfunctions, [])
        self.assertIsNone(an.state)

    def test_is_alive_property(self):
        an = AgentNeighbour("10.0.0.1")
        self.assertFalse(an.is_alive)
        an.is_alive = True
        self.assertTrue(an.is_alive)

    @patch('software.software_controller.stale_hosts', [])
    @patch('software.software_controller.pending_queries', [])
    def test_rx_ack(self):
        an = AgentNeighbour("10.0.0.1")
        before = time.time()
        an.rx_ack("host-0", True, False, 1, False, "1.0", "idle")
        after = time.time()
        self.assertEqual(an.hostname, "host-0")
        self.assertTrue(an.out_of_date)
        self.assertFalse(an.requires_reboot)
        self.assertFalse(an.patch_failed)
        self.assertEqual(an.sw_version, "1.0")
        self.assertEqual(an.state, "idle")
        self.assertGreaterEqual(an.last_ack, before)
        self.assertLessEqual(an.last_ack, after)

    def test_get_age(self):
        an = AgentNeighbour("10.0.0.1")
        an.last_ack = time.time() - 10
        age = an.get_age()
        self.assertGreaterEqual(age, 9)
        self.assertLessEqual(age, 11)

    @patch('software.software_controller.stale_hosts', [])
    @patch('software.software_controller.pending_queries', [])
    def test_handle_query_detailed_resp(self):
        an = AgentNeighbour("10.0.0.1")
        an.stale = True
        an.pending_query = True
        an.handle_query_detailed_resp(
            "commit123", "controller", "2.0", ["sub1"], "deployed")
        self.assertEqual(an.latest_sysroot_commit, "commit123")
        self.assertEqual(an.nodetype, "controller")
        self.assertEqual(an.sw_version, "2.0")
        self.assertEqual(an.subfunctions, ["sub1"])
        self.assertEqual(an.state, "deployed")
        self.assertFalse(an.stale)
        self.assertFalse(an.pending_query)

    @patch('software.software_controller.stale_hosts', [])
    @patch('software.software_controller.pending_queries', [])
    def test_get_dict(self):
        an = AgentNeighbour("10.0.0.1")
        an.rx_ack("host-0", False, False, 0, False, "1.0", "idle")
        d = an.get_dict()
        self.assertEqual(d["ip"], "10.0.0.1")
        self.assertEqual(d["hostname"], "host-0")
        self.assertTrue(d["deployed"])
        self.assertFalse(d["patch_failed"])
        self.assertFalse(d["stale_details"])
        self.assertEqual(d["sw_version"], "1.0")
        self.assertEqual(d["state"], "idle")
        self.assertIn("secs_since_ack", d)


class TestIsSimplex(unittest.TestCase):

    @patch('software.software_controller.get_system_info',
           return_value=(None, "simplex"))
    def test_simplex(self, _mock):
        sc_mod.system_mode = None
        self.assertTrue(sc_mod.is_simplex())

    @patch('software.software_controller.get_system_info',
           return_value=(None, "duplex"))
    def test_duplex(self, _mock):
        sc_mod.system_mode = None
        self.assertFalse(sc_mod.is_simplex())


class TestMessageInit(unittest.TestCase):
    """Verify __init__ sets the correct msgtype
    for every message class.
    """

    EXPECTED = [
        (PatchMessageHello, messages.PATCHMSG_HELLO),
        (PatchMessageHelloAck, messages.PATCHMSG_HELLO_ACK),
        (PatchMessageSyncReq, messages.PATCHMSG_SYNC_REQ),
        (PatchMessageSyncComplete, messages.PATCHMSG_SYNC_COMPLETE),
        (PatchMessageHelloAgent, messages.PATCHMSG_HELLO_AGENT),
        (PatchMessageSendLatestFeedCommit,
         messages.PATCHMSG_SEND_LATEST_FEED_COMMIT),
        (PatchMessageHelloAgentAck, messages.PATCHMSG_HELLO_AGENT_ACK),
        (PatchMessageQueryDetailed, messages.PATCHMSG_QUERY_DETAILED),
        (PatchMessageQueryDetailedResp, messages.PATCHMSG_QUERY_DETAILED_RESP),
        (PatchMessageAgentInstallReq, messages.PATCHMSG_AGENT_INSTALL_REQ),
        (PatchMessageAgentInstallResp, messages.PATCHMSG_AGENT_INSTALL_RESP),
        (PatchMessageDropHostReq, messages.PATCHMSG_DROP_HOST_REQ),
        (SoftwareMessageDeployStateUpdate,
         messages.PATCHMSG_DEPLOY_STATE_UPDATE),
        (SoftwareMessageDeployStateUpdateAck,
         messages.PATCHMSG_DEPLOY_STATE_UPDATE_ACK),
        (SoftwareMessageReleaseStateUpdate,
         messages.PATCHMSG_RELEASE_STATE_UPDATE),
        (SWMessageDeployStateChanged, messages.PATCHMSG_DEPLOY_STATE_CHANGED),
        (SoftwareMessageDeployDeleteCleanupReq,
         messages.PATCHMSG_DEPLOY_DELETE_CLEANUP_REQ),
        (SoftwareMessageDeployDeleteCleanupResp,
         messages.PATCHMSG_DEPLOY_DELETE_CLEANUP_RESP),
        (SoftwareMessageCheckAgentAliveReq,
         messages.PATCHMSG_CHECK_AGENT_ALIVE_REQ),
        (SoftwareMessageCheckAgentAliveResp,
         messages.PATCHMSG_CHECK_AGENT_ALIVE_RESP),
    ]

    def test_msgtype(self):
        for cls, expected_type in self.EXPECTED:
            obj = cls()
            self.assertEqual(obj.msgtype, expected_type,
                             "%s msgtype mismatch" % cls.__name__)
            self.assertIsInstance(obj, messages.PatchMessage)


class TestMessageEncode(unittest.TestCase):
    """Verify encode() populates the message dict."""

    @patch('software.software_controller.sc', FakeSC())
    def test_hello_encode(self):
        msg = PatchMessageHello()
        msg.encode()
        self.assertIn('msgtype', msg.message)
        self.assertIn('patch_op_counter', msg.message)

    def test_hello_ack_encode(self):
        msg = PatchMessageHelloAck()
        msg.encode()
        self.assertIn('msgtype', msg.message)

    def test_sync_req_encode(self):
        msg = PatchMessageSyncReq()
        msg.encode()
        self.assertIn('msgtype', msg.message)

    def test_sync_complete_encode(self):
        msg = PatchMessageSyncComplete()
        msg.encode()
        self.assertIn('msgtype', msg.message)

    @patch('software.software_controller.sc', FakeSC())
    def test_hello_agent_encode(self):
        msg = PatchMessageHelloAgent()
        msg.encode()
        self.assertIn('patch_op_counter', msg.message)

    def test_send_latest_feed_commit_encode(self):
        msg = PatchMessageSendLatestFeedCommit()
        msg.latest_feed_commit = "abc123"
        msg.encode()
        self.assertEqual(msg.message['latest_feed_commit'], "abc123")

    def test_hello_agent_ack_encode(self):
        msg = PatchMessageHelloAgentAck()
        msg.encode()
        self.assertIn('msgtype', msg.message)

    def test_query_detailed_encode(self):
        msg = PatchMessageQueryDetailed()
        msg.encode()
        self.assertIn('msgtype', msg.message)

    @patch('software.software_controller.sc', FakeSC())
    def test_agent_install_req_encode(self):
        msg = PatchMessageAgentInstallReq()
        msg.force = True
        msg.major_release = "2.0"
        msg.commit_id = "cid"
        msg.encode()
        self.assertTrue(msg.message['force'])
        self.assertEqual(msg.message['major_release'], "2.0")
        self.assertEqual(msg.message['commit_id'], "cid")

    @patch('software.software_controller.sc', FakeSC())
    def test_agent_install_req_encode_additional_data(self):
        msg = PatchMessageAgentInstallReq(additional_data={"key": "val"})
        msg.encode()
        self.assertEqual(msg.message['additional_data'], {"key": "val"})

    def test_agent_install_resp_encode(self):
        msg = PatchMessageAgentInstallResp()
        msg.encode()
        self.assertIn('msgtype', msg.message)

    def test_drop_host_req_encode(self):
        msg = PatchMessageDropHostReq()
        msg.ip = FAKE_HOST_IP
        msg.encode()
        self.assertEqual(msg.message['ip'], FAKE_HOST_IP)

    @patch('software.utils.get_software_filesystem_data',
           return_value={"deploy_host": {"h": 1}, "deploy": {"d": 1}})
    def test_deploy_state_update_encode(self, _mock):
        msg = SoftwareMessageDeployStateUpdate()
        msg.encode()
        self.assertIn('deploy_state', msg.message)
        self.assertEqual(msg.message['deploy_state']['deploy'], {"d": 1})

    @patch('software.utils.get_synced_software_filesystem_data',
           return_value={"synced": True})
    def test_deploy_state_update_ack_encode(self, _mock):
        msg = SoftwareMessageDeployStateUpdateAck()
        msg.encode("success")
        self.assertEqual(msg.message['result'], "success")
        self.assertIn('deploy_state', msg.message)

    def test_release_state_update_encode(self):
        msg = SoftwareMessageReleaseStateUpdate()
        msg.encode()
        self.assertIn('msgtype', msg.message)

    def test_deploy_delete_cleanup_req_encode(self):
        msg = SoftwareMessageDeployDeleteCleanupReq()
        msg.major_release = "3.0"
        msg.encode()
        self.assertEqual(msg.message['major_release'], "3.0")

    def test_deploy_delete_cleanup_resp_encode(self):
        msg = SoftwareMessageDeployDeleteCleanupResp()
        msg.encode()
        self.assertIn('msgtype', msg.message)

    def test_check_agent_alive_req_encode(self):
        msg = SoftwareMessageCheckAgentAliveReq()
        msg.encode()
        self.assertIn('msgtype', msg.message)

    def test_check_agent_alive_resp_encode(self):
        msg = SoftwareMessageCheckAgentAliveResp()
        msg.encode()
        self.assertIn('msgtype', msg.message)


class TestMessageDecode(unittest.TestCase):
    """Verify decode() extracts fields from data dict."""

    def test_hello_decode(self):
        msg = PatchMessageHello()
        msg.decode({'patch_op_counter': 42,
                    'msgtype': messages.PATCHMSG_HELLO})
        self.assertEqual(msg.patch_op_counter, 42)

    def test_hello_decode_missing_counter(self):
        msg = PatchMessageHello()
        msg.decode({'msgtype': messages.PATCHMSG_HELLO})
        self.assertEqual(msg.patch_op_counter, 0)

    def test_hello_agent_ack_decode(self):
        msg = PatchMessageHelloAgentAck()
        data = {
            'query_id': 7,
            'out_of_date': True,
            'hostname': 'worker-0',
            'requires_reboot': True,
            'patch_failed': True,
            'sw_version': '5.0',
            'state': 'deploying',
        }
        msg.decode(data)
        self.assertEqual(msg.query_id, 7)
        self.assertTrue(msg.agent_out_of_date)
        self.assertEqual(msg.agent_hostname, 'worker-0')
        self.assertTrue(msg.agent_requires_reboot)
        self.assertTrue(msg.agent_patch_failed)
        self.assertEqual(msg.agent_sw_version, '5.0')
        self.assertEqual(msg.agent_state, 'deploying')

    def test_hello_agent_ack_decode_defaults(self):
        msg = PatchMessageHelloAgentAck()
        msg.decode({})
        self.assertEqual(msg.query_id, 0)
        self.assertFalse(msg.agent_out_of_date)
        self.assertEqual(msg.agent_hostname, "n/a")

    def test_query_detailed_resp_decode(self):
        msg = PatchMessageQueryDetailedResp()
        data = {
            'latest_sysroot_commit': 'commit456',
            'nodetype': 'worker',
            'sw_version': '3.0',
            'subfunctions': ['compute', 'storage'],
            'state': 'deployed',
        }
        msg.decode(data)
        self.assertEqual(msg.latest_sysroot_commit, 'commit456')
        self.assertEqual(msg.nodetype, 'worker')
        self.assertEqual(msg.agent_sw_version, '3.0')
        self.assertEqual(msg.subfunctions, ['compute', 'storage'])
        self.assertEqual(msg.agent_state, 'deployed')

    def test_query_detailed_resp_decode_defaults(self):
        msg = PatchMessageQueryDetailedResp()
        msg.decode({})
        self.assertEqual(msg.latest_sysroot_commit, "unknown")
        self.assertEqual(msg.nodetype, "unknown")

    def test_agent_install_resp_decode(self):
        msg = PatchMessageAgentInstallResp()
        data = {
            'status': True,
            'reject_reason': 'disk full',
            'reboot_required': True,
        }
        msg.decode(data)
        self.assertTrue(msg.status)
        self.assertEqual(msg.reject_reason, 'disk full')
        self.assertTrue(msg.reboot_required)

    def test_agent_install_resp_decode_defaults(self):
        msg = PatchMessageAgentInstallResp()
        msg.decode({})
        self.assertFalse(msg.status)
        self.assertIsNone(msg.reject_reason)
        self.assertFalse(msg.reboot_required)

    def test_drop_host_req_decode(self):
        msg = PatchMessageDropHostReq()
        msg.decode({'ip': '10.0.0.5'})
        self.assertEqual(msg.ip, '10.0.0.5')

    def test_drop_host_req_decode_no_ip(self):
        msg = PatchMessageDropHostReq()
        msg.decode({})
        self.assertIsNone(msg.ip)

    def test_deploy_state_update_decode(self):
        msg = SoftwareMessageDeployStateUpdate()
        data = {'deploy_state': {'deploy': {}, 'deploy_host': {}}}
        msg.decode(data)
        self.assertEqual(msg.data, data)

    def test_deploy_state_update_ack_decode(self):
        msg = SoftwareMessageDeployStateUpdateAck()
        data = {'result': 'success', 'deploy_state': {}}
        msg.decode(data)
        self.assertEqual(msg.peer_state_data, data)

    def test_deploy_delete_cleanup_resp_decode(self):
        msg = SoftwareMessageDeployDeleteCleanupResp()
        msg.decode({'success': True})
        self.assertTrue(msg.success)

    def test_deploy_delete_cleanup_resp_decode_missing(self):
        msg = SoftwareMessageDeployDeleteCleanupResp()
        msg.decode({})
        self.assertIsNone(msg.success)

    def test_check_agent_alive_resp_decode(self):
        msg = SoftwareMessageCheckAgentAliveResp()
        msg.decode({'msgtype': messages.PATCHMSG_CHECK_AGENT_ALIVE_RESP})
        self.assertEqual(msg.msgtype, messages.PATCHMSG_CHECK_AGENT_ALIVE_RESP)


class TestSWMessageDeployStateChangedDecode(unittest.TestCase):

    def test_valid_deploy_state(self):
        msg = SWMessageDeployStateChanged()
        data = {
            'agent': 'deploy-start',
            'deploy-state': DEPLOY_STATES.START_DONE.value,
        }
        msg.decode(data)
        self.assertTrue(msg.valid)
        self.assertEqual(msg.deploy_state, DEPLOY_STATES.START_DONE)
        self.assertEqual(msg.agent, 'deploy-start')

    def test_valid_host_state(self):
        msg = SWMessageDeployStateChanged()
        data = {
            'agent': 'admin',
            'hostname': 'worker-0',
            'host-state': DEPLOY_HOST_STATES.DEPLOYED.value,
        }
        msg.decode(data)
        self.assertTrue(msg.valid)
        self.assertEqual(msg.hostname, 'worker-0')
        self.assertEqual(msg.host_state, DEPLOY_HOST_STATES.DEPLOYED)
        self.assertIsNone(msg.deploy_state)

    def test_unknown_agent(self):
        msg = SWMessageDeployStateChanged()
        data = {'agent': 'bad-agent'}
        msg.decode(data)
        self.assertFalse(msg.valid)

    def test_missing_agent(self):
        msg = SWMessageDeployStateChanged()
        data = {'deploy-state': DEPLOY_STATES.START_DONE.value}
        msg.decode(data)
        self.assertFalse(msg.valid)

    def test_invalid_deploy_state(self):
        msg = SWMessageDeployStateChanged()
        data = {
            'agent': 'deploy-start',
            'deploy-state': 'bogus-state',
        }
        msg.decode(data)
        self.assertFalse(msg.valid)

    def test_both_deploy_and_host_state_invalid(self):
        msg = SWMessageDeployStateChanged()
        data = {
            'agent': 'admin',
            'deploy-state': DEPLOY_STATES.START_DONE.value,
            'hostname': 'worker-0',
            'host-state': DEPLOY_HOST_STATES.DEPLOYED.value,
        }
        msg.decode(data)
        self.assertFalse(msg.valid)

    def test_activate_done(self):
        msg = SWMessageDeployStateChanged()
        data = {
            'agent': 'deploy-activate',
            'deploy-state': DEPLOY_STATES.ACTIVATE_DONE.value,
        }
        msg.decode(data)
        self.assertTrue(msg.valid)
        self.assertEqual(msg.deploy_state, DEPLOY_STATES.ACTIVATE_DONE)

    def test_activate_rollback_done(self):
        msg = SWMessageDeployStateChanged()
        data = {
            'agent': 'deploy-activate-rollback',
            'deploy-state': DEPLOY_STATES.ACTIVATE_ROLLBACK_DONE.value,
        }
        msg.decode(data)
        self.assertTrue(msg.valid)
        self.assertEqual(
            msg.deploy_state,
            DEPLOY_STATES.ACTIVATE_ROLLBACK_DONE)


class TestMessageSend(unittest.TestCase):
    """Verify send() calls sock.sendto or sock.sendall."""

    def _make_sock(self):
        return MagicMock()

    @patch('software.config.agent_mcast_group', FAKE_AGENT_MCAST)
    @patch('software.software_controller.sc', FakeSC())
    def test_hello_agent_send(self):
        sock = self._make_sock()
        msg = PatchMessageHelloAgent()
        msg.send(sock)
        self.assertGreaterEqual(sock.sendto.call_count, 1)

    @patch('software.config.agent_mcast_group', FAKE_AGENT_MCAST)
    @patch('software.software_controller.sc', FakeSC())
    def test_send_latest_feed_commit_send(self):
        sock = self._make_sock()
        msg = PatchMessageSendLatestFeedCommit()
        msg.send(sock, "commit_abc")
        self.assertGreaterEqual(sock.sendto.call_count, 1)
        sent = json.loads(sock.sendto.call_args_list[0][0][0].decode())
        self.assertEqual(sent['latest_feed_commit'], "commit_abc")


class TestMessageSendPayload(unittest.TestCase):
    """Verify send() transmits valid JSON with expected fields."""

    @patch('software.software_controller.sc', FakeSC())
    def test_hello_payload(self):
        sock = MagicMock()
        msg = PatchMessageHello()
        msg.send(sock)
        raw = sock.sendto.call_args[0][0]
        payload = json.loads(raw.decode())
        self.assertEqual(payload['msgtype'], messages.PATCHMSG_HELLO)
        self.assertEqual(payload['patch_op_counter'], 1)

    @patch('software.software_controller.sc', FakeSC())
    def test_drop_host_req_payload(self):
        sock = MagicMock()
        msg = PatchMessageDropHostReq()
        msg.ip = "10.0.0.99"
        msg.send(sock)
        raw = sock.sendto.call_args[0][0]
        payload = json.loads(raw.decode())
        self.assertEqual(payload['ip'], "10.0.0.99")

    @patch('software.software_controller.sc', FakeSC())
    def test_agent_install_req_payload(self):
        sock = MagicMock()
        msg = PatchMessageAgentInstallReq()
        msg.ip = FAKE_HOST_IP
        msg.force = True
        msg.major_release = "9.0"
        msg.commit_id = "ccc"
        msg.send(sock)
        raw = sock.sendto.call_args[0][0]
        payload = json.loads(raw.decode())
        self.assertTrue(payload['force'])
        self.assertEqual(payload['major_release'], "9.0")
        self.assertEqual(payload['commit_id'], "ccc")
