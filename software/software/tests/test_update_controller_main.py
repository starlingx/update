#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import os
import socket
import threading
import time
import unittest
from unittest import mock
from unittest.mock import MagicMock
from unittest.mock import patch

from software.tests import base as test_base  # noqa: F401

import software.messages as messages
from software.software_controller import AgentNeighbour
from software.software_controller import ControllerNeighbour
from software.software_controller import PatchControllerApiThread
from software.software_controller import PatchControllerAuthApiThread
from software.software_controller import PatchControllerMainThread
from software.software_controller import PatchMessageAgentInstallResp
from software.software_controller import PatchMessageDropHostReq
from software.software_controller import PatchMessageHello
from software.software_controller import PatchMessageHelloAck
from software.software_controller import PatchMessageHelloAgentAck
from software.software_controller import PatchMessageQueryDetailedResp
from software.software_controller import PatchMessageSyncComplete
from software.software_controller import PatchMessageSyncReq
from software.software_controller import SoftwareMessageCheckAgentAliveResp
from software.software_controller import SoftwareMessageDeployDeleteCleanupResp
from software.software_controller import SoftwareMessageDeployStateUpdate
from software.software_controller import SoftwareMessageDeployStateUpdateAck
from software.software_controller import SWMessageDeployStateChanged
from software.states import DEPLOY_HOST_STATES
from software.states import DEPLOY_STATES
from software.software_controller import insvc_patch_restart_controller
from software.software_controller import main

FAKE_CONTROLLER_ADDR = "192.168.204.2"
FAKE_AGENT_ADDR = "192.168.204.3"
FAKE_HOST_IP = "10.10.10.2"
FAKE_MGMT_IP = "192.168.204.1"


def _make_sc_mock():
    """Return a MagicMock that mimics the global sc PatchController."""
    sc = MagicMock()
    sc.controller_address = FAKE_CONTROLLER_ADDR
    sc.agent_address = FAKE_AGENT_ADDR
    sc.mgmt_ip = FAKE_MGMT_IP
    sc.patch_op_counter = 1
    sc.install_local = False
    sc.pre_bootstrap = False
    sc.hostname = "controller-0"
    sc.sock_in = MagicMock()
    sc.sock_out = MagicMock()
    sc.socket_lock = MagicMock()
    sc.controller_neighbours_lock = MagicMock()
    sc.hosts_lock = MagicMock()
    sc.hosts = {}
    sc.controller_neighbours = {}
    sc.interim_state = {}
    sc.ignore_errors = "False"
    sc.setup_socket.return_value = sc.sock_in
    sc.is_host_active_controller.return_value = True
    sc.set_interruption_fail_state.return_value = None
    return sc


class TestPatchMessageHelloAckHandle(unittest.TestCase):

    @patch('software.software_controller.sc')
    def test_handle_new_neighbour(self, mock_sc):
        mock_sc.controller_neighbours = {}
        mock_sc.controller_neighbours_lock = MagicMock()
        msg = PatchMessageHelloAck()
        msg.handle(MagicMock(), (FAKE_HOST_IP, 1234))
        self.assertIn(FAKE_HOST_IP, mock_sc.controller_neighbours)

    @patch('software.software_controller.sc')
    def test_handle_multiple_neighbours(self, mock_sc):
        mock_sc.controller_neighbours = {}
        mock_sc.controller_neighbours_lock = MagicMock()
        msg = PatchMessageHelloAck()
        msg.handle(MagicMock(), ("10.0.0.1", 1234))
        msg.handle(MagicMock(), ("10.0.0.2", 1234))
        self.assertEqual(len(mock_sc.controller_neighbours), 2)


class TestPatchMessageSyncReqHandle(unittest.TestCase):

    @patch('software.software_controller.sc')
    @patch('software.software_controller.cfg')
    @patch('software.software_controller.time')
    def test_handle_sync_retries_on_failure(self, _mock_time, mock_cfg,
                                            mock_sc):
        mock_cfg.get_mgmt_ip.return_value = FAKE_MGMT_IP
        mock_cfg.controller_port = 5678
        mock_sc.controller_address = FAKE_CONTROLLER_ADDR
        mock_sc.sync_from_nbr.side_effect = [False, False, True]
        mock_sock = MagicMock()
        msg = PatchMessageSyncReq()
        msg.handle(mock_sock, (FAKE_HOST_IP, 1234))
        self.assertEqual(mock_sc.sync_from_nbr.call_count, 3)
        mock_sock.sendto.assert_called_once()

    @patch('software.software_controller.sc')
    @patch('software.software_controller.cfg')
    @patch('software.software_controller.time')
    def test_handle_sync_all_retries_fail(self, _mock_time, mock_cfg, mock_sc):
        mock_cfg.get_mgmt_ip.return_value = FAKE_MGMT_IP
        mock_cfg.controller_port = 5678
        mock_sc.controller_address = FAKE_CONTROLLER_ADDR
        mock_sc.sync_from_nbr.return_value = False
        mock_sock = MagicMock()
        msg = PatchMessageSyncReq()
        msg.handle(mock_sock, (FAKE_HOST_IP, 1234))
        self.assertEqual(mock_sc.sync_from_nbr.call_count, 3)
        mock_sock.sendto.assert_not_called()

    @patch('software.software_controller.sc')
    @patch('software.software_controller.cfg')
    @patch('software.software_controller.time')
    def test_handle_sync_success_second_attempt(self, _mock_time, mock_cfg,
                                                mock_sc):
        mock_cfg.get_mgmt_ip.return_value = FAKE_MGMT_IP
        mock_cfg.controller_port = 5678
        mock_sc.controller_address = FAKE_CONTROLLER_ADDR
        mock_sc.sync_from_nbr.side_effect = [False, True]
        mock_sock = MagicMock()
        msg = PatchMessageSyncReq()
        msg.handle(mock_sock, (FAKE_HOST_IP, 1234))
        self.assertEqual(mock_sc.sync_from_nbr.call_count, 2)
        mock_sock.sendto.assert_called_once()


class TestPatchMessageSyncCompleteHandle(unittest.TestCase):

    @patch('software.software_controller.sc')
    def test_handle_new_neighbour(self, mock_sc):
        mock_sc.controller_neighbours = {}
        mock_sc.controller_neighbours_lock = MagicMock()
        msg = PatchMessageSyncComplete()
        msg.handle(MagicMock(), (FAKE_HOST_IP, 1234))
        self.assertIn(FAKE_HOST_IP, mock_sc.controller_neighbours)


class TestPatchMessageHelloAgentAckHandle(unittest.TestCase):

    @patch('software.software_controller.sc')
    def test_handle_new_host(self, mock_sc):
        mock_sc.hosts = {}
        mock_sc.hosts_lock = MagicMock()
        msg = PatchMessageHelloAgentAck()
        msg.decode({
            'msgtype': messages.PATCHMSG_HELLO_AGENT_ACK,
            'msgversion': 1,
            'query_id': 1,
            'out_of_date': False,
            'hostname': 'worker-0',
            'requires_reboot': False,
            'patch_failed': False,
            'sw_version': '24.09',
            'state': 'idle',
        })
        msg.handle(MagicMock(), (FAKE_HOST_IP, 1234))
        self.assertIn(FAKE_HOST_IP, mock_sc.hosts)

    @patch('software.software_controller.stale_hosts', [])
    @patch('software.software_controller.pending_queries', [])
    @patch('software.software_controller.sc')
    def test_handle_defaults_when_no_fields(self, mock_sc):
        mock_sc.hosts = {}
        mock_sc.hosts_lock = MagicMock()
        msg = PatchMessageHelloAgentAck()
        msg.decode({'msgtype': messages.PATCHMSG_HELLO_AGENT_ACK,
                    'msgversion': 1})
        msg.handle(MagicMock(), (FAKE_HOST_IP, 1234))
        host = mock_sc.hosts[FAKE_HOST_IP]
        self.assertEqual(host.hostname, 'n/a')

    @patch('software.software_controller.stale_hosts', [])
    @patch('software.software_controller.pending_queries', [])
    @patch('software.software_controller.sc')
    def test_handle_decode_partial_data(self, mock_sc):
        mock_sc.hosts = {}
        mock_sc.hosts_lock = MagicMock()
        msg = PatchMessageHelloAgentAck()
        msg.decode({'msgtype': messages.PATCHMSG_HELLO_AGENT_ACK,
                    'msgversion': 1,
                    'hostname': 'ctrl-1',
                    'sw_version': '25.03'})
        msg.handle(MagicMock(), (FAKE_HOST_IP, 1234))
        host = mock_sc.hosts[FAKE_HOST_IP]
        self.assertEqual(host.hostname, 'ctrl-1')
        self.assertEqual(host.sw_version, '25.03')


class TestPatchMessageQueryDetailedRespHandle(unittest.TestCase):

    @patch('software.software_controller.sc')
    def test_handle_clears_interim_state(self, mock_sc):
        agent = MagicMock()
        mock_sc.hosts = {FAKE_HOST_IP: agent}
        mock_sc.hosts_lock = MagicMock()
        mock_sc.interim_state = {'patch-1': [FAKE_HOST_IP]}
        msg = PatchMessageQueryDetailedResp()
        msg.decode({'msgtype': messages.PATCHMSG_QUERY_DETAILED_RESP,
                    'msgversion': 1})
        msg.handle(MagicMock(), (FAKE_HOST_IP, 1234))
        self.assertNotIn('patch-1', mock_sc.interim_state)

    @patch('software.software_controller.sc')
    def test_handle_interim_state_other_hosts_remain(self, mock_sc):
        agent = MagicMock()
        mock_sc.hosts = {FAKE_HOST_IP: agent}
        mock_sc.hosts_lock = MagicMock()
        mock_sc.interim_state = {'patch-1': [FAKE_HOST_IP, '10.0.0.99']}
        msg = PatchMessageQueryDetailedResp()
        msg.decode({'msgtype': messages.PATCHMSG_QUERY_DETAILED_RESP,
                    'msgversion': 1})
        msg.handle(MagicMock(), (FAKE_HOST_IP, 1234))
        self.assertEqual(mock_sc.interim_state['patch-1'], ['10.0.0.99'])


class TestPatchMessageAgentInstallRespHandle(unittest.TestCase):

    def _make_host(self, hostname='worker-0'):
        host = MagicMock()
        host.hostname = hostname
        host.install_status = False
        host.install_pending = True
        host.install_reject_reason = None
        return host

    @patch('software.software_controller.DeployHostState')
    @patch('software.software_controller.get_instance')
    @patch('software.software_controller.sc')
    def test_handle_unknown_host_creates_entry(self, mock_sc, mock_get_inst,
                                               _mock_dhs_cls):
        mock_sc.hosts = {}
        mock_sc.hosts_lock = MagicMock()
        mock_get_inst.return_value.get_deploy_all.return_value = []
        msg = PatchMessageAgentInstallResp()
        msg.decode({'msgtype': messages.PATCHMSG_AGENT_INSTALL_RESP,
                    'msgversion': 1, 'status': True})
        msg.handle(MagicMock(), (FAKE_HOST_IP, 1234))
        self.assertIn(FAKE_HOST_IP, mock_sc.hosts)

    @patch('software.software_controller.DeployHostState')
    @patch('software.software_controller.get_instance')
    @patch('software.software_controller.sc')
    def test_set_host_install_completed(self, mock_sc, mock_get_inst,
                                        _mock_dhs_cls):
        host = self._make_host()
        host.install_pending = True
        mock_sc.hosts = {FAKE_HOST_IP: host}
        mock_sc.hosts_lock = MagicMock()
        mock_get_inst.return_value.get_deploy_all.return_value = []
        msg = PatchMessageAgentInstallResp()
        msg.status = True
        msg.reject_reason = None
        msg._set_host_install_completed(host)
        self.assertTrue(host.install_status)
        self.assertFalse(host.install_pending)


class TestSWMessageDeployStateChangedHandle(unittest.TestCase):

    def _make_valid_deploy_state_data(
            self, deploy_state, agent='deploy-start'):
        return {
            'msgtype': messages.PATCHMSG_DEPLOY_STATE_CHANGED,
            'msgversion': 1,
            'agent': agent,
            'deploy-state': deploy_state,
        }

    def _make_valid_host_state_data(self, hostname, host_state,
                                    agent='deploy-start'):
        return {
            'msgtype': messages.PATCHMSG_DEPLOY_STATE_CHANGED,
            'msgversion': 1,
            'agent': agent,
            'hostname': hostname,
            'host-state': host_state,
        }

    def test_decode_invalid_deploy_state(self):
        data = {
            'msgtype': messages.PATCHMSG_DEPLOY_STATE_CHANGED,
            'msgversion': 1,
            'agent': 'deploy-start',
            'deploy-state': 'bogus-state',
        }
        msg = SWMessageDeployStateChanged()
        msg.decode(data)
        self.assertFalse(msg.valid)

    def test_decode_invalid_host_state(self):
        data = {
            'msgtype': messages.PATCHMSG_DEPLOY_STATE_CHANGED,
            'msgversion': 1,
            'agent': 'deploy-start',
            'hostname': 'worker-0',
            'host-state': 'bogus-host-state',
        }
        msg = SWMessageDeployStateChanged()
        with self.assertRaises(ValueError):
            msg.decode(data)

    def test_decode_both_deploy_and_host_state_invalid(self):
        data = {
            'msgtype': messages.PATCHMSG_DEPLOY_STATE_CHANGED,
            'msgversion': 1,
            'agent': 'deploy-start',
            'deploy-state': DEPLOY_STATES.START_DONE.value,
            'hostname': 'worker-0',
            'host-state': DEPLOY_HOST_STATES.DEPLOYED.value,
        }
        msg = SWMessageDeployStateChanged()
        msg.decode(data)
        self.assertFalse(msg.valid)

    def test_decode_activate_done(self):
        data = self._make_valid_deploy_state_data(
            DEPLOY_STATES.ACTIVATE_DONE.value, agent='deploy-activate')
        msg = SWMessageDeployStateChanged()
        msg.decode(data)
        self.assertTrue(msg.valid)
        self.assertEqual(msg.deploy_state, DEPLOY_STATES.ACTIVATE_DONE)

    def test_decode_activate_failed(self):
        data = self._make_valid_deploy_state_data(
            DEPLOY_STATES.ACTIVATE_FAILED.value, agent='deploy-activate')
        msg = SWMessageDeployStateChanged()
        msg.decode(data)
        self.assertTrue(msg.valid)
        self.assertEqual(msg.deploy_state, DEPLOY_STATES.ACTIVATE_FAILED)

    def test_decode_activate_rollback_done(self):
        data = self._make_valid_deploy_state_data(
            DEPLOY_STATES.ACTIVATE_ROLLBACK_DONE.value,
            agent='deploy-activate-rollback')
        msg = SWMessageDeployStateChanged()
        msg.decode(data)
        self.assertTrue(msg.valid)

    def test_decode_activate_rollback_failed(self):
        data = self._make_valid_deploy_state_data(
            DEPLOY_STATES.ACTIVATE_ROLLBACK_FAILED.value,
            agent='deploy-activate-rollback')
        msg = SWMessageDeployStateChanged()
        msg.decode(data)
        self.assertTrue(msg.valid)

    def test_decode_host_failed(self):
        data = self._make_valid_deploy_state_data(
            DEPLOY_STATES.HOST_FAILED.value, agent='admin')
        msg = SWMessageDeployStateChanged()
        msg.decode(data)
        self.assertTrue(msg.valid)
        self.assertEqual(msg.deploy_state, DEPLOY_STATES.HOST_FAILED)

    def test_decode_no_agent_defaults_unknown(self):
        data = {
            'msgtype': messages.PATCHMSG_DEPLOY_STATE_CHANGED,
            'msgversion': 1,
            'deploy-state': DEPLOY_STATES.START_DONE.value,
        }
        msg = SWMessageDeployStateChanged()
        msg.decode(data)
        self.assertFalse(msg.valid)
        self.assertEqual(msg.agent, 'unknown')

    def test_decode_empty_deploy_state(self):
        data = {
            'msgtype': messages.PATCHMSG_DEPLOY_STATE_CHANGED,
            'msgversion': 1,
            'agent': 'deploy-start',
            'deploy-state': '',
        }
        msg = SWMessageDeployStateChanged()
        msg.decode(data)
        self.assertFalse(msg.valid)


class TestSoftwareMessageCheckAgentAliveRespHandle(unittest.TestCase):

    @patch('software.software_controller.sc')
    def test_handle_sets_alive(self, mock_sc):
        host = MagicMock()
        host.is_alive = False
        mock_sc.hosts = {FAKE_HOST_IP: host}
        mock_sc.hosts_lock = MagicMock()
        msg = SoftwareMessageCheckAgentAliveResp()
        msg.decode({'msgtype': messages.PATCHMSG_CHECK_AGENT_ALIVE_RESP,
                    'msgversion': 1})
        msg.handle(MagicMock(), (FAKE_HOST_IP, 1234))
        self.assertTrue(host.is_alive)


class TestPatchControllerApiThread(unittest.TestCase):

    @patch('software.software_controller.app')
    @patch('software.software_controller.simple_server')
    @patch('software.software_controller.cfg')
    @patch('software.software_controller.thread_death',
           new_callable=threading.Event)
    @patch('software.software_controller.keep_running', True)
    def test_run_starts_wsgi(self, mock_td, mock_cfg, mock_ss, _mock_app):
        mock_cfg.api_port = 15491
        mock_wsgi = MagicMock()
        mock_wsgi.timeout = 5.0
        call_count = [0]

        def handle_once():
            call_count[0] += 1
            if call_count[0] >= 2:
                mock_td.set()

        mock_wsgi.handle_request.side_effect = handle_once
        mock_ss.make_server.return_value = mock_wsgi
        t = PatchControllerApiThread()
        t.run()
        mock_ss.make_server.assert_called_once()
        self.assertGreaterEqual(mock_wsgi.handle_request.call_count, 1)

    @patch('software.software_controller.thread_death',
           new_callable=threading.Event)
    def test_run_exception_sets_thread_death(self, mock_td):
        with patch('software.software_controller.cfg') as mock_cfg:
            mock_cfg.api_port = 15491
            with patch('software.software_controller.simple_server') as ms:
                ms.make_server.side_effect = Exception("bind fail")
                t = PatchControllerApiThread()
                t.run()
                self.assertTrue(mock_td.is_set())

    @patch('software.software_controller.app')
    @patch('software.software_controller.simple_server')
    @patch('software.software_controller.cfg')
    @patch('software.software_controller.thread_death',
           new_callable=threading.Event)
    @patch('software.software_controller.keep_running', True)
    def test_run_socket_timeout_continues(self, mock_td, mock_cfg, mock_ss,
                                          _mock_app):
        mock_cfg.api_port = 15491
        mock_wsgi = MagicMock()
        mock_wsgi.timeout = 5.0
        call_count = [0]

        def handle_req():
            call_count[0] += 1
            if call_count[0] == 1:
                raise socket.timeout()
            mock_td.set()

        mock_wsgi.handle_request.side_effect = handle_req
        mock_ss.make_server.return_value = mock_wsgi
        t = PatchControllerApiThread()
        t.run()
        self.assertEqual(call_count[0], 2)

    @patch('software.software_controller.app')
    @patch('software.software_controller.simple_server')
    @patch('software.software_controller.cfg')
    @patch('software.software_controller.thread_death',
           new_callable=threading.Event)
    @patch('software.software_controller.keep_running', True)
    def test_run_handle_exception_sets_death(self, mock_td, mock_cfg, mock_ss,
                                             _mock_app):
        mock_cfg.api_port = 15491
        mock_wsgi = MagicMock()
        mock_wsgi.timeout = 5.0
        mock_wsgi.handle_request.side_effect = RuntimeError("crash")
        mock_ss.make_server.return_value = mock_wsgi
        t = PatchControllerApiThread()
        t.run()
        self.assertTrue(mock_td.is_set())


class TestPatchControllerAuthApiThread(unittest.TestCase):

    @patch('software.software_controller.thread_death',
           new_callable=threading.Event)
    def test_kill_with_wsgi(self, mock_td):
        t = PatchControllerAuthApiThread(5001)
        t.wsgi = MagicMock()
        t.kill()
        t.wsgi.shutdown.assert_called_once()
        self.assertTrue(mock_td.is_set())

    @patch('software.software_controller.thread_death',
           new_callable=threading.Event)
    @patch('software.software_controller.keep_running', True)
    @patch('software.software_controller.os.path.exists')
    def test_run_exception_sets_thread_death(self, mock_exists, mock_td):
        mock_exists.return_value = True
        with patch('software.software_controller.CONF') as mock_conf:
            mock_conf.auth_api_bind_ip = None
            with patch('software.software_controller.utils') as mu:
                mu.get_versioned_address_all.return_value = '0.0.0.0'
                mu.get_management_family.return_value = socket.AF_INET
                with patch('software.software_controller.simple_server') as ms:
                    ms.make_server.side_effect = Exception("bind fail")
                    t = PatchControllerAuthApiThread(5001)
                    t.run()
                    self.assertTrue(mock_td.is_set())

    def test_init_name(self):
        with patch('software.software_controller.thread_death',
                   new_callable=threading.Event):
            t = PatchControllerAuthApiThread(5001)
            self.assertEqual(t.name, "PatchControllerAuthApiThread_5001")
            self.assertEqual(t.port, 5001)

    @patch('software.software_controller.auth_app')
    @patch('software.software_controller.utils')
    @patch('software.software_controller.simple_server')
    @patch('software.software_controller.CONF')
    @patch('software.software_controller.os.path.exists', return_value=True)
    @patch('software.software_controller.thread_death',
           new_callable=threading.Event)
    @patch('software.software_controller.keep_running', True)
    def test_run_socket_timeout_continues(self, mock_td, _mock_exists,
                                          mock_conf, mock_ss, mock_utils,
                                          _mock_auth_app):
        mock_conf.auth_api_bind_ip = '0.0.0.0'
        mock_utils.get_management_family.return_value = socket.AF_INET
        mock_wsgi = MagicMock()
        mock_wsgi.timeout = 5.0
        call_count = [0]

        def handle_req():
            call_count[0] += 1
            if call_count[0] == 1:
                raise socket.timeout()
            mock_td.set()

        mock_wsgi.handle_request.side_effect = handle_req
        mock_ss.make_server.return_value = mock_wsgi
        t = PatchControllerAuthApiThread(5001)
        t.run()
        self.assertEqual(call_count[0], 2)


class TestPatchControllerMainThreadRun(unittest.TestCase):

    def _setup_sc_and_patches(self):
        """Return a dict of common patches for
        the main thread run loop.
        """
        sc = _make_sc_mock()
        patches = {
            'sc': patch('software.software_controller.sc', sc),
            'thread_death': patch(
                'software.software_controller.thread_death',
                threading.Event()),
            'cfg': patch('software.software_controller.cfg'),
            'os_environ': patch.dict(os.environ, {}, clear=False),
            'open': patch(
                'builtins.open',
                mock.mock_open(
                    read_data='nameserver 8.8.8.8')),
            'os_path_isfile': patch(
                'software.software_controller'
                '.os.path.isfile',
                return_value=False),
            'os_path_exists': patch(
                'software.software_controller'
                '.os.path.exists',
                return_value=False),
            'time_module': patch('software.software_controller.time'),
            'select_module': patch('software.software_controller.select'),
            'json_module': patch('software.software_controller.json'),
            'is_simplex': patch('software.software_controller.is_simplex',
                                return_value=True),
            'is_deploy_in_progress': patch(
                'software.software_controller.is_deployment_in_progress',
                return_value=False),
            'is_active': patch(
                'software.software_controller'
                '.utils.is_active_controller',
                return_value=True),
        }
        return sc, patches

    def _start_patches(self, patches):
        mocks = {}
        for name, p in patches.items():
            mocks[name] = p.start()
        return mocks

    def _stop_patches(self, patches):
        for p in patches.values():
            p.stop()

    def test_init(self):
        t = PatchControllerMainThread()
        self.assertEqual(t.name, "PatchControllerMainThread")

    @patch('software.software_controller.is_simplex', return_value=True)
    @patch('software.software_controller.is_deployment_in_progress',
           return_value=False)
    @patch('software.software_controller.select')
    @patch('software.software_controller.time')
    @patch('software.software_controller.os.path.exists')
    @patch('software.software_controller.os.path.isfile', return_value=False)
    @patch('builtins.open', mock.mock_open(read_data='nameserver 8.8.8.8'))
    @patch('software.software_controller.cfg')
    @patch('software.software_controller.thread_death',
           new_callable=threading.Event)
    @patch('software.software_controller.sc')
    def test_run_insvc_restart_flag(self, mock_sc, mock_td, mock_cfg,
                                    mock_time, mock_select,
                                    _mock_isfile, mock_exists,
                                    _mock_is_deploy, _mock_is_simplex):
        mock_sc.pre_bootstrap = False
        mock_sc.install_local = False
        mock_sc.setup_socket.return_value = MagicMock()
        mock_sc.sock_in = MagicMock()
        mock_sc.sock_out = MagicMock()
        mock_sc.socket_lock = MagicMock()
        mock_sc.controller_neighbours_lock = MagicMock()
        mock_sc.hosts_lock = MagicMock()
        mock_sc.hosts = {}
        mock_sc.controller_neighbours = {}
        mock_sc.interim_state = {}
        mock_sc.ignore_errors = 'False'
        mock_sc.hostname = 'ctrl-0'
        mock_sc.is_host_active_controller.return_value = True
        mock_cfg.get_mgmt_ip.return_value = FAKE_MGMT_IP
        mock_cfg.controller_port = 5678
        mock_cfg.agent_port = 5491
        mock_cfg.agent_mcast_group = '239.1.1.4'
        mock_sc.patch_op_counter = 1
        mock_time.time.return_value = 1000.0

        call_count = [0]

        def fake_exists(path):
            call_count[0] += 1
            if path == insvc_patch_restart_controller:
                return True
            return False

        mock_exists.side_effect = fake_exists
        mock_select.select.return_value = ([], [], [])

        with patch('software.software_controller.os.remove'):
            t = PatchControllerMainThread()
            t.run()
        self.assertTrue(mock_td.is_set())

    @patch('software.software_controller.is_simplex', return_value=True)
    @patch('software.software_controller.is_deployment_in_progress',
           return_value=False)
    @patch('software.software_controller.select')
    @patch('software.software_controller.time')
    @patch('software.software_controller.os.path.exists', return_value=False)
    @patch('software.software_controller.os.path.isfile', return_value=False)
    @patch('builtins.open', mock.mock_open(read_data='nameserver 8.8.8.8'))
    @patch('software.software_controller.cfg')
    @patch('software.software_controller.thread_death',
           new_callable=threading.Event)
    @patch('software.software_controller.sc')
    def test_run_setup_socket_retry(self, mock_sc, mock_td, mock_cfg,
                                    mock_time, mock_select,
                                    _mock_isfile, _mock_exists,
                                    _mock_is_deploy, _mock_is_simplex):
        mock_sc.pre_bootstrap = False
        mock_sc.install_local = False
        mock_sc.setup_socket.side_effect = [None, MagicMock()]
        mock_sc.sock_in = MagicMock()
        mock_sc.sock_out = MagicMock()
        mock_sc.socket_lock = MagicMock()
        mock_sc.controller_neighbours_lock = MagicMock()
        mock_sc.hosts_lock = MagicMock()
        mock_sc.hosts = {}
        mock_sc.controller_neighbours = {}
        mock_sc.interim_state = {}
        mock_sc.ignore_errors = 'False'
        mock_sc.hostname = 'ctrl-0'
        mock_sc.is_host_active_controller.return_value = True
        mock_cfg.get_mgmt_ip.return_value = FAKE_MGMT_IP
        mock_cfg.controller_port = 5678
        mock_cfg.agent_port = 5491
        mock_cfg.agent_mcast_group = '239.1.1.4'
        mock_sc.patch_op_counter = 1
        mock_time.time.return_value = 1000.0
        mock_td.set()
        mock_select.select.return_value = ([], [], [])
        t = PatchControllerMainThread()
        t.run()
        self.assertEqual(mock_sc.setup_socket.call_count, 2)


class TestMainFunction(unittest.TestCase):

    @patch('builtins.open', mock.mock_open())
    @patch('software.software_controller.PatchControllerMainThread')
    @patch('software.software_controller.PatchControllerAuthApiThread')
    @patch('software.software_controller.PatchControllerApiThread')
    @patch('software.software_controller.PatchController')
    @patch('software.software_controller.configure_logging')
    @patch('software.software_controller.cfg')
    @patch('software.software_controller.CONF')
    @patch('software.software_controller.configparser')
    @patch('software.software_controller.os.environ', {})
    def test_main_sets_tmpdir(self, mock_cp, _mock_conf, _mock_cfg,
                              _mock_log, _mock_pc, _mock_api, _mock_auth,
                              _mock_main):
        mock_config = MagicMock()
        mock_cp.ConfigParser.return_value = mock_config
        td = threading.Event()
        td.set()
        env = {}
        with patch('threading.Event', return_value=td), \
                patch('software.software_controller.keep_running', False), \
                patch('software.software_controller.os.environ', env):
            main()
        self.assertEqual(env.get('TMPDIR'), '/scratch')


class TestPatchMessageHelloAgentAckDecode(unittest.TestCase):

    def test_decode_all_fields(self):
        msg = PatchMessageHelloAgentAck()
        msg.decode({
            'msgtype': messages.PATCHMSG_HELLO_AGENT_ACK,
            'msgversion': 1,
            'query_id': 42,
            'out_of_date': True,
            'hostname': 'worker-1',
            'requires_reboot': True,
            'patch_failed': True,
            'sw_version': '25.03',
            'state': 'installing',
        })
        self.assertEqual(msg.query_id, 42)
        self.assertTrue(msg.agent_out_of_date)
        self.assertEqual(msg.agent_hostname, 'worker-1')
        self.assertTrue(msg.agent_requires_reboot)
        self.assertTrue(msg.agent_patch_failed)
        self.assertEqual(msg.agent_sw_version, '25.03')
        self.assertEqual(msg.agent_state, 'installing')

    def test_decode_empty(self):
        msg = PatchMessageHelloAgentAck()
        msg.decode({'msgtype': messages.PATCHMSG_HELLO_AGENT_ACK,
                    'msgversion': 1})
        self.assertEqual(msg.query_id, 0)
        self.assertFalse(msg.agent_out_of_date)
        self.assertEqual(msg.agent_hostname, 'n/a')


class TestPatchMessageQueryDetailedRespDecode(unittest.TestCase):

    def test_decode_all_fields(self):
        msg = PatchMessageQueryDetailedResp()
        msg.decode({
            'msgtype': messages.PATCHMSG_QUERY_DETAILED_RESP,
            'msgversion': 1,
            'latest_sysroot_commit': 'commit123',
            'nodetype': 'controller',
            'sw_version': '24.09',
            'subfunctions': ['controller', 'worker'],
            'state': 'idle',
        })
        self.assertEqual(msg.latest_sysroot_commit, 'commit123')
        self.assertEqual(msg.nodetype, 'controller')
        self.assertEqual(msg.agent_sw_version, '24.09')
        self.assertEqual(msg.subfunctions, ['controller', 'worker'])
        self.assertEqual(msg.agent_state, 'idle')

    def test_decode_defaults(self):
        msg = PatchMessageQueryDetailedResp()
        msg.decode({'msgtype': messages.PATCHMSG_QUERY_DETAILED_RESP,
                    'msgversion': 1})
        self.assertEqual(msg.latest_sysroot_commit, 'unknown')
        self.assertEqual(msg.nodetype, 'unknown')


class TestPatchMessageAgentInstallRespDecode(unittest.TestCase):

    def test_decode_all_fields(self):
        msg = PatchMessageAgentInstallResp()
        msg.decode({
            'msgtype': messages.PATCHMSG_AGENT_INSTALL_RESP,
            'msgversion': 1,
            'status': True,
            'reject_reason': 'none',
            'reboot_required': True,
        })
        self.assertTrue(msg.status)
        self.assertEqual(msg.reject_reason, 'none')
        self.assertTrue(msg.reboot_required)

    def test_decode_defaults(self):
        msg = PatchMessageAgentInstallResp()
        msg.decode({'msgtype': messages.PATCHMSG_AGENT_INSTALL_RESP,
                    'msgversion': 1})
        self.assertFalse(msg.status)
        self.assertIsNone(msg.reject_reason)
        self.assertFalse(msg.reboot_required)


class TestPatchMessageDropHostReqDecode(unittest.TestCase):

    def test_decode_with_ip(self):
        msg = PatchMessageDropHostReq()
        msg.decode({'msgtype': messages.PATCHMSG_DROP_HOST_REQ,
                    'msgversion': 1, 'ip': '10.0.0.5'})
        self.assertEqual(msg.ip, '10.0.0.5')

    def test_decode_without_ip(self):
        msg = PatchMessageDropHostReq()
        msg.decode({'msgtype': messages.PATCHMSG_DROP_HOST_REQ,
                    'msgversion': 1})
        self.assertIsNone(msg.ip)


class TestSoftwareMessageDeployDeleteCleanupRespDecode(unittest.TestCase):

    def test_decode_success(self):
        msg = SoftwareMessageDeployDeleteCleanupResp()
        msg.decode({'msgtype': messages.PATCHMSG_DEPLOY_DELETE_CLEANUP_RESP,
                    'msgversion': 1, 'success': True})
        self.assertTrue(msg.success)

    def test_decode_failure(self):
        msg = SoftwareMessageDeployDeleteCleanupResp()
        msg.decode({'msgtype': messages.PATCHMSG_DEPLOY_DELETE_CLEANUP_RESP,
                    'msgversion': 1, 'success': False})
        self.assertFalse(msg.success)

    def test_decode_no_success_field(self):
        msg = SoftwareMessageDeployDeleteCleanupResp()
        msg.decode({'msgtype': messages.PATCHMSG_DEPLOY_DELETE_CLEANUP_RESP,
                    'msgversion': 1})
        self.assertIsNone(msg.success)


class TestSWMessageDeployStateChangedDecodeEdgeCases(unittest.TestCase):

    def test_decode_admin_agent(self):
        data = {
            'msgtype': messages.PATCHMSG_DEPLOY_STATE_CHANGED,
            'msgversion': 1,
            'agent': 'admin',
            'hostname': 'ctrl-0',
            'host-state': DEPLOY_HOST_STATES.FAILED.value,
        }
        msg = SWMessageDeployStateChanged()
        msg.decode(data)
        self.assertTrue(msg.valid)
        self.assertEqual(msg.hostname, 'ctrl-0')
        self.assertEqual(msg.host_state, DEPLOY_HOST_STATES.FAILED)

    def test_decode_deploy_activate_agent(self):
        data = {
            'msgtype': messages.PATCHMSG_DEPLOY_STATE_CHANGED,
            'msgversion': 1,
            'agent': 'deploy-activate',
            'deploy-state': DEPLOY_STATES.ACTIVATE_DONE.value,
        }
        msg = SWMessageDeployStateChanged()
        msg.decode(data)
        self.assertTrue(msg.valid)

    def test_decode_deploy_activate_rollback_agent(self):
        data = {
            'msgtype': messages.PATCHMSG_DEPLOY_STATE_CHANGED,
            'msgversion': 1,
            'agent': 'deploy-activate-rollback',
            'deploy-state': DEPLOY_STATES.ACTIVATE_ROLLBACK_DONE.value,
        }
        msg = SWMessageDeployStateChanged()
        msg.decode(data)
        self.assertTrue(msg.valid)

    def test_decode_no_state_at_all(self):
        data = {
            'msgtype': messages.PATCHMSG_DEPLOY_STATE_CHANGED,
            'msgversion': 1,
            'agent': 'deploy-start',
        }
        msg = SWMessageDeployStateChanged()
        msg.decode(data)
        self.assertFalse(msg.valid)

    def test_decode_host_state_pending(self):
        data = {
            'msgtype': messages.PATCHMSG_DEPLOY_STATE_CHANGED,
            'msgversion': 1,
            'agent': 'deploy-start',
            'hostname': 'w-0',
            'host-state': DEPLOY_HOST_STATES.PENDING.value,
        }
        msg = SWMessageDeployStateChanged()
        msg.decode(data)
        self.assertTrue(msg.valid)
        self.assertEqual(msg.host_state, DEPLOY_HOST_STATES.PENDING)

    def test_decode_host_state_deploying(self):
        data = {
            'msgtype': messages.PATCHMSG_DEPLOY_STATE_CHANGED,
            'msgversion': 1,
            'agent': 'deploy-start',
            'hostname': 'w-0',
            'host-state': DEPLOY_HOST_STATES.DEPLOYING.value,
        }
        msg = SWMessageDeployStateChanged()
        msg.decode(data)
        self.assertTrue(msg.valid)

    def test_decode_host_state_rollback_pending(self):
        data = {
            'msgtype': messages.PATCHMSG_DEPLOY_STATE_CHANGED,
            'msgversion': 1,
            'agent': 'admin',
            'hostname': 'w-0',
            'host-state': DEPLOY_HOST_STATES.ROLLBACK_PENDING.value,
        }
        msg = SWMessageDeployStateChanged()
        msg.decode(data)
        self.assertTrue(msg.valid)

    def test_decode_host_state_rollback_deploying(self):
        data = {
            'msgtype': messages.PATCHMSG_DEPLOY_STATE_CHANGED,
            'msgversion': 1,
            'agent': 'admin',
            'hostname': 'w-0',
            'host-state': DEPLOY_HOST_STATES.ROLLBACK_DEPLOYING.value,
        }
        msg = SWMessageDeployStateChanged()
        msg.decode(data)
        self.assertTrue(msg.valid)

    def test_decode_host_state_rollback_failed(self):
        data = {
            'msgtype': messages.PATCHMSG_DEPLOY_STATE_CHANGED,
            'msgversion': 1,
            'agent': 'admin',
            'hostname': 'w-0',
            'host-state': DEPLOY_HOST_STATES.ROLLBACK_FAILED.value,
        }
        msg = SWMessageDeployStateChanged()
        msg.decode(data)
        self.assertTrue(msg.valid)

    def test_decode_host_state_rollback_deployed(self):
        data = {
            'msgtype': messages.PATCHMSG_DEPLOY_STATE_CHANGED,
            'msgversion': 1,
            'agent': 'admin',
            'hostname': 'w-0',
            'host-state': DEPLOY_HOST_STATES.ROLLBACK_DEPLOYED.value,
        }
        msg = SWMessageDeployStateChanged()
        msg.decode(data)
        self.assertTrue(msg.valid)


class TestSoftwareMessageDeployStateUpdateDecode(unittest.TestCase):

    def test_decode(self):
        msg = SoftwareMessageDeployStateUpdate()
        data = {
            'msgtype': messages.PATCHMSG_DEPLOY_STATE_UPDATE,
            'msgversion': 1,
            'deploy_state': {
                'deploy': {},
                'deploy_host': {}}}
        msg.decode(data)
        self.assertEqual(msg.data, data)


class TestSoftwareMessageDeployStateUpdateAckDecode(unittest.TestCase):

    def test_decode(self):
        msg = SoftwareMessageDeployStateUpdateAck()
        data = {'msgtype': messages.PATCHMSG_DEPLOY_STATE_UPDATE_ACK,
                'msgversion': 1, 'result': 'success',
                'deploy_state': {'deploy': {}}}
        msg.decode(data)
        self.assertEqual(msg.peer_state_data, data)


class TestPatchMessageHelloDecode(unittest.TestCase):

    def test_decode_with_counter(self):
        msg = PatchMessageHello()
        msg.decode({'msgtype': messages.PATCHMSG_HELLO,
                    'msgversion': 1, 'patch_op_counter': 7})
        self.assertEqual(msg.patch_op_counter, 7)

    def test_decode_without_counter(self):
        msg = PatchMessageHello()
        msg.decode({'msgtype': messages.PATCHMSG_HELLO, 'msgversion': 1})
        self.assertEqual(msg.patch_op_counter, 0)


class TestControllerNeighbourUnit(unittest.TestCase):

    def test_rx_ack_updates_time(self):
        cn = ControllerNeighbour()
        cn.rx_ack()
        self.assertGreater(cn.last_ack, 0)

    def test_get_age(self):
        cn = ControllerNeighbour()
        cn.last_ack = time.time() - 60
        age = cn.get_age()
        self.assertGreaterEqual(age, 59)
        self.assertLessEqual(age, 62)

    def test_synced_lifecycle(self):
        cn = ControllerNeighbour()
        self.assertFalse(cn.get_synced())
        cn.rx_synced()
        self.assertTrue(cn.get_synced())
        cn.clear_synced()
        self.assertFalse(cn.get_synced())


class TestAgentNeighbourUnit(unittest.TestCase):

    def test_init(self):
        an = AgentNeighbour('10.0.0.1')
        self.assertEqual(an.ip, '10.0.0.1')
        self.assertEqual(an.hostname, 'n/a')
        self.assertFalse(an.out_of_date)

    def test_is_alive_property(self):
        an = AgentNeighbour('10.0.0.1')
        self.assertFalse(an.is_alive)
        an.is_alive = True
        self.assertTrue(an.is_alive)

    def test_get_age(self):
        an = AgentNeighbour('10.0.0.1')
        an.last_ack = time.time() - 120
        age = an.get_age()
        self.assertGreaterEqual(age, 119)
        self.assertLessEqual(age, 122)

    def test_get_dict(self):
        an = AgentNeighbour('10.0.0.1')
        an.hostname = 'worker-0'
        an.out_of_date = False
        an.sw_version = '24.09'
        d = an.get_dict()
        self.assertEqual(d['ip'], '10.0.0.1')
        self.assertEqual(d['hostname'], 'worker-0')
        self.assertTrue(d['deployed'])
        self.assertEqual(d['sw_version'], '24.09')

    @patch('software.software_controller.stale_hosts', [])
    @patch('software.software_controller.pending_queries', [])
    def test_rx_ack_marks_stale(self):
        an = AgentNeighbour('10.0.0.1')
        an.last_query_id = 0
        an.rx_ack('worker-0', False, False, 1, False, '24.09', 'idle')
        self.assertTrue(an.stale)

    @patch('software.software_controller.pending_queries', [])
    @patch('software.software_controller.stale_hosts', [])
    def test_handle_query_detailed_resp(self):
        an = AgentNeighbour('10.0.0.1')
        an.stale = True
        an.pending_query = True
        an.handle_query_detailed_resp('commit1', 'worker', '24.09',
                                      ['worker'], 'idle')
        self.assertFalse(an.stale)
        self.assertFalse(an.pending_query)
        self.assertEqual(an.latest_sysroot_commit, 'commit1')
        self.assertEqual(an.nodetype, 'worker')
