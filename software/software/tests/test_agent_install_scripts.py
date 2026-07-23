#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Extended tests for software.software_agent module."""

import subprocess
import unittest
from unittest import mock

from software.tests import base as test_base  # noqa: F401
from software.software_agent import check_install_uuid
from software.software_agent import pull_install_scripts_from_controller
from software.software_agent import run_post_install_script
import software.software_agent as software_agent
import software.constants as constants
import requests as req


class TestPullInstallScripts(unittest.TestCase):
    """Tests for pull_install_scripts_from_controller."""

    @mock.patch('subprocess.check_output', return_value=b"synced")
    @mock.patch('os.makedirs')
    @mock.patch('shutil.rmtree')
    @mock.patch('os.path.exists', return_value=True)
    def test_pull_scripts_success(self, _exists, _rmtree, _makedirs, mock_sub):
        pull_install_scripts_from_controller()
        mock_sub.assert_called_once()
        args = mock_sub.call_args[0][0]
        self.assertEqual(args[0], "rsync")
        self.assertIn("controller", args[-2])

    @mock.patch('subprocess.check_output', return_value=b"synced")
    @mock.patch('os.makedirs')
    @mock.patch('shutil.rmtree')
    @mock.patch('os.path.exists', return_value=True)
    def test_pull_scripts_install_local(
            self, _exists, _rmtree, _makedirs, mock_sub):
        pull_install_scripts_from_controller(install_local=True)
        args = mock_sub.call_args[0][0]
        self.assertIn("127.0.0.1", args[-2])

    @mock.patch('subprocess.check_output',
                side_effect=subprocess.CalledProcessError(
                    1, 'rsync', output=b'connection refused'))
    @mock.patch('os.makedirs')
    @mock.patch('shutil.rmtree')
    @mock.patch('os.path.exists', return_value=False)
    def test_pull_scripts_rsync_failure(
            self, _exists, _rmtree, _makedirs, _sub):
        self.assertRaises(subprocess.CalledProcessError,
                          pull_install_scripts_from_controller)


class TestRunPostInstallScript(unittest.TestCase):
    """Tests for run_post_install_script."""

    @mock.patch('subprocess.check_output', return_value=b"ok")
    def test_before_reboot(self, mock_sub):
        result = run_post_install_script(running_after_reboot=False)
        self.assertTrue(result)
        args = mock_sub.call_args[0][0]
        self.assertIn(constants.BEFORE_REBOOT, args)

    @mock.patch('subprocess.check_output', return_value=b"ok")
    def test_after_reboot(self, mock_sub):
        result = run_post_install_script(running_after_reboot=True)
        self.assertTrue(result)
        args = mock_sub.call_args[0][0]
        self.assertIn(constants.AFTER_REBOOT, args)

    @mock.patch('subprocess.check_output',
                side_effect=subprocess.CalledProcessError(
                    1, 'cmd', output=b'err'))
    def test_script_failure(self, _sub):
        result = run_post_install_script()
        self.assertFalse(result)

    @mock.patch('subprocess.check_output', return_value=b"done")
    def test_default_is_before_reboot(self, mock_sub):
        run_post_install_script()
        args = mock_sub.call_args[0][0]
        self.assertIn(constants.BEFORE_REBOOT, args)


class TestCheckInstallUuid(unittest.TestCase):
    """Tests for check_install_uuid."""

    @mock.patch('software.software_agent.install_uuid', 'test-uuid-123')
    @mock.patch('requests.get')
    def test_matching_uuid(self, mock_get):
        mock_get.return_value = mock.Mock(
            status_code=200, text='test-uuid-123\n')
        self.assertTrue(check_install_uuid())

    @mock.patch('software.software_agent.install_uuid', 'local-uuid')
    @mock.patch('requests.get')
    def test_mismatched_uuid(self, mock_get):
        mock_get.return_value = mock.Mock(status_code=200, text='remote-uuid')
        self.assertFalse(check_install_uuid())

    @mock.patch('socket.gethostname', return_value='controller-1')
    @mock.patch('requests.get')
    def test_404_on_controller1(self, mock_get, _hostname):
        mock_get.return_value = mock.Mock(status_code=404)
        self.assertTrue(check_install_uuid())

    @mock.patch('socket.gethostname', return_value='controller-0')
    @mock.patch('requests.get')
    def test_404_on_controller0(self, mock_get, _hostname):
        mock_get.return_value = mock.Mock(status_code=404)
        self.assertFalse(check_install_uuid())

    @mock.patch('requests.get', side_effect=Exception("connection refused"))
    def test_connection_error(self, _get):
        with mock.patch('requests.get', side_effect=req.ConnectionError):
            self.assertFalse(check_install_uuid())


def _create_patch_agent():
    """Helper to create a PatchAgent with
    mocked PatchService.__init__.
    """
    with mock.patch.object(software_agent.PatchService, '__init__',
                           return_value=None):
        with mock.patch('os.path.exists', return_value=False):
            with mock.patch('os.makedirs'):
                agent = software_agent.PatchAgent()
    return agent


class TestPatchAgentInit(unittest.TestCase):
    """Tests for PatchAgent.__init__."""

    def test_init_defaults(self):
        agent = _create_patch_agent()
        self.assertIsNone(agent.sock_out)
        self.assertIsNone(agent.sock_in)
        self.assertIsNone(agent.controller_address)
        self.assertIsNone(agent.listener)
        self.assertFalse(agent.changes)
        self.assertIsNone(agent.latest_feed_commit)
        self.assertIsNone(agent.latest_sysroot_commit)
        self.assertEqual(agent.patch_op_counter, 0)
        self.assertEqual(agent.query_id, 0)
        self.assertEqual(agent.state, constants.PATCH_AGENT_STATE_IDLE)
        self.assertEqual(agent.rejection_timestamp, 0)
        self.assertIsNone(agent.last_repo_revision)

    @mock.patch('os.makedirs')
    @mock.patch('os.path.exists', side_effect=lambda filepath: filepath ==
                software_agent.patch_failed_file)
    @mock.patch.object(software_agent.PatchService,
                       '__init__', return_value=None)
    def test_init_patch_failed_state(self, _ps, _exists, _makedirs):
        agent = software_agent.PatchAgent()
        self.assertEqual(
            agent.state,
            constants.PATCH_AGENT_STATE_INSTALL_FAILED)
        self.assertTrue(agent.patch_failed)


class TestPatchAgentUpdateConfig(unittest.TestCase):
    """Tests for PatchAgent.update_config."""

    def setUp(self):
        self.agent = _create_patch_agent()
        self.agent.pre_bootstrap = False
        self.agent.port = 0

    @mock.patch('software.config.get_mgmt_iface',
                return_value=constants.LOOPBACK_INTERFACE_NAME)
    @mock.patch('software.config.get_mgmt_ip', return_value='127.0.0.1')
    @mock.patch('software.config.read_config')
    @mock.patch('software.config.agent_port', 5495)
    def test_loopback_no_mcast(self, _read, _ip, _iface):
        self.agent.update_config()
        self.assertIsNone(self.agent.mcast_addr)
        self.assertEqual(self.agent.controller_address, '127.0.0.1')
        self.assertEqual(self.agent.port, 5495)

    @mock.patch('software.config.get_mgmt_iface', return_value='eth0')
    @mock.patch('software.config.agent_mcast_group', '239.1.1.4')
    @mock.patch('software.config.controller_mcast_group', '239.1.1.3')
    @mock.patch('software.config.read_config')
    @mock.patch('software.config.agent_port', 5495)
    def test_normal_interface_mcast(self, _read, _iface):
        self.agent.update_config()
        self.assertEqual(self.agent.mcast_addr, '239.1.1.4')
        self.assertEqual(self.agent.controller_address, '239.1.1.3')

    @mock.patch('software.utils.gethostbyname', return_value='127.0.0.1')
    @mock.patch('software.config.read_config')
    @mock.patch('software.config.agent_port', 5495)
    def test_pre_bootstrap(self, _read, _resolve):
        self.agent.pre_bootstrap = True
        self.agent.update_config()
        self.assertIsNone(self.agent.mcast_addr)
        self.assertEqual(self.agent.controller_address, '127.0.0.1')


def _patch_ostree_lock():
    """Return stacked context managers to bypass ostree_lock."""
    return [
        mock.patch('builtins.open', mock.mock_open()),
        mock.patch('fcntl.flock'),
    ]


class TestPatchAgentQuery(unittest.TestCase):
    """Tests for PatchAgent.query."""

    def setUp(self):
        self.agent = _create_patch_agent()
        self.agent.install_local = True
        self.agent.sock_out = None
        self._patches = _patch_ostree_lock()
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in reversed(self._patches):
            p.stop()

    @mock.patch('software.ostree_utils.get_latest_deployment_commit',
                return_value='commit_abc')
    @mock.patch('software.ostree_utils.get_sysroot_latest_commit',
                return_value='commit_abc')
    def test_query_no_changes(self, _sysroot, _deploy):
        self.agent.latest_feed_commit = 'commit_abc'
        result = self.agent.query()
        self.assertTrue(result)
        self.assertFalse(self.agent.changes)
        self.assertEqual(self.agent.latest_sysroot_commit, 'commit_abc')

    @mock.patch('software.ostree_utils.get_latest_deployment_commit',
                return_value='commit_old')
    @mock.patch('software.ostree_utils.get_sysroot_latest_commit',
                return_value='commit_old')
    def test_query_with_changes(self, _sysroot, _deploy):
        self.agent.latest_feed_commit = 'commit_new'
        result = self.agent.query()
        self.assertTrue(result)
        self.assertTrue(self.agent.changes)

    @mock.patch('software.ostree_utils.get_sysroot_latest_commit',
                return_value='commit_abc')
    def test_query_major_release(self, _sysroot):
        result = self.agent.query(major_release='25.03')
        self.assertTrue(result)
        self.assertTrue(self.agent.changes)
        self.assertIsNone(self.agent.latest_feed_commit)

    @mock.patch('software.software_agent.check_install_uuid',
                return_value=False)
    def test_query_uuid_fail_not_local(self, _uuid):
        self.agent.install_local = False
        result = self.agent.query()
        self.assertFalse(result)

    @mock.patch('software.ostree_utils.get_sysroot_latest_commit',
                return_value='commit_abc')
    def test_query_sets_query_id(self, _sysroot):
        self.agent.latest_feed_commit = None
        self.agent.query()
        self.assertNotEqual(self.agent.query_id, 0)


class TestPatchAgentSetInstallFailedFlags(unittest.TestCase):
    """Tests for PatchAgent.set_install_failed_flags."""

    @mock.patch('software.software_agent.setflag')
    def test_sets_flags(self, mock_setflag):
        agent = _create_patch_agent()
        agent.set_install_failed_flags()
        self.assertTrue(agent.patch_failed)
        self.assertEqual(
            agent.state,
            constants.PATCH_AGENT_STATE_INSTALL_FAILED)
        mock_setflag.assert_called_once_with(software_agent.patch_failed_file)


class TestPatchAgentHandleInstall(unittest.TestCase):
    """Tests for PatchAgent.handle_install."""

    def setUp(self):
        self.agent = _create_patch_agent()
        self.agent.install_local = True
        self.agent.sock_out = None
        self.agent.changes = False

    @mock.patch('software.software_agent.clearflag')
    @mock.patch('software.software_agent.setflag')
    @mock.patch.object(software_agent.PatchAgent, 'query', return_value=True)
    @mock.patch('software.ostree_utils.copy_updated_efi_files')
    @mock.patch('shutil.rmtree')
    @mock.patch('software.software_agent.utils.get_platform_conf',
                return_value='controller')
    @mock.patch('os.path.exists', return_value=False)
    def test_handle_install_no_changes(self, _exists, _platform_conf,
                                       _rmtree, _efi, _query, _setflag,
                                       _clearflag):
        result = self.agent.handle_install()
        self.assertTrue(result)

    @mock.patch('software.software_agent.check_install_uuid',
                return_value=False)
    @mock.patch('software.software_agent.setflag')
    def test_handle_install_uuid_fail(self, _setflag, _uuid):
        self.agent.install_local = False
        result = self.agent.handle_install()
        self.assertFalse(result)
        self.assertEqual(self.agent.state,
                         constants.PATCH_AGENT_STATE_INSTALL_FAILED)

    @mock.patch('software.software_agent.clearflag')
    @mock.patch('software.software_agent.setflag')
    @mock.patch.object(software_agent.PatchAgent, 'query', return_value=True)
    @mock.patch('software.ostree_utils.copy_updated_efi_files')
    @mock.patch('software.ostree_utils.get_latest_deployment_commit',
                return_value='commit_match')
    @mock.patch('shutil.rmtree')
    @mock.patch('os.path.exists', return_value=False)
    def test_handle_install_commit_already_deployed(self, _exists, _rmtree,
                                                    _deploy, _efi, _query,
                                                    _setflag, _clearflag):
        result = self.agent.handle_install(commit_id='commit_match')
        self.assertTrue(result)
        self.assertEqual(self.agent.state, constants.PATCH_AGENT_STATE_IDLE)


class TestPatchAgentHandlePatchOpCounter(unittest.TestCase):
    """Tests for PatchAgent.handle_patch_op_counter."""

    def setUp(self):
        self.agent = _create_patch_agent()
        self.agent.node_is_patched = False
        self.agent.node_is_patched_timestamp = 0
        self.agent.patch_op_counter = 0

    @mock.patch.object(software_agent.PatchAgent, 'query', return_value=True)
    @mock.patch('os.path.exists', return_value=False)
    def test_counter_increase_triggers_query(self, _exists, mock_query):
        self.agent.handle_patch_op_counter(5)
        mock_query.assert_called_once()
        self.assertEqual(self.agent.patch_op_counter, 5)

    @mock.patch.object(software_agent.PatchAgent, 'query', return_value=True)
    @mock.patch('os.path.getmtime', return_value=1000.0)
    @mock.patch('os.path.exists', return_value=True)
    def test_node_patched_file_appears(self, _exists, _mtime, mock_query):
        self.agent.handle_patch_op_counter(1)
        self.assertTrue(self.agent.node_is_patched)
        mock_query.assert_called_once()

    @mock.patch.object(software_agent.PatchAgent, 'query', return_value=False)
    @mock.patch('os.path.exists', return_value=False)
    def test_query_fail_resets_counter(self, _exists, _query):
        self.agent.handle_patch_op_counter(10)
        self.assertEqual(self.agent.patch_op_counter, 0)

    @mock.patch.object(software_agent.PatchAgent, 'query', return_value=True)
    @mock.patch('os.path.exists', return_value=False)
    def test_node_patched_cleared(self, _exists, _mock_query):
        self.agent.node_is_patched = True
        self.agent.handle_patch_op_counter(1)
        self.assertFalse(self.agent.node_is_patched)
        self.assertEqual(self.agent.node_is_patched_timestamp, 0)


class TestPatchAgentSetupTcpSocket(unittest.TestCase):
    """Tests for PatchAgent.setup_tcp_socket."""

    def setUp(self):
        self.agent = _create_patch_agent()
        self.agent.port = 5495
        self.agent.pre_bootstrap = False
        self.agent.listener = None

    @mock.patch('software.utils.get_management_family',
                return_value=2)  # AF_INET
    @mock.patch('socket.socket')
    def test_setup_tcp_socket(self, mock_sock_cls, _family):
        mock_sock = mock.MagicMock()
        mock_sock_cls.return_value = mock_sock
        self.agent.setup_tcp_socket()
        mock_sock.bind.assert_called_once_with(('', 5495))
        mock_sock.listen.assert_called_once_with(2)
        self.assertEqual(self.agent.listener, mock_sock)


class TestPatchMessageHelloAgentAck(unittest.TestCase):
    """Tests for PatchMessageHelloAgentAck.encode."""

    @mock.patch('software.software_agent.SW_VERSION', '24.09')
    @mock.patch('socket.gethostname', return_value='worker-0')
    def test_encode_normal(self, _hostname):
        old_pa = software_agent.pa
        try:
            agent = _create_patch_agent()
            agent.query_id = 42
            agent.changes = True
            agent.node_is_patched = False
            agent.patch_failed = False
            agent.state = constants.PATCH_AGENT_STATE_IDLE
            agent.pre_bootstrap = False
            agent.controller_address = '127.0.0.1'
            software_agent.pa = agent

            msg = software_agent.PatchMessageHelloAgentAck()
            msg.encode()
            self.assertEqual(msg.message['query_id'], 42)
            self.assertTrue(msg.message['out_of_date'])
            self.assertEqual(msg.message['hostname'], 'worker-0')
            self.assertEqual(msg.message['state'],
                             constants.PATCH_AGENT_STATE_IDLE)
        finally:
            software_agent.pa = old_pa

    @mock.patch('software.software_agent.SW_VERSION', '24.09')
    def test_encode_pre_bootstrap(self):
        old_pa = software_agent.pa
        try:
            agent = _create_patch_agent()
            agent.pre_bootstrap = True
            agent.query_id = 1
            agent.changes = False
            agent.node_is_patched = False
            agent.patch_failed = False
            agent.state = constants.PATCH_AGENT_STATE_IDLE
            agent.controller_address = '127.0.0.1'
            software_agent.pa = agent

            msg = software_agent.PatchMessageHelloAgentAck()
            msg.encode()
            self.assertEqual(msg.message['hostname'],
                             constants.PREBOOTSTRAP_HOSTNAME)
        finally:
            software_agent.pa = old_pa


class TestPatchMessageAgentInstallReq(unittest.TestCase):
    """Tests for PatchMessageAgentInstallReq.decode."""

    def test_decode_all_fields(self):
        msg = software_agent.PatchMessageAgentInstallReq()
        data = {
            'msgtype': 9,
            'msgversion': 1,
            'force': True,
            'major_release': '25.03',
            'commit_id': 'abc123',
            'additional_data': {'key': 'val'},
        }
        msg.decode(data)
        self.assertTrue(msg.force)
        self.assertEqual(msg.major_release, '25.03')
        self.assertEqual(msg.commit_id, 'abc123')
        self.assertEqual(msg.additional_data, {'key': 'val'})

    def test_decode_defaults(self):
        msg = software_agent.PatchMessageAgentInstallReq()
        msg.decode({'msgtype': 9, 'msgversion': 1})
        self.assertFalse(msg.force)
        self.assertIsNone(msg.major_release)
        self.assertIsNone(msg.commit_id)
        self.assertEqual(msg.additional_data, {})


class TestPatchMessageAgentInstallResp(unittest.TestCase):
    """Tests for PatchMessageAgentInstallResp.encode."""

    def test_encode_with_reject(self):
        old_pa = software_agent.pa
        try:
            agent = _create_patch_agent()
            software_agent.pa = agent

            msg = software_agent.PatchMessageAgentInstallResp()
            msg.status = False
            msg.reject_reason = 'Node must be locked.'
            msg.encode()
            self.assertFalse(msg.message['status'])
            self.assertEqual(msg.message['reject_reason'],
                             'Node must be locked.')
        finally:
            software_agent.pa = old_pa

    def test_encode_success_no_reject(self):
        old_pa = software_agent.pa
        try:
            agent = _create_patch_agent()
            software_agent.pa = agent

            msg = software_agent.PatchMessageAgentInstallResp()
            msg.status = True
            msg.encode()
            self.assertTrue(msg.message['status'])
            self.assertNotIn('reject_reason', msg.message)
        finally:
            software_agent.pa = old_pa


class TestPatchMessageSendLatestFeedCommit(unittest.TestCase):
    """Tests for PatchMessageSendLatestFeedCommit.decode."""

    @mock.patch.object(software_agent.PatchAgent, 'query')
    def test_decode_sets_commit(self, _query):
        old_pa = software_agent.pa
        try:
            agent = _create_patch_agent()
            software_agent.pa = agent

            msg = software_agent.PatchMessageSendLatestFeedCommit()
            msg.decode({'msgtype': 12, 'msgversion': 1,
                        'latest_feed_commit': 'feed_abc'})
            self.assertEqual(agent.latest_feed_commit, 'feed_abc')
        finally:
            software_agent.pa = old_pa
