#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for software.config, release_state,
release_verify, sysinv_utils, and plugin modules.
"""

import configparser
import unittest
from unittest import mock

from software.tests import base as test_base  # noqa: F401
import software.config as cfg
from software.release_state import ReleaseState
from software.exceptions import ReleaseNotFound
from software import states
from software.release_verify import read_RSA_key
from software.release_verify import verify_files
from software.sysinv_utils import get_sysinv_client
from software import sysinv_utils
from software.exceptions import SysinvClientNotInitialized
from software.sysinv_utils import get_ihost_list
from software.sysinv_utils import get_system_info
from software.sysinv_utils import is_host_locked_and_online
from software.sysinv_utils import trigger_vim_host_audit
from software.plugin import DeployPluginRunner
from software.plugin import USM_PLUGIN_PATH


class TestReadConfig(unittest.TestCase):
    """Tests for software.config.read_config."""

    @mock.patch('builtins.open', mock.mock_open(
        read_data='management_interface=eth0\nnodetype=controller\n'))
    @mock.patch('os.stat')
    def test_read_config_parses_values(self, mock_stat):
        mock_stat.return_value = mock.MagicMock(st_mtime=999)
        cfg.software_conf_mtime = 0
        cfg.software_conf = '/etc/software/software.conf'

        ini_content = (
            "[runtime]\n"
            "controller_multicast=239.1.1.3\n"
            "agent_multicast=239.1.1.4\n"
            "api_port=5493\n"
            "controller_port=5494\n"
            "agent_port=5495\n"
            "alt_postgresql_port=6666\n"
            "package_feed=http://controller:8080/feed\n"
        )
        mock_config = configparser.ConfigParser(interpolation=None)
        mock_config.read_string(ini_content)

        with mock.patch.object(configparser.ConfigParser, 'read'), \
                mock.patch.object(configparser.ConfigParser, 'get',
                                  side_effect=mock_config.get), \
                mock.patch.object(configparser.ConfigParser, 'getint',
                                  side_effect=mock_config.getint), \
                mock.patch.object(configparser.ConfigParser, 'read_file'):
            cfg.read_config()

        self.assertEqual(cfg.controller_mcast_group, '239.1.1.3')
        self.assertEqual(cfg.agent_mcast_group, '239.1.1.4')
        self.assertEqual(cfg.api_port, 5493)
        self.assertEqual(cfg.controller_port, 5494)
        self.assertEqual(cfg.agent_port, 5495)


class TestGetMgmtIp(unittest.TestCase):
    """Tests for software.config.get_mgmt_ip."""

    @mock.patch('os.path.exists', return_value=False)
    def test_no_initial_config(self, _):
        self.assertIsNone(cfg.get_mgmt_ip())

    @mock.patch('software.config.utils.gethostbyname',
                return_value='10.0.0.1')
    @mock.patch('socket.gethostname', return_value='controller-0')
    @mock.patch('os.path.exists', return_value=True)
    @mock.patch('software.config.tsc')
    def test_returns_ip(self, mock_tsc, _exists, _host, _resolve):
        mock_tsc.INITIAL_CONFIG_COMPLETE_FLAG = '/tmp/.init'
        mock_tsc.system_mode = 'duplex'
        result = cfg.get_mgmt_ip()
        self.assertEqual(result, '10.0.0.1')


class TestGetMgmtIface(unittest.TestCase):
    """Tests for software.config.get_mgmt_iface."""

    @mock.patch('os.path.exists', return_value=False)
    def test_no_initial_config(self, _):
        self.assertIsNone(cfg.get_mgmt_iface())

    @mock.patch('os.stat')
    @mock.patch('builtins.open', mock.mock_open(
        read_data='management_interface=eth0\n'))
    @mock.patch('os.path.exists', return_value=True)
    def test_reads_iface(self, _exists, mock_stat):
        mock_stat.return_value = mock.MagicMock(st_mtime=999)
        cfg.mgmt_if = None
        cfg.platform_conf_mtime = 0
        result = cfg.get_mgmt_iface()
        self.assertEqual(result, 'eth0')

    @mock.patch('os.stat')
    @mock.patch('os.path.exists', return_value=True)
    def test_returns_cached(self, _exists, mock_stat):
        mock_stat.return_value = mock.MagicMock(st_mtime=100)
        cfg.mgmt_if = 'eth1'
        cfg.platform_conf_mtime = 100
        result = cfg.get_mgmt_iface()
        self.assertEqual(result, 'eth1')


class TestReleaseState(unittest.TestCase):
    """Tests for software.release_state.ReleaseState."""

    def _mock_collection(self, _release_ids=None, states_map=None):
        """Build a mock SWReleaseCollection."""
        mock_coll = mock.MagicMock()
        if states_map:
            def getitem(rel_id):
                r = mock.MagicMock()
                r.id = rel_id
                r.state = states_map.get(rel_id, 'available')
                r.is_ga_release = False
                r.prepatched_iso = False
                r.is_product_release = False
                return r
            mock_coll.__getitem__ = mock.MagicMock(side_effect=getitem)
            mock_coll.get_release_by_id = mock.MagicMock(
                side_effect=getitem)
        else:
            mock_coll.__getitem__ = mock.MagicMock(
                return_value=mock.MagicMock(is_product_release=False))
        return mock_coll

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_init_with_release_ids(self, mock_get_coll):
        mock_coll = self._mock_collection()
        mock_get_coll.return_value = mock_coll
        rs = ReleaseState(release_ids=['rel-1', 'rel-2'])
        self.assertEqual(rs._release_ids, ['rel-1', 'rel-2'])

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_init_with_release_state(self, mock_get_coll):
        mock_rel = mock.MagicMock()
        mock_rel.is_product_release = False
        mock_rel.id = 'rel-1'
        mock_rel.is_product_release = False
        mock_coll = mock.MagicMock()
        mock_coll.iterate_releases_by_state.return_value = [mock_rel]
        mock_coll.__getitem__ = mock.MagicMock(
            return_value=mock.MagicMock(is_product_release=False))
        mock_get_coll.return_value = mock_coll
        rs = ReleaseState(release_state='available')
        self.assertEqual(rs._release_ids, ['rel-1'])

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_init_not_found_raises(self, mock_get_coll):
        mock_coll = mock.MagicMock()
        mock_coll.__getitem__ = mock.MagicMock(return_value=None)
        mock_get_coll.return_value = mock_coll
        with self.assertRaises(ReleaseNotFound):
            ReleaseState(release_ids=['bad-id'])

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_check_transition_valid(self, mock_get_coll):
        mock_coll = self._mock_collection(
            states_map={'rel-1': states.AVAILABLE})
        mock_get_coll.return_value = mock_coll
        rs = ReleaseState.__new__(ReleaseState)
        rs._release_ids = ['rel-1']
        rs._pre_upgrade_deploy = False
        self.assertTrue(rs.check_transition(states.DEPLOYING))

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_check_transition_invalid(self, mock_get_coll):
        mock_coll = self._mock_collection(
            states_map={'rel-1': states.AVAILABLE})
        mock_get_coll.return_value = mock_coll
        rs = ReleaseState.__new__(ReleaseState)
        rs._release_ids = ['rel-1']
        rs._pre_upgrade_deploy = False
        self.assertFalse(rs.check_transition(states.DEPLOYED))

    def test_register_event_listener(self):
        ReleaseState._callbacks = []
        cb = mock.MagicMock()
        cb.__qualname__ = 'test_cb'
        ReleaseState.register_event_listener(cb)
        self.assertIn(cb, ReleaseState._callbacks)
        # Duplicate registration ignored
        ReleaseState.register_event_listener(cb)
        self.assertEqual(len(ReleaseState._callbacks), 1)
        ReleaseState._callbacks = []

    def test_register_event_listener_none(self):
        ReleaseState._callbacks = []
        ReleaseState.register_event_listener(None)
        self.assertEqual(len(ReleaseState._callbacks), 0)

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_is_major_release_deployment_ga(self, mock_get_coll):
        mock_coll = mock.MagicMock()
        mock_rel = mock.MagicMock()
        mock_rel.is_product_release = False
        mock_rel.is_ga_release = True
        mock_rel.prepatched_iso = False
        mock_coll.get_release_by_id.return_value = mock_rel
        mock_get_coll.return_value = mock_coll
        rs = ReleaseState.__new__(ReleaseState)
        rs._release_ids = ['rel-1']
        rs._pre_upgrade_deploy = False
        self.assertTrue(rs.is_major_release_deployment())

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_is_major_release_deployment_prepatched(self, mock_get_coll):
        mock_coll = mock.MagicMock()
        mock_rel = mock.MagicMock()
        mock_rel.is_product_release = False
        mock_rel.is_ga_release = False
        mock_rel.prepatched_iso = True
        mock_coll.get_release_by_id.return_value = mock_rel
        mock_get_coll.return_value = mock_coll
        rs = ReleaseState.__new__(ReleaseState)
        rs._release_ids = ['rel-1']
        rs._pre_upgrade_deploy = False
        self.assertTrue(rs.is_major_release_deployment())

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_is_major_release_deployment_false(self, mock_get_coll):
        mock_coll = mock.MagicMock()
        mock_rel = mock.MagicMock()
        mock_rel.is_product_release = False
        mock_rel.is_ga_release = False
        mock_rel.prepatched_iso = False
        mock_coll.get_release_by_id.return_value = mock_rel
        mock_get_coll.return_value = mock_coll
        rs = ReleaseState.__new__(ReleaseState)
        rs._release_ids = ['rel-1']
        rs._pre_upgrade_deploy = False
        self.assertFalse(rs.is_major_release_deployment())


class TestReadRSAKey(unittest.TestCase):
    """Tests for software.release_verify.read_RSA_key."""

    @mock.patch('software.release_verify.RSA.importKey')
    def test_read_raw_key(self, mock_import):
        mock_key = mock.MagicMock()
        mock_import.return_value = mock_key
        result = read_RSA_key(b'raw-key-data')
        self.assertEqual(result, mock_key)

    @mock.patch('software.release_verify.DerSequence')
    @mock.patch('software.release_verify.binascii.a2b_base64',
                return_value=b'\x00' * 16)
    @mock.patch('software.release_verify.RSA.importKey')
    def test_read_x509_cert(self, mock_import, _a2b, mock_der):
        mock_import.side_effect = [ValueError("not raw"), mock.MagicMock()]
        mock_seq = mock.MagicMock()
        mock_seq.__getitem__ = mock.MagicMock(return_value=b'pubkey')
        mock_der.return_value = mock_seq
        cert_data = (
            '-----BEGIN CERTIFICATE-----\n'
            'dGVzdGRhdGE=\n'
            '-----END CERTIFICATE-----'
        )
        result = read_RSA_key(cert_data)
        self.assertIsNotNone(result)


class TestVerifyFiles(unittest.TestCase):
    """Tests for software.release_verify.verify_files."""

    @mock.patch('software.release_verify.verify_hash', return_value=True)
    @mock.patch('software.release_verify.get_public_certificates',
                return_value=['cert1'])
    @mock.patch('builtins.open', mock.mock_open(read_data=b''))
    def test_verify_files_success(self, _certs, _verify):
        result = verify_files(['/tmp/f1'], '/tmp/sig')
        self.assertTrue(result)

    @mock.patch('software.release_verify.verify_hash', return_value=False)
    @mock.patch('software.release_verify.get_public_certificates',
                return_value=['cert1'])
    @mock.patch('builtins.open', mock.mock_open(read_data=b''))
    def test_verify_files_failure(self, _certs, _verify):
        result = verify_files(['/tmp/f1'], '/tmp/sig')
        self.assertFalse(result)

    @mock.patch('software.release_verify.verify_hash', return_value=True)
    @mock.patch('software.release_verify.get_public_certificates_by_type',
                return_value=['cert1'])
    @mock.patch('builtins.open', mock.mock_open(read_data=b''))
    def test_verify_files_with_cert_type(self, _certs, _verify):
        result = verify_files(['/tmp/f1'], '/tmp/sig', cert_type=['dev'])
        self.assertTrue(result)


class TestGetSysinvClient(unittest.TestCase):
    """Tests for software.sysinv_utils.get_sysinv_client."""

    @mock.patch.dict('sys.modules', {'cgtsclient': mock.MagicMock(),
                                     'cgtsclient.client': mock.MagicMock()})
    def test_success(self):
        client = get_sysinv_client('token', 'http://endpoint')
        self.assertIsNotNone(client)

    @mock.patch.dict('sys.modules', {'cgtsclient': None})
    def test_import_error(self):
        # Force reimport to trigger ImportError
        with mock.patch.dict('sys.modules',
                             {'cgtsclient': None,
                              'cgtsclient.client': None}):
            with self.assertRaises(ImportError):
                sysinv_utils.get_sysinv_client('token', 'http://ep')

    def test_client_exception(self):
        mock_client_mod = mock.MagicMock()
        mock_client_mod.Client.side_effect = Exception("conn fail")
        mock_cgtsclient = mock.MagicMock()
        mock_cgtsclient.client = mock_client_mod
        with mock.patch.dict('sys.modules',
                             {'cgtsclient': mock_cgtsclient,
                              'cgtsclient.client': mock_client_mod}):
            with self.assertRaises(SysinvClientNotInitialized):
                get_sysinv_client('token', 'http://ep')


class TestGetIhostList(unittest.TestCase):
    """Tests for software.sysinv_utils.get_ihost_list."""

    @mock.patch('software.sysinv_utils.get_sysinv_client')
    @mock.patch('software.sysinv_utils.utils.get_endpoints_token',
                return_value=('token', 'http://ep'))
    def test_success(self, _tok, mock_client):
        mock_sc = mock.MagicMock()
        mock_sc.ihost.list.return_value = ['host1']
        mock_client.return_value = mock_sc
        result = get_ihost_list()
        self.assertEqual(result, ['host1'])

    @mock.patch('software.sysinv_utils.get_sysinv_client',
                side_effect=Exception("fail"))
    @mock.patch('software.sysinv_utils.utils.get_endpoints_token',
                return_value=('token', 'http://ep'))
    def test_failure_raises(self, _tok, _client):
        with self.assertRaises(Exception):  # noqa: H202
            get_ihost_list()


class TestGetSystemInfo(unittest.TestCase):
    """Tests for software.sysinv_utils.get_system_info."""

    @mock.patch('software.sysinv_utils.utils.get_platform_conf',
                side_effect=['All-in-one', 'simplex'])
    def test_returns_type_and_mode(self, _conf):
        sys_type, sys_mode = get_system_info()
        self.assertEqual(sys_type, 'All-in-one')
        self.assertEqual(sys_mode, 'simplex')


class TestIsHostLockedAndOnline(unittest.TestCase):
    """Tests for software.sysinv_utils.is_host_locked_and_online."""

    @mock.patch('software.sysinv_utils.get_ihost_list')
    def test_true(self, mock_list):
        host = mock.MagicMock()
        host.hostname = 'worker-0'
        host.availability = 'online'
        host.administrative = 'locked'
        mock_list.return_value = [host]
        self.assertTrue(is_host_locked_and_online('worker-0'))

    @mock.patch('software.sysinv_utils.get_ihost_list')
    def test_false_unlocked(self, mock_list):
        host = mock.MagicMock()
        host.hostname = 'worker-0'
        host.availability = 'online'
        host.administrative = 'unlocked'
        mock_list.return_value = [host]
        self.assertFalse(is_host_locked_and_online('worker-0'))

    @mock.patch('software.sysinv_utils.get_ihost_list')
    def test_false_no_match(self, mock_list):
        mock_list.return_value = []
        self.assertFalse(is_host_locked_and_online('worker-0'))


class TestTriggerVimHostAudit(unittest.TestCase):
    """Tests for software.sysinv_utils.trigger_vim_host_audit."""

    @mock.patch('software.sysinv_utils.get_sysinv_client')
    @mock.patch('software.sysinv_utils.utils.get_endpoints_token',
                return_value=('token', 'http://ep'))
    def test_failure_raises(self, _tok, mock_client):
        mock_sc = mock.MagicMock()
        mock_sc.ihost.get.side_effect = Exception("not found")
        mock_client.return_value = mock_sc
        with self.assertRaises(Exception):  # noqa: H202
            trigger_vim_host_audit('bad-host')


class TestDeployPluginRunnerInit(unittest.TestCase):
    """Tests for software.plugin.DeployPluginRunner.__init__."""

    @mock.patch('software.plugin.constants.SW_VERSION', '24.09')
    @mock.patch('software.plugin.utils.get_major_release_version',
                return_value='24.09')
    def test_init_same_version(self, _ver):
        deploy = {'from_release': '24.09.0', 'to_release': '24.09.1'}
        runner = DeployPluginRunner(deploy)
        self.assertEqual(runner.plugin_path, USM_PLUGIN_PATH)
        self.assertIsNone(runner._temp_plugin_path)

    @mock.patch('tempfile.mkdtemp', return_value='/tmp/usm-pluginXXX')
    @mock.patch('software.plugin.constants.SW_VERSION', '24.03')
    @mock.patch('software.plugin.utils.get_major_release_version',
                return_value='24.09')
    def test_init_different_version(self, _ver, _tmp):
        deploy = {'from_release': '24.03.0', 'to_release': '24.09.0'}
        runner = DeployPluginRunner(deploy)
        self.assertIsNotNone(runner._temp_plugin_path)
        self.assertIn('upgrade.d', runner.plugin_path)

    def test_init_with_explicit_path(self):
        deploy = {'from_release': '24.09.0', 'to_release': '24.09.1'}
        runner = DeployPluginRunner(deploy, plugin_path='/custom/path')
        self.assertEqual(runner.plugin_path, '/custom/path')
        self.assertIsNone(runner._temp_plugin_path)


class TestGetHigherVersion(unittest.TestCase):
    """Tests for DeployPluginRunner.get_higher_version."""

    @mock.patch('software.plugin.utils.get_major_release_version',
                side_effect=lambda value: value)
    def test_to_higher(self, _ver):
        deploy = {'from_release': '24.03.0', 'to_release': '24.09.0'}
        result = DeployPluginRunner.get_higher_version(deploy)
        self.assertEqual(result, '24.09.0')

    @mock.patch('software.plugin.utils.get_major_release_version',
                side_effect=lambda value: value)
    def test_from_higher(self, _ver):
        deploy = {'from_release': '24.09.0', 'to_release': '24.03.0'}
        result = DeployPluginRunner.get_higher_version(deploy)
        self.assertEqual(result, '24.09.0')

    @mock.patch('software.plugin.utils.get_major_release_version',
                side_effect=lambda value: value)
    def test_equal_versions(self, _ver):
        deploy = {'from_release': '24.09.0', 'to_release': '24.09.0'}
        result = DeployPluginRunner.get_higher_version(deploy)
        self.assertEqual(result, '24.09.0')


class TestPluginPath(unittest.TestCase):
    """Tests for DeployPluginRunner.plugin_path property."""

    def test_returns_bin_path(self):
        deploy = {'from_release': '24.09.0', 'to_release': '24.09.1'}
        runner = DeployPluginRunner(deploy, plugin_path='/my/path')
        self.assertEqual(runner.plugin_path, '/my/path')
