#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from unittest.mock import MagicMock
from unittest.mock import patch
import tempfile
import os
import unittest

from software.tests import base  # noqa: F401
from software.software_worker import SoftwareWorker
import subprocess
from software.release_state import ReleaseState
from software.exceptions import ReleaseNotFound
from software import states
from software.sysinv_utils import is_host_locked_and_online
from software.sysinv_utils import are_all_hosts_unlocked_and_online
from software.sysinv_utils import get_system_info
from software.sysinv_utils import is_system_controller
from software.sysinv_utils import get_sw_version_from_host
from software.sysinv_utils import get_active_k8s_ver
from software.software_agent import PatchAgent
from software.software_functions import parse_release_metadata
from software.software_functions import is_deployment_in_progress
from software.software_functions import get_sw_version
from software.software_functions import ReleaseData


class TestSoftwareWorker(unittest.TestCase):
    @patch('software.software_worker.os.makedirs')
    def _make_worker(self, _mock_mkdirs):
        with patch.object(SoftwareWorker, '_read_file', return_value={}):
            return SoftwareWorker('rel1', 'stage1')

    def test_init(self):
        w = self._make_worker()
        self.assertEqual(w._release, 'rel1')

    def test_read_file_missing(self):
        w = self._make_worker()
        w._filename = '/nonexistent'
        self.assertEqual(w._read_file(), {})

    def test_write_and_read(self):
        w = self._make_worker()
        with tempfile.NamedTemporaryFile(
                mode='w', suffix='.json',
                delete=False) as tmpf:
            w._filename = tmpf.name
        try:
            w._write_file('op1', 'echo hello', 0, [])
            data = w._read_file()
            self.assertIn(w._run, data)
        finally:
            os.unlink(w._filename)

    def test_run_func_success(self):
        w = self._make_worker()
        with tempfile.NamedTemporaryFile(
                mode='w', suffix='.json',
                delete=False) as tmpf:
            w._filename = tmpf.name
        try:
            result = w.run_func('op', lambda val: val * 2, 5)
            self.assertEqual(result, 10)
        finally:
            os.unlink(w._filename)

    def test_run_func_failure(self):
        w = self._make_worker()
        with tempfile.NamedTemporaryFile(
                mode='w', suffix='.json',
                delete=False) as tmpf:
            w._filename = tmpf.name
        try:
            with self.assertRaises(ValueError):
                w.run_func(
                    'op', lambda: (
                        _ for _ in ()).throw(
                        ValueError("bad")))
        finally:
            os.unlink(w._filename)

    def test_run_command(self):
        w = self._make_worker()
        with tempfile.NamedTemporaryFile(
                mode='w', suffix='.json',
                delete=False) as tmpf:
            w._filename = tmpf.name
        try:
            result = w.run('op', 'echo', 'hello')
            self.assertEqual(result.returncode, 0)
        finally:
            os.unlink(w._filename)

    def test_run_command_check_fail(self):
        w = self._make_worker()
        with tempfile.NamedTemporaryFile(
                mode='w', suffix='.json',
                delete=False) as tmpf:
            w._filename = tmpf.name
        try:
            with self.assertRaises(subprocess.CalledProcessError):
                w.run('op', 'false', check=True)
        finally:
            os.unlink(w._filename)

    def test_get_key(self):
        self.assertEqual(SoftwareWorker._get_key({}), 1)
        self.assertEqual(SoftwareWorker._get_key({'0': {}, '1': {}}), 2)

    def test_suppress_text(self):
        result = SoftwareWorker._suppress_text('password=secret123 rest')
        self.assertNotIn('secret123', result)

    def test_join_stdout_stderr(self):
        output = [
            {'timestamp': '1', 'type': 'stdout', 'output': 'line1\n'},
            {'timestamp': '2', 'type': 'stderr', 'output': 'err1\n'},
        ]
        stdout, stderr = SoftwareWorker._join_stdout_stderr(output)
        self.assertIn('line1', stdout)
        self.assertIn('err1', stderr)


class TestReleaseState(unittest.TestCase):
    @patch('software.release_state.get_SWReleaseCollection')
    def test_init_by_ids(self, mock_rc):
        mock_rc.return_value.__getitem__ = MagicMock(return_value=MagicMock(is_product_release=False))
        rs = ReleaseState(release_ids=['r1'])
        self.assertEqual(rs._release_ids, ['r1'])

    @patch('software.release_state.get_SWReleaseCollection')
    def test_init_not_found(self, mock_rc):
        mock_rc.return_value.__getitem__ = MagicMock(return_value=None)
        with self.assertRaises(ReleaseNotFound):
            ReleaseState(release_ids=['r1'])

    @patch('software.release_state.get_SWReleaseCollection')
    def test_check_transition(self, mock_rc):
        rel = MagicMock()
        rel.is_product_release = False
        rel.state = states.AVAILABLE
        rel.is_product_release = False
        mock_rc.return_value.__getitem__ = MagicMock(return_value=rel)
        rs = ReleaseState(release_ids=['r1'])
        self.assertTrue(rs.check_transition(states.DEPLOYING))
        self.assertFalse(rs.check_transition(states.COMMITTED))

    def test_register_listener(self):
        ReleaseState._callbacks = []

        def mock_callback(_value):
            pass
        ReleaseState.register_event_listener(mock_callback)
        self.assertIn(mock_callback, ReleaseState._callbacks)
        ReleaseState.register_event_listener(mock_callback)
        self.assertEqual(len(ReleaseState._callbacks), 1)


class TestSysinvUtils(unittest.TestCase):
    @patch('software.sysinv_utils.get_ihost_list')
    def test_is_host_locked_and_online_true(self, mock_hosts):
        host = MagicMock(hostname='ctrl-0', availability='online',
                         administrative='locked')
        mock_hosts.return_value = [host]
        self.assertTrue(is_host_locked_and_online('ctrl-0'))

    @patch('software.sysinv_utils.get_ihost_list')
    def test_is_host_locked_and_online_false(self, mock_hosts):
        host = MagicMock(hostname='ctrl-0', availability='online',
                         administrative='unlocked')
        mock_hosts.return_value = [host]
        self.assertFalse(is_host_locked_and_online('ctrl-0'))

    @patch('software.sysinv_utils.get_ihost_list')
    def test_are_all_hosts_unlocked(self, mock_hosts):
        h = MagicMock(administrative='unlocked', availability='available')
        mock_hosts.return_value = [h]
        self.assertTrue(are_all_hosts_unlocked_and_online())

    @patch('software.sysinv_utils.get_ihost_list')
    def test_are_all_hosts_not_unlocked(self, mock_hosts):
        h = MagicMock(administrative='locked', availability='online')
        mock_hosts.return_value = [h]
        self.assertFalse(are_all_hosts_unlocked_and_online())

    @patch('software.sysinv_utils.utils.get_platform_conf')
    def test_get_system_info(self, mock_conf):
        mock_conf.side_effect = (
            lambda key: {
                'system_type': 'All-in-one',
                'system_mode': 'simplex',
            }[key]
        )
        _sys_type, sys_mode = get_system_info()
        self.assertEqual(sys_mode, 'simplex')

    @patch('software.sysinv_utils.utils.get_platform_conf',
           return_value='systemcontroller')
    def test_is_system_controller(self, _mock_conf):
        self.assertTrue(is_system_controller())

    @patch('software.sysinv_utils.get_ihost_list')
    def test_get_sw_version_from_host(self, mock_hosts):
        h = MagicMock(hostname='ctrl-0', sw_version='24.09')
        mock_hosts.return_value = [h]
        self.assertEqual(get_sw_version_from_host('ctrl-0'), '24.09')
        self.assertIsNone(get_sw_version_from_host('unknown'))

    @patch('software.sysinv_utils.get_sysinv_client')
    @patch('software.sysinv_utils.utils.get_endpoints_token',
           return_value=('t', 'e'))
    def test_get_active_k8s_ver(self, _mock_tok, mock_client):
        ver = MagicMock(state='active', version='v1.28.4')
        mock_client.return_value.kube_version.list.return_value = [ver]
        self.assertEqual(get_active_k8s_ver(), 'v1.28.4')


class TestPatchAgentHandlePatchOpCounter(unittest.TestCase):
    def _make_pa(self):
        pa = PatchAgent.__new__(PatchAgent)
        pa.node_is_patched = False
        pa.node_is_patched_timestamp = 0
        pa.patch_op_counter = 0
        pa.changes = False
        pa.patch_failed = False
        pa.state = 'idle'
        pa.query_id = 0
        pa.latest_sysroot_commit = None
        pa.latest_feed_commit = None
        pa.sock_out = None
        pa.install_local = False
        pa.pre_bootstrap = False
        return pa

    @patch('software.software_agent.os.path.exists', return_value=True)
    @patch('software.software_agent.os.path.getmtime', return_value=100.0)
    def test_counter_with_patched_file(self, _mock_mtime, _mock_exists):
        pa = self._make_pa()
        with patch.object(pa, 'query', return_value=True):
            pa.handle_patch_op_counter(5)
        self.assertTrue(pa.node_is_patched)
        self.assertEqual(pa.patch_op_counter, 5)

    @patch('software.software_agent.os.path.exists', return_value=False)
    def test_counter_cleared(self, _mock_exists):
        pa = self._make_pa()
        pa.node_is_patched = True
        with patch.object(pa, 'query', return_value=True):
            pa.handle_patch_op_counter(1)
        self.assertFalse(pa.node_is_patched)

    @patch('software.software_agent.os.path.exists', return_value=True)
    @patch('software.software_agent.os.path.getmtime', return_value=200.0)
    def test_counter_timestamp_changed(self, _mock_mtime, _mock_exists):
        pa = self._make_pa()
        pa.node_is_patched = True
        pa.node_is_patched_timestamp = 100.0
        with patch.object(pa, 'query', return_value=True):
            pa.handle_patch_op_counter(1)
        self.assertEqual(pa.node_is_patched_timestamp, 200.0)

    @patch('software.software_agent.os.path.exists', return_value=True)
    @patch('software.software_agent.os.path.getmtime', return_value=100.0)
    def test_query_failure_resets_counter(self, _mock_mtime, _mock_exists):
        pa = self._make_pa()
        with patch.object(pa, 'query', return_value=False):
            pa.handle_patch_op_counter(5)
        self.assertEqual(pa.patch_op_counter, 0)


class TestParseReleaseMetadata(unittest.TestCase):
    def test_parse(self):
        with tempfile.NamedTemporaryFile(
                mode='w', suffix='.xml',
                delete=False) as tmpf:
            tmpf.write(
                '<patch><id>R1</id>'
                '<sw_version>24.09</sw_version>'
                '<summary>test</summary>'
                '<description>d</description>'
                '<status>REL</status>'
                '<reboot_required>Y'
                '</reboot_required>'
                '</patch>')
            fname = tmpf.name
        try:
            result = parse_release_metadata(fname)
            self.assertEqual(result['id'], 'R1')
        finally:
            os.unlink(fname)


class TestIsDeploymentInProgress(unittest.TestCase):
    @patch('software.software_functions.get_instance')
    def test_no_deploy(self, mock_db):
        mock_db.return_value.get_deploy_all.return_value = []
        self.assertFalse(is_deployment_in_progress())

    @patch('software.software_functions.get_instance')
    def test_deploy_exists(self, mock_db):
        mock_db.return_value.get_deploy_all.return_value = [{'state': 'start'}]
        self.assertTrue(is_deployment_in_progress())


class TestGetSwVersion(unittest.TestCase):
    def test_get_sw_version(self):
        with tempfile.NamedTemporaryFile(
                mode='w', suffix='.xml',
                delete=False) as tmpf:
            tmpf.write('<patch><sw_version>24.09.1</sw_version></patch>')
            fname = tmpf.name
        try:
            result = get_sw_version([fname])
            self.assertEqual(result, '24.09.1')
        finally:
            os.unlink(fname)


class TestReleaseDataLoadAll(unittest.TestCase):
    @patch('software.software_functions.glob.glob', return_value=[])
    def test_load_all_empty(self, _mock_glob):
        rd = ReleaseData()
        rd.load_all()
        self.assertEqual(rd.metadata, {})
