#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for uncovered paths in software.utils, software.config,
software.deploy_state, software.deploy_host_state.
"""

import json
import os
import socket
import tempfile
import shutil
import time
import unittest
from unittest import mock

from software.tests import base  # noqa: F401
from software.states import DEPLOY_STATES
from software.states import DEPLOY_HOST_STATES
from software.deploy_state import DeployState
from software.deploy_host_state import DeployHostState
from software.exceptions import InvalidOperation
from software.utils import find_file_by_regex
from software.utils import get_all_files
from software.utils import get_iface_ip
from software.utils import get_software_filesystem_data
from software.utils import get_synced_software_filesystem_data
from software.utils import interval_task
from software.utils import load_from_json_file
from software.utils import read_cached_file
from software.utils import save_to_json_file


class TestReadCachedFile(unittest.TestCase):
    """Tests for read_cached_file — caching with mtime check."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.filepath = os.path.join(self.tmpdir, "test.conf")
        with open(self.filepath, 'w') as f:
            f.write("initial content")

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_reads_file_first_time(self):
        """First read loads the file content."""
        cache = {}
        result = read_cached_file(self.filepath, cache)
        self.assertEqual(result, "initial content")
        self.assertIn('mtime', cache)
        self.assertIn('data', cache)

    def test_returns_cached_on_same_mtime(self):
        """Second read with same mtime returns cached data."""
        cache = {}
        read_cached_file(self.filepath, cache)
        # Modify cache data to verify it's not re-read
        cache['data'] = "cached value"
        result = read_cached_file(self.filepath, cache)
        self.assertEqual(result, "cached value")

    def test_rereads_on_mtime_change(self):
        """Re-reads file when mtime changes."""
        cache = {}
        read_cached_file(self.filepath, cache)
        # Touch the file to change mtime
        time.sleep(0.01)
        with open(self.filepath, 'w') as f:
            f.write("new content")
        result = read_cached_file(self.filepath, cache)
        self.assertEqual(result, "new content")

    def test_calls_reload_func(self):
        """Calls reload_func when file is reloaded."""
        cache = {}
        reload_data = []
        read_cached_file(self.filepath, cache,
                         reload_func=reload_data.append)
        self.assertEqual(reload_data, ["initial content"])


class TestSaveLoadJsonFile(unittest.TestCase):
    """Tests for save_to_json_file and load_from_json_file."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_save_and_load_roundtrip(self):
        """Data survives save/load cycle."""
        filepath = os.path.join(self.tmpdir, "data.json")
        data = {"releases": ["24.09.0", "25.03.0"], "count": 2}
        save_to_json_file(filepath, data)
        result = load_from_json_file(filepath)
        self.assertEqual(result, data)

    def test_load_missing_file_returns_none(self):
        """Loading non-existent file returns None."""
        result = load_from_json_file("/tmp/nonexistent_file_xyz.json")
        self.assertIsNone(result)

    def test_save_creates_file(self):
        """save_to_json_file creates the file."""
        filepath = os.path.join(self.tmpdir, "new.json")
        save_to_json_file(filepath, {"key": "value"})
        self.assertTrue(os.path.exists(filepath))


class TestGetAllFiles(unittest.TestCase):
    """Tests for get_all_files."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_returns_file_list(self):
        """Returns full paths of files in directory."""
        open(os.path.join(self.tmpdir, "a.txt"), 'w').close()
        open(os.path.join(self.tmpdir, "b.txt"), 'w').close()
        result = get_all_files(self.tmpdir)
        self.assertEqual(len(result), 2)
        self.assertTrue(all(os.path.isabs(f) for f in result))

    @mock.patch('os.listdir', side_effect=Exception("fail"))
    def test_returns_empty_on_error(self, _):
        """Returns empty list on error."""
        result = get_all_files("/tmp/nonexistent")
        self.assertEqual(result, [])


class TestGetSoftwareFilesystemData(unittest.TestCase):
    """Tests for get_software_filesystem_data and synced variant."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    @mock.patch('software.utils.constants.SOFTWARE_JSON_FILE', '/tmp/nonexist.json')
    def test_missing_file_returns_empty_dict(self):
        """Returns empty dict when file doesn't exist."""
        result = get_software_filesystem_data("/tmp/nonexist_xyz.json")
        self.assertEqual(result, {})

    def test_returns_data_from_file(self):
        """Returns parsed JSON data."""
        filepath = os.path.join(self.tmpdir, "sw.json")
        with open(filepath, 'w') as f:
            json.dump({"version": "24.09"}, f)
        result = get_software_filesystem_data(filepath)
        self.assertEqual(result, {"version": "24.09"})

    @mock.patch('software.utils.constants.SYNCED_SOFTWARE_JSON_FILE', '/tmp/nonexist.json')
    def test_synced_missing_returns_empty(self):
        """Synced variant returns empty dict when file missing."""
        result = get_synced_software_filesystem_data()
        self.assertEqual(result, {})


class TestFindFileByRegex(unittest.TestCase):
    """Tests for find_file_by_regex."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_finds_matching_files(self):
        """Returns files matching regex pattern."""
        open(os.path.join(self.tmpdir, "patch_001.xml"), 'w').close()
        open(os.path.join(self.tmpdir, "patch_002.xml"), 'w').close()
        open(os.path.join(self.tmpdir, "other.txt"), 'w').close()
        result = find_file_by_regex(self.tmpdir, r"patch_\d+\.xml")
        self.assertEqual(sorted(result), ["patch_001.xml", "patch_002.xml"])

    def test_no_match_returns_empty(self):
        """Returns empty list when no files match."""
        open(os.path.join(self.tmpdir, "other.txt"), 'w').close()
        result = find_file_by_regex(self.tmpdir, r"patch_\d+\.xml")
        self.assertEqual(result, [])

    def test_nonexistent_dir_returns_empty(self):
        """Returns empty list for non-existent directory."""
        result = find_file_by_regex("/tmp/nonexistent_dir_xyz", r".*")
        self.assertEqual(result, [])


class TestIntervalTask(unittest.TestCase):
    """Tests for interval_task decorator — rate limiting."""

    def test_immediate_call_blocked_by_interval(self):
        """Call within interval of decoration returns no_run_return."""
        @interval_task(interval_sec=100, no_run_return='skipped')
        def my_func():
            return 'ran'
        result = my_func()
        self.assertEqual(result, 'skipped')

    def test_call_after_interval_executes(self):
        """Call after interval expires runs the function."""
        @interval_task(interval_sec=0)
        def my_func():
            return 'ran'
        time.sleep(0.01)
        result = my_func()
        self.assertEqual(result, 'ran')

    def test_subsequent_call_within_interval_blocked(self):
        """After execution, next call within interval is blocked."""
        @interval_task(interval_sec=100, no_run_return='blocked')
        def my_func():
            return 'ran'
        time.sleep(0.01)
        # First call after interval passes
        # But subsequent immediate call is blocked
        my_func()
        result = my_func()
        self.assertEqual(result, 'blocked')


class TestGetIfaceIp(unittest.TestCase):
    """Tests for get_iface_ip — interface IP lookup."""

    def test_invalid_iface_raises_valueerror(self):
        """Empty interface name raises ValueError."""
        with self.assertRaises(ValueError):
            get_iface_ip("")

    def test_none_iface_raises_valueerror(self):
        """None interface raises ValueError."""
        with self.assertRaises(ValueError):
            get_iface_ip(None)

    def test_invalid_family_raises_typeerror(self):
        """Invalid address family raises TypeError."""
        with self.assertRaises(TypeError):
            get_iface_ip("eth0", ip_family=999)

    @mock.patch('software.utils.psutil.net_if_addrs')
    def test_missing_interface_returns_empty(self, mock_addrs):
        """Non-existent interface returns empty list."""
        mock_addrs.return_value = {"lo": []}
        result = get_iface_ip("eth99")
        self.assertEqual(result, [])

    @mock.patch('software.utils.psutil.net_if_addrs')
    def test_returns_ipv4_addresses(self, mock_addrs):
        """Returns IPv4 addresses for matching interface."""
        addr = mock.MagicMock()
        addr.family = socket.AF_INET
        addr.address = "192.168.1.10"
        mock_addrs.return_value = {"mgmt0": [addr]}
        result = get_iface_ip("mgmt0", socket.AF_INET)
        self.assertEqual(result, ["192.168.1.10"])

    @mock.patch('software.utils.psutil.net_if_addrs')
    def test_filters_by_family(self, mock_addrs):
        """Only returns addresses matching requested family."""
        addr_v4 = mock.MagicMock()
        addr_v4.family = socket.AF_INET
        addr_v4.address = "192.168.1.10"
        addr_v6 = mock.MagicMock()
        addr_v6.family = socket.AF_INET6
        addr_v6.address = "fd00::1"
        mock_addrs.return_value = {"mgmt0": [addr_v4, addr_v6]}
        result = get_iface_ip("mgmt0", socket.AF_INET6)
        self.assertEqual(result, ["fd00::1"])


class TestDeployStateFullTransitions(unittest.TestCase):
    """Tests for DeployState full lifecycle transitions."""

    def setUp(self):
        DeployState._instance = None
        DeployState._callbacks = []

    @mock.patch('software.deploy_state.get_instance')
    def test_start_done_to_host(self, mock_db):
        """START_DONE -> HOST via deploy_host()."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'start-done'}
        ]
        ds = DeployState()
        ds.deploy_host()
        mock_db.return_value.update_deploy.assert_called_with(
            state=DEPLOY_STATES.HOST)

    @mock.patch('software.deploy_state.get_instance')
    def test_host_done_to_activate(self, mock_db):
        """HOST_DONE -> ACTIVATE."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'host-done'}
        ]
        ds = DeployState()
        ds.activate()
        mock_db.return_value.update_deploy.assert_called_with(
            state=DEPLOY_STATES.ACTIVATE)

    @mock.patch('software.deploy_state.get_instance')
    def test_activate_done_to_completed(self, mock_db):
        """ACTIVATE_DONE -> COMPLETED."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'activate-done'}
        ]
        ds = DeployState()
        ds.completed()
        mock_db.return_value.update_deploy.assert_called_with(
            state=DEPLOY_STATES.COMPLETED)

    @mock.patch('software.deploy_state.get_instance')
    def test_activate_failed_to_activate_retry(self, mock_db):
        """ACTIVATE_FAILED -> ACTIVATE (retry)."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'activate-failed'}
        ]
        ds = DeployState()
        ds.activate()
        mock_db.return_value.update_deploy.assert_called_with(
            state=DEPLOY_STATES.ACTIVATE)

    @mock.patch('software.deploy_state.get_instance')
    def test_activate_failed_to_rollback_pending(self, mock_db):
        """ACTIVATE_FAILED -> ACTIVATE_ROLLBACK_PENDING."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'activate-failed'}
        ]
        ds = DeployState()
        ds.transform(DEPLOY_STATES.ACTIVATE_ROLLBACK_PENDING)
        mock_db.return_value.update_deploy.assert_called_with(
            state=DEPLOY_STATES.ACTIVATE_ROLLBACK_PENDING)

    @mock.patch('software.deploy_state.get_instance')
    def test_activate_rollback_pending_to_rollback(self, mock_db):
        """ACTIVATE_ROLLBACK_PENDING -> ACTIVATE_ROLLBACK."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'activate-rollback-pending'}
        ]
        ds = DeployState()
        ds.activate_rollback()
        mock_db.return_value.update_deploy.assert_called_with(
            state=DEPLOY_STATES.ACTIVATE_ROLLBACK)

    @mock.patch('software.deploy_state.get_instance')
    def test_activate_rollback_to_done(self, mock_db):
        """ACTIVATE_ROLLBACK -> ACTIVATE_ROLLBACK_DONE."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'activate-rollback'}
        ]
        ds = DeployState()
        ds.activate_rollback_done()
        mock_db.return_value.update_deploy.assert_called_with(
            state=DEPLOY_STATES.ACTIVATE_ROLLBACK_DONE)

    @mock.patch('software.deploy_state.get_instance')
    def test_activate_rollback_to_failed(self, mock_db):
        """ACTIVATE_ROLLBACK -> ACTIVATE_ROLLBACK_FAILED."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'activate-rollback'}
        ]
        ds = DeployState()
        ds.activate_rollback_failed()
        mock_db.return_value.update_deploy.assert_called_with(
            state=DEPLOY_STATES.ACTIVATE_ROLLBACK_FAILED)

    @mock.patch('software.deploy_state.get_instance')
    def test_host_rollback_done_is_terminal(self, mock_db):
        """HOST_ROLLBACK_DONE cannot transition further."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'host-rollback-done'}
        ]
        ds = DeployState()
        with self.assertRaises(InvalidOperation):
            ds.transform(DEPLOY_STATES.HOST)

    @mock.patch('software.deploy_state.get_instance')
    def test_start_failed_is_terminal(self, mock_db):
        """START_FAILED cannot transition further."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'start-failed'}
        ]
        ds = DeployState()
        with self.assertRaises(InvalidOperation):
            ds.transform(DEPLOY_STATES.HOST)


class TestDeployHostStateFullPaths(unittest.TestCase):
    """Tests for additional DeployHostState transition paths."""

    def setUp(self):
        DeployHostState._callbacks = []

    @mock.patch('software.deploy_host_state.get_instance')
    def test_deploying_to_deployed(self, mock_db):
        """DEPLOYING -> DEPLOYED (success path)."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'deploying'
        }
        dhs = DeployHostState("controller-0")
        dhs.transform(DEPLOY_HOST_STATES.DEPLOYED)
        mock_db.return_value.update_deploy_host.assert_called_with(
            "controller-0", DEPLOY_HOST_STATES.DEPLOYED)

    @mock.patch('software.deploy_host_state.get_instance')
    def test_deploying_to_failed(self, mock_db):
        """DEPLOYING -> FAILED."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'deploying'
        }
        dhs = DeployHostState("worker-0")
        dhs.transform(DEPLOY_HOST_STATES.FAILED)
        mock_db.return_value.update_deploy_host.assert_called_with(
            "worker-0", DEPLOY_HOST_STATES.FAILED)

    @mock.patch('software.deploy_host_state.get_instance')
    def test_failed_to_deploying_retry(self, mock_db):
        """FAILED -> DEPLOYING (retry)."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'failed'
        }
        dhs = DeployHostState("worker-0")
        dhs.transform(DEPLOY_HOST_STATES.DEPLOYING)
        mock_db.return_value.update_deploy_host.assert_called_with(
            "worker-0", DEPLOY_HOST_STATES.DEPLOYING)

    @mock.patch('software.deploy_host_state.get_instance')
    def test_failed_reentrant(self, mock_db):
        """FAILED -> FAILED is allowed (reentrant)."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'failed'
        }
        dhs = DeployHostState("worker-0")
        dhs.transform(DEPLOY_HOST_STATES.FAILED)
        mock_db.return_value.update_deploy_host.assert_called_with(
            "worker-0", DEPLOY_HOST_STATES.FAILED)

    @mock.patch('software.deploy_host_state.get_instance')
    def test_rollback_deploying_to_rollback_deployed(self, mock_db):
        """ROLLBACK_DEPLOYING -> ROLLBACK_DEPLOYED."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'rollback-deploying'
        }
        dhs = DeployHostState("controller-0")
        dhs.transform(DEPLOY_HOST_STATES.ROLLBACK_DEPLOYED)
        mock_db.return_value.update_deploy_host.assert_called_with(
            "controller-0", DEPLOY_HOST_STATES.ROLLBACK_DEPLOYED)

    @mock.patch('software.deploy_host_state.get_instance')
    def test_rollback_deploying_to_rollback_failed(self, mock_db):
        """ROLLBACK_DEPLOYING -> ROLLBACK_FAILED."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'rollback-deploying'
        }
        dhs = DeployHostState("worker-0")
        dhs.transform(DEPLOY_HOST_STATES.ROLLBACK_FAILED)
        mock_db.return_value.update_deploy_host.assert_called_with(
            "worker-0", DEPLOY_HOST_STATES.ROLLBACK_FAILED)

    @mock.patch('software.deploy_host_state.get_instance')
    def test_rollback_failed_to_rollback_deploying_retry(self, mock_db):
        """ROLLBACK_FAILED -> ROLLBACK_DEPLOYING (retry)."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'rollback-failed'
        }
        dhs = DeployHostState("worker-0")
        dhs.transform(DEPLOY_HOST_STATES.ROLLBACK_DEPLOYING)
        mock_db.return_value.update_deploy_host.assert_called_with(
            "worker-0", DEPLOY_HOST_STATES.ROLLBACK_DEPLOYING)

    @mock.patch('software.deploy_host_state.get_instance')
    def test_deployed_to_rollback_pending(self, mock_db):
        """DEPLOYED -> ROLLBACK_PENDING."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'deployed'
        }
        dhs = DeployHostState("controller-0")
        dhs.transform(DEPLOY_HOST_STATES.ROLLBACK_PENDING)
        mock_db.return_value.update_deploy_host.assert_called_with(
            "controller-0", DEPLOY_HOST_STATES.ROLLBACK_PENDING)

    @mock.patch('software.deploy_host_state.get_instance')
    def test_rollback_deployed_is_terminal(self, mock_db):
        """ROLLBACK_DEPLOYED is terminal — no transitions."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'rollback-deployed'
        }
        dhs = DeployHostState("controller-0")
        with self.assertRaises(InvalidOperation):
            dhs.transform(DEPLOY_HOST_STATES.PENDING)
