#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import shutil
import sys
import tempfile
import unittest
from unittest.mock import MagicMock
from unittest.mock import patch

# cgtsclient is not available in the test env and is not mocked by base,
# so mock it before importing modules that pull it in.
sys.modules['cgtsclient'] = MagicMock()
sys.modules['cgtsclient.client'] = MagicMock()

from software.tests import base  # noqa: F401
from software import software_worker
from software import plugin
from software import system_deploy_state
from software import sysinv_utils
from software import constants
from software.states import SYSTEM_DEPLOY_STATES


class TestGetSysinvClient(unittest.TestCase):
    @patch('software.sysinv_utils.utils.get_endpoints_token',
           return_value=("tok", "ep"))
    def test_success(self, _mock_token):
        # cgtsclient is mocked at module level
        result = sysinv_utils.get_sysinv_client("token", "http://endpoint")
        self.assertIsNotNone(result)


class TestGetActiveK8sVer(unittest.TestCase):
    @patch('software.sysinv_utils.get_sysinv_client')
    @patch('software.sysinv_utils.utils.get_endpoints_token',
           return_value=("tok", "ep"))
    def test_found(self, _mock_token, mock_client):
        mock_ver = MagicMock()
        mock_ver.state = "active"
        mock_ver.version = "v1.28.4"
        mock_client.return_value.kube_version.list.return_value = [mock_ver]
        result = sysinv_utils.get_active_k8s_ver()
        self.assertEqual(result, "v1.28.4")

    @patch('software.sysinv_utils.get_sysinv_client')
    @patch('software.sysinv_utils.utils.get_endpoints_token',
           return_value=("tok", "ep"))
    def test_not_found(self, _mock_token, mock_client):
        mock_ver = MagicMock()
        mock_ver.state = "available"
        mock_client.return_value.kube_version.list.return_value = [mock_ver]
        with self.assertRaises(Exception):  # noqa: H202
            sysinv_utils.get_active_k8s_ver()


class TestGetIhostList(unittest.TestCase):
    @patch('software.sysinv_utils.get_sysinv_client')
    @patch('software.sysinv_utils.utils.get_endpoints_token',
           return_value=("tok", "ep"))
    def test_success(self, _mock_token, mock_client):
        mock_client.return_value.ihost.list.return_value = ["host1", "host2"]
        result = sysinv_utils.get_ihost_list()
        self.assertEqual(len(result), 2)


class TestIsHostLockedAndOnline(unittest.TestCase):
    @patch('software.sysinv_utils.get_ihost_list')
    def test_locked_online(self, mock_list):
        mock_host = MagicMock()
        mock_host.hostname = "worker-0"
        mock_host.availability = constants.AVAILABILITY_ONLINE
        mock_host.administrative = constants.ADMIN_LOCKED
        mock_list.return_value = [mock_host]
        result = sysinv_utils.is_host_locked_and_online("worker-0")
        self.assertTrue(result)

    @patch('software.sysinv_utils.get_ihost_list')
    def test_not_locked(self, mock_list):
        mock_host = MagicMock()
        mock_host.hostname = "worker-0"
        mock_host.availability = constants.AVAILABILITY_ONLINE
        mock_host.administrative = "unlocked"
        mock_list.return_value = [mock_host]
        result = sysinv_utils.is_host_locked_and_online("worker-0")
        self.assertFalse(result)


class TestSystemDeployState(unittest.TestCase):
    def test_register_listener(self):
        def callback(*_args):
            pass
        system_deploy_state.SystemDeployState.register_event_listener(callback)
        self.assertIn(
            callback,
            system_deploy_state.SystemDeployState._callbacks)
        system_deploy_state.SystemDeployState._callbacks.remove(callback)

    def test_register_none(self):
        initial_len = len(system_deploy_state.SystemDeployState._callbacks)
        system_deploy_state.SystemDeployState.register_event_listener(None)
        self.assertEqual(
            len(system_deploy_state.SystemDeployState._callbacks),
            initial_len)

    @patch('software.system_deploy_state.get_instance')
    def test_get_system_deploy_state_none(self, mock_db):
        mock_db.return_value.get_system_deploy.return_value = None
        result = (
            system_deploy_state.SystemDeployState
            .get_system_deploy_state())
        self.assertIsNone(result)

    @patch('software.system_deploy_state.get_instance')
    def test_get_system_deploy_state_exists(self, mock_db):
        mock_db.return_value.get_system_deploy.return_value = {"state": "init"}
        result = (
            system_deploy_state.SystemDeployState
            .get_system_deploy_state())
        self.assertEqual(result, SYSTEM_DEPLOY_STATES.START)


class TestDeployPluginRunner(unittest.TestCase):
    def test_get_higher_version_to_higher(self):
        deploy = {"from_release": "24.09.0", "to_release": "25.03.0"}
        result = plugin.DeployPluginRunner.get_higher_version(deploy)
        self.assertEqual(result, "25.03")

    def test_get_higher_version_from_higher(self):
        deploy = {"from_release": "25.03.0", "to_release": "24.09.0"}
        result = plugin.DeployPluginRunner.get_higher_version(deploy)
        self.assertEqual(result, "25.03")

    @patch('software.plugin.constants.SW_VERSION', '25.03')
    def test_init_same_version(self):
        deploy = {"from_release": "24.09.0", "to_release": "25.03.0"}
        runner = plugin.DeployPluginRunner(deploy)
        self.assertIsNotNone(runner.plugin_path)

    @patch('software.plugin.constants.SW_VERSION', '24.09')
    @patch('software.plugin.tempfile.mkdtemp',
           return_value="/tmp/usm-plugin-test")
    def test_init_different_version(self, _mock_mkdtemp):
        deploy = {"from_release": "24.09.0", "to_release": "25.03.0"}
        runner = plugin.DeployPluginRunner(deploy)
        self.assertIn("/tmp/usm-plugin-test", runner.plugin_path)

    def test_init_with_plugin_path(self):
        deploy = {"from_release": "24.09.0", "to_release": "25.03.0"}
        runner = plugin.DeployPluginRunner(deploy, plugin_path="/custom/path")
        self.assertEqual(runner.plugin_path, "/custom/path")

    @patch('software.plugin.utils.get_endpoints_token',
           return_value=("token", "http://sys/v1"))
    def test_set_auth_token(self, _mock_token):
        deploy = {"from_release": "24.09.0", "to_release": "25.03.0"}
        runner = plugin.DeployPluginRunner(deploy, plugin_path="/path")
        runner._env = {}
        runner.set_auth_token()
        self.assertEqual(runner._env["OS_AUTH_TOKEN"], "token")

    def test_set_deploy_options(self):
        deploy = {"from_release": "24.09.0", "to_release": "25.03.0",
                  "options": {"key1": "val1"}}
        runner = plugin.DeployPluginRunner(deploy, plugin_path="/path")
        runner._env = {}
        runner.set_deploy_options()
        self.assertEqual(runner._env["key1"], "val1")

    def test_set_execution_context(self):
        deploy = {"from_release": "24.09.0", "to_release": "25.03.0"}
        runner = plugin.DeployPluginRunner(deploy, plugin_path="/path")
        runner._env = {}
        runner.set_execution_context([("ctx_key", "ctx_val")])
        self.assertEqual(runner._env["from_release"], "24.09.0")
        self.assertEqual(runner._env["ctx_key"], "ctx_val")


class TestSoftwareWorker(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    @patch('software.software_worker.constants.WORKER_SUMMARY_DIR')
    def test_init(self, mock_dir):
        mock_dir.__str__ = lambda val: self.test_dir
        with patch(
                'software.software_worker'
                '.constants.WORKER_SUMMARY_DIR',
                self.test_dir):
            worker = software_worker.SoftwareWorker("rel-24.09", "deploy")
            self.assertIsNotNone(worker._filename)

    @patch('software.software_worker.constants.WORKER_SUMMARY_DIR')
    def test_read_file_not_exists(self, _mock_dir):
        with patch(
                'software.software_worker'
                '.constants.WORKER_SUMMARY_DIR',
                self.test_dir):
            worker = software_worker.SoftwareWorker("rel-24.09", "deploy")
            result = worker._read_file()
            self.assertEqual(result, {})

    @patch('software.software_worker.constants.WORKER_SUMMARY_DIR')
    def test_write_and_read(self, _mock_dir):
        with patch(
                'software.software_worker'
                '.constants.WORKER_SUMMARY_DIR',
                self.test_dir):
            worker = software_worker.SoftwareWorker("rel-24.09", "deploy")
            worker._write_file("op1", "ls -la", 0, "output")
            result = worker._read_file()
            self.assertIn(worker._run, result)
            self.assertEqual(result[worker._run]["op1"]["rc"], 0)
