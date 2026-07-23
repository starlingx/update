#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from software import states
import threading
import unittest
from unittest.mock import patch
from unittest.mock import MagicMock

from software.tests import base as test_base  # noqa: F401
from software.tests.test_helpers import create_software_controller  # noqa: E402
from software.software_controller import PatchController
from software.exceptions import HostNotFound
import socket
from software.exceptions import HostAgentUnreachable
from software.software_controller import DEPLOY_STATES
from software.exceptions import SoftwareServiceError
from software.exceptions import SoftwareError
from software import constants
from software.software_controller import DEPLOY_HOST_STATES


def _create_controller():
    """Create a PatchController mock with full attributes."""
    return create_software_controller(
        db_api_instance=MagicMock(),
        hosts={},
        hosts_lock=threading.RLock(),
        controller_neighbours={},
        controller_neighbours_lock=threading.RLock(),
        hostname="controller-0",
        allow_insvc_patching=True,
        base_pkgdata=MagicMock(),
    )


class TestDeployHost(unittest.TestCase):
    """Tests for _deploy_host."""

    def test_host_not_found(self):
        sc = _create_controller()
        sc.db_api_instance.get_deploy_host_by_hostname.return_value = None
        with self.assertRaises(HostNotFound):
            PatchController._deploy_host(sc, "bad-host", False)

    @patch('software.software_controller.utils.gethostbyname')
    def test_dns_failure(self, mock_dns):
        sc = _create_controller()
        sc.db_api_instance.get_deploy_host_by_hostname.return_value = {
            "hostname": "ctrl-0"}
        mock_dns.side_effect = socket.gaierror("not found")
        result = PatchController._deploy_host(sc, "ctrl-0", False)
        self.assertIn("not found", result["error"])

    @patch('time.sleep')
    @patch('software.software_controller.SoftwareMessageCheckAgentAliveReq')
    @patch('software.software_controller.utils.gethostbyname',
           return_value='10.0.0.1')
    def test_agent_unreachable(self, _mock_dns, _mock_alive_cls, _mock_sleep):
        sc = _create_controller()
        sc.db_api_instance.get_deploy_host_by_hostname.return_value = {
            "hostname": "ctrl-0"}
        agent = MagicMock()
        agent.is_alive = False
        sc.hosts = {"10.0.0.1": agent}
        with self.assertRaises(HostAgentUnreachable):
            PatchController._deploy_host(sc, "ctrl-0", False)


class TestSoftwareDeployDeleteApi(unittest.TestCase):
    """Tests for software_deploy_delete_api."""

    def test_hosts_not_online(self):
        sc = _create_controller()
        sc.db_api_instance.get_current_deploy.return_value = {
            "to_release": "24.09.1", "from_release": "24.09.0"}
        mock_deploy = MagicMock()
        mock_deploy.get_deploy_state.return_value = DEPLOY_STATES.HOST
        with patch(
                'software.software_controller.DeployState.get_instance',
                return_value=mock_deploy):
            with patch(
                    'software.software_controller'
                    '.are_all_hosts_unlocked_and_online',
                    return_value=False):
                with self.assertRaises(SoftwareServiceError):
                    PatchController.software_deploy_delete_api(sc)

    def test_major_release_wrong_controller(self):
        sc = _create_controller()
        sc.hostname = "controller-1"
        sc.db_api_instance.get_current_deploy.return_value = {
            "to_release": "25.03", "from_release": "24.09"}
        mock_deploy = MagicMock()
        mock_deploy.get_deploy_state.return_value = DEPLOY_STATES.START_DONE
        mock_rs = MagicMock()
        mock_rs.has_release_id.return_value = True
        mock_rs.is_major_release_deployment.return_value = True
        with patch(
                'software.software_controller.DeployState.get_instance',
                return_value=mock_deploy):
            with patch(
                    'software.software_controller.ReleaseState',
                    return_value=mock_rs):
                with self.assertRaises(SoftwareServiceError):
                    PatchController.software_deploy_delete_api(sc)


class TestSoftwareSync(unittest.TestCase):
    """Tests for software_sync timeout path."""

    @patch('time.time')
    @patch('time.sleep')
    @patch('software.software_controller.PatchMessageHelloAgent')
    @patch('software.software_controller.PatchMessageSyncReq')
    @patch('software.software_controller.cfg')
    def test_sync_timeout(self, _mock_cfg, _mock_sync_cls, _mock_hello_cls,
                          _mock_sleep, mock_time):
        sc = _create_controller()
        sc.sock_out = MagicMock()
        sc.install_local = False
        nbr = MagicMock()
        nbr.get_synced.return_value = False
        sc.controller_neighbours = {"peer": nbr}
        # Simulate timeout: time goes from 0 to 200
        mock_time.side_effect = [0] + [200] * 10
        result = PatchController.software_sync(sc)
        self.assertFalse(result)

    @patch('time.time')
    @patch('time.sleep')
    @patch('software.software_controller.PatchMessageHelloAgent')
    @patch('software.software_controller.PatchMessageSyncReq')
    @patch('software.software_controller.cfg')
    def test_sync_success(self, _mock_cfg, _mock_sync_cls, _mock_hello_cls,
                          _mock_sleep, mock_time):
        sc = _create_controller()
        sc.sock_out = MagicMock()
        sc.install_local = False
        nbr = MagicMock()
        nbr.get_synced.return_value = True
        sc.controller_neighbours = {"peer": nbr}
        mock_time.side_effect = [0, 1]
        result = PatchController.software_sync(sc)
        self.assertTrue(result)


class TestInstallReleases(unittest.TestCase):
    """Tests for install_releases."""

    @patch('software.software_controller.apt_utils')
    def test_install_apt_failure(self, mock_apt):
        sc = _create_controller()
        sc._release_basic_checks.return_value = None
        rel = MagicMock()
        rel.activation_scripts = []
        sc.release_collection.get_release_by_id.return_value = rel
        mock_apt.run_install.side_effect = SoftwareError("apt fail")
        with self.assertRaises(SoftwareError):
            PatchController.install_releases(sc, ["P1"], "/feed")


class TestAnyPatchHostInstalling(unittest.TestCase):
    """Tests for any_patch_host_installing."""

    def test_no_hosts(self):
        sc = _create_controller()
        sc.hosts = {}
        result = PatchController.any_patch_host_installing(sc)
        self.assertFalse(result)

    def test_host_installing(self):
        sc = _create_controller()
        host = MagicMock()
        host.state = constants.PATCH_AGENT_STATE_INSTALLING
        sc.hosts = {"10.0.0.1": host}
        result = PatchController.any_patch_host_installing(sc)
        self.assertTrue(result)


class TestCheckReleasesState(unittest.TestCase):
    """Tests for check_releases_state."""

    def test_all_available(self):
        sc = _create_controller()
        r = MagicMock(state=states.AVAILABLE)
        sc.release_collection.get_release_by_id.return_value = r
        result = PatchController.check_releases_state(sc, ["P1"], states.AVAILABLE)
        self.assertTrue(result)

    def test_wrong_state(self):
        sc = _create_controller()
        r = MagicMock(state=states.DEPLOYED)
        sc.release_collection.get_release_by_id.return_value = r
        result = PatchController.check_releases_state(sc, ["P1"], states.AVAILABLE)
        self.assertFalse(result)


class TestDropHost(unittest.TestCase):
    """Tests for drop_host."""

    @patch('software.software_controller.PatchMessageDropHostReq')
    def test_drop_host_success(self, _mock_msg_cls):
        sc = _create_controller()
        host = MagicMock()
        sc.hosts = {"10.0.0.1": host}
        result = PatchController.drop_host(sc, "controller-0")
        self.assertIn("info", result)


class TestSoftwareDeployShowApi(unittest.TestCase):
    """Tests for software_deploy_show_api."""

    def test_no_deploy(self):
        sc = _create_controller()
        sc.db_api_instance.get_deploy_all.return_value = []
        result = PatchController.software_deploy_show_api(sc)
        self.assertEqual(result, [])

    def test_with_deploy(self):
        sc = _create_controller()
        sc.db_api_instance.get_deploy_all.return_value = [
            {"from_release": "24.09",
             "to_release": "24.09.1",
             "state": "start-done"}
        ]
        sc.db_api_instance.get_deploy_host.return_value = []
        result = PatchController.software_deploy_show_api(sc)
        self.assertEqual(len(result), 1)


class TestDeployComplete(unittest.TestCase):
    """Tests for _deploy_complete."""

    def test_all_hosts_deployed(self):
        sc = _create_controller()
        sc.db_api_instance.get_deploy_host.return_value = [
            {"state": DEPLOY_HOST_STATES.DEPLOYED.value}
        ]
        result = PatchController._deploy_complete(sc)
        self.assertTrue(result)

    def test_not_all_deployed(self):
        sc = _create_controller()
        sc.db_api_instance.get_deploy_host.return_value = [
            {"state": "deploying"}
        ]
        with self.assertRaises(SoftwareServiceError):
            PatchController._deploy_complete(sc)


class TestPatchQueryDependencies(unittest.TestCase):
    """Tests for patch_query_dependencies."""

    def test_basic(self):
        sc = _create_controller()
        r = MagicMock()
        sc.release_collection.get_release_by_id.return_value = r
        sc.get_dependencies.return_value = ["P1", "P0"]
        result = PatchController.patch_query_dependencies(sc, ["P1"])
        self.assertIn("P1", result["patches"])

    def test_unrecognized(self):
        sc = _create_controller()
        sc.release_collection.get_release_by_id.return_value = None
        result = PatchController.patch_query_dependencies(sc, ["BAD"])
        self.assertIn("unrecognized", result["error"])
