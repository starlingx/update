#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for software_controller.py
"""

import threading
import unittest
from packaging import version
from unittest.mock import MagicMock
from unittest.mock import patch

from software.tests import base  # noqa: F401
from software import states
from software.software_controller import DEPLOY_STATES
from software.software_controller import PatchController
from software.exceptions import SoftwareServiceError
from software.deploy_state import DEPLOY_HOST_STATES


class ComparableRelease:
    """A release object that supports > < ==
    comparison like SWRelease.
    """

    def __init__(self, sw_release, release_id=None, sw_version=None,
                 state=states.AVAILABLE, commit_id="abc123",
                 packages=None, requires_release_ids=None,
                 apply_active_release_only="N"):
        self.sw_release = sw_release
        self.id = release_id or f"stx-{sw_release}"
        self.sw_version = sw_version or sw_release.rsplit(
            '.', 1)[0] if sw_release.count('.') > 1 else sw_release
        self.state = state
        self.commit_id = commit_id
        self.packages = packages or []
        self.requires_release_ids = requires_release_ids or []
        self.apply_active_release_only = apply_active_release_only
        self._release = version.parse(sw_release)
        self.post_start = None
        self.pre_start = None
        self._unremovable = "N"
        self.pre_install = None
        self.has_pre_upgrade_deploy_deployed = False
        self.post_install = None
        self.component = None
        self.metapackages = {}
        self.status = "DEV"
        self.summary = "test"

    @property
    def is_deletable(self):
        return self.state in [states.AVAILABLE, states.UNAVAILABLE]

    @property
    def is_product_release(self):
        return False

    @property
    def is_metapackage_release(self):
        return False

    @property
    def is_ga_release(self):
        ver = version.parse(self.sw_release)
        return len(ver.release) <= 2 or ver.release[2] == 0

    @property
    def unremovable(self):
        return self._unremovable == "Y"

    @property
    def version_obj(self):
        return self._release

    def __gt__(self, other):
        return self.version_obj > other.version_obj

    def __lt__(self, other):
        return self.version_obj < other.version_obj

    def __eq__(self, other):
        return self.version_obj == other.version_obj

    def __ge__(self, other):
        return self.version_obj >= other.version_obj

    def __le__(self, other):
        return self.version_obj <= other.version_obj


def _make_controller():
    c = PatchController()
    c.hosts = {"10.0.0.1": MagicMock(nodetype="controller", ip="10.0.0.1",
                                     hostname="controller-0", is_alive=True)}
    c.hosts_lock = threading.RLock()
    c.interim_state = {}
    c.pre_bootstrap = False
    c.install_local = False
    c.hostname = "controller-0"
    c.sock_out = MagicMock()
    c.socket_lock = threading.RLock()
    c.db_api_instance = MagicMock()
    c._release_basic_checks = MagicMock()
    c.run_semantic_check = MagicMock()
    c.is_deployment_list_reboot_required = MagicMock(return_value=False)
    c.install_releases_thread = MagicMock()
    c.software_sync = MagicMock(return_value=True)
    c._should_run_precheck_prior_deploy_start = MagicMock(return_value=False)
    c._safe_remove_precheck_result_file = MagicMock()
    c._parse_and_sanitize_extra_options = MagicMock(return_value={})
    c.release_apply_order = MagicMock()
    c.release_remove_order = MagicMock()
    c.manage_software_alarm = MagicMock()
    c.execute_delete_actions = MagicMock()
    c.delete_all_patch_activate_scripts = MagicMock()
    c.read_state_file = MagicMock()
    c.copy_install_scripts = MagicMock()
    c.check_upgrade_in_progress = MagicMock(return_value=False)
    c._get_system_deploy = MagicMock(return_value=None)
    c.allow_insvc_patching = True
    c.app_dependencies = {}
    c.delete_start_install_script = MagicMock()
    c.delete_patch_activate_scripts = MagicMock()
    c.get_ostree_tar_filename = MagicMock(return_value="/tmp/fake.tar")
    c.base_pkgdata = MagicMock()
    return c


@patch('software.software_controller.get_SWReleaseCollection')
@patch(
    'software.software_controller.PatchController.__init__',
    return_value=None)
class TestSyncFromNbr(unittest.TestCase):
    """Tests for sync_from_nbr."""

    @patch('software.ostree_utils.constants.OSTREE_LOCK',
           '/tmp/.test_ostree_lock')
    @patch('subprocess.check_output')
    @patch('software.software_controller.reload_release_data')
    @patch('software.software_controller.SW_VERSION', '24.09')
    def test_sync_success(
            self,
            _mock_reload,
            mock_subproc,
            _mock_init,
            _mock_swrc):
        open('/tmp/.test_ostree_lock', 'w').close()
        c = _make_controller()
        c.hosts["10.0.0.1"].nodetype = "controller"
        c.hosts["10.0.0.1"].ip = "10.0.0.1"
        mock_subproc.return_value = "ok"

        with patch('os.listdir', return_value=["rel-24.09"]):
            with patch('os.path.isdir', return_value=True):
                result = c.sync_from_nbr("10.0.0.1")
        self.assertTrue(result)

    @patch('software.ostree_utils.constants.OSTREE_LOCK',
           '/tmp/.test_ostree_lock')
    @patch('subprocess.check_output',
           side_effect=__import__('subprocess').CalledProcessError(
               1, 'rsync', output="fail"))
    @patch('software.software_controller.SW_VERSION', '24.09')
    def test_sync_rsync_fail(self, _mock_subproc, _mock_init, _mock_swrc):
        open('/tmp/.test_ostree_lock', 'w').close()
        c = _make_controller()
        result = c.sync_from_nbr("10.0.0.1")
        self.assertFalse(result)


@patch('software.software_controller.get_SWReleaseCollection')
@patch(
    'software.software_controller.PatchController.__init__',
    return_value=None)
class TestDeployDeleteApi(unittest.TestCase):
    """Tests for software_deploy_delete_api."""

    @patch('software.software_controller.DeployState.get_deploy_state',
           return_value=DEPLOY_STATES.START_DONE)
    @patch('software.software_controller.reload_release_data')
    @patch('software.software_controller.run_remove_temporary_data_script')
    def test_delete_start_done_patch(self, _mock_remove, _mock_reload,
                                     _mock_get_state, _mock_init, mock_swrc):
        c = _make_controller()
        c.db_api_instance.get_current_deploy.return_value = {
            "to_release": "24.09.1", "from_release": "24.09.0"}
        c.db_api_instance.get_deploy_host.return_value = []
        rc = mock_swrc.return_value
        rc.iterate_releases.return_value = []
        rc.iterate_releases_by_state.return_value = []

        mock_deploy = MagicMock()
        mock_deploy.get_deploy_state.return_value = DEPLOY_STATES.START_DONE
        mock_rs = MagicMock()
        mock_rs.is_major_release_deployment.return_value = False
        mock_rs.get_release_ids.return_value = ["stx-24.09.1"]

        with patch(
                'software.software_controller.DeployState.get_instance',
                return_value=mock_deploy):
            with patch(
                    'software.software_controller.ReleaseState',
                    return_value=mock_rs):
                with patch(
                        'software.software_controller'
                        '.utils.get_major_release_version',
                        return_value="24.09"):
                    result = c.software_deploy_delete_api()
        self.assertEqual(result["error"], "")

    @patch('software.software_controller.DeployState.get_deploy_state',
           return_value=DEPLOY_STATES.START_FAILED)
    @patch('software.software_controller.reload_release_data')
    def test_delete_start_failed(self, _mock_reload, _mock_get_state,
                                 _mock_init, mock_swrc):
        c = _make_controller()
        c.db_api_instance.get_current_deploy.return_value = {
            "to_release": "24.09.1", "from_release": "24.09.0"}
        c.db_api_instance.get_deploy_host.return_value = []
        rc = mock_swrc.return_value
        rc.iterate_releases.return_value = []
        rc.iterate_releases_by_state.return_value = []

        mock_deploy = MagicMock()
        mock_deploy.get_deploy_state.return_value = DEPLOY_STATES.START_FAILED
        mock_rs = MagicMock()
        mock_rs.is_major_release_deployment.return_value = False
        mock_rs.get_release_ids.return_value = ["stx-24.09.1"]

        with patch(
                'software.software_controller.DeployState.get_instance',
                return_value=mock_deploy):
            with patch(
                    'software.software_controller.ReleaseState',
                    return_value=mock_rs):
                with patch(
                        'software.software_controller'
                        '.utils.get_major_release_version',
                        return_value="24.09"):
                    result = c.software_deploy_delete_api()
        self.assertEqual(result["error"], "")

    @patch('software.software_controller.DeployState.get_deploy_state',
           return_value=DEPLOY_STATES.START_DONE)
    @patch('software.software_controller.reload_release_data')
    def test_delete_start_done_hosts_deploying(
            self, _mock_reload, _mock_get_state, _mock_init, mock_swrc):
        """Test START_DONE with hosts already deploying raises error."""
        c = _make_controller()
        c.db_api_instance.get_current_deploy.return_value = {
            "to_release": "24.09.1", "from_release": "24.09.0"}
        c.db_api_instance.get_deploy_host.return_value = [
            {"state": DEPLOY_HOST_STATES.DEPLOYING.value}]
        rc = mock_swrc.return_value
        rc.iterate_releases.return_value = []
        rc.iterate_releases_by_state.return_value = []

        mock_deploy = MagicMock()
        mock_deploy.get_deploy_state.return_value = DEPLOY_STATES.START_DONE
        mock_rs = MagicMock()
        mock_rs.is_major_release_deployment.return_value = False

        with patch(
                'software.software_controller.DeployState.get_instance',
                return_value=mock_deploy):
            with patch(
                    'software.software_controller.ReleaseState',
                    return_value=mock_rs):
                with patch(
                        'software.software_controller'
                        '.utils.get_major_release_version',
                        return_value="24.09"):
                    with self.assertRaises(SoftwareServiceError):
                        c.software_deploy_delete_api()


@patch('software.software_controller.get_SWReleaseCollection')
@patch(
    'software.software_controller.PatchController.__init__',
    return_value=None)
class TestReleaseDeleteApi(unittest.TestCase):
    """Tests for software_release_delete_api."""

    @patch('software.software_controller.reload_release_data')
    @patch(
        'software.software_controller.is_system_controller',
        return_value=False)
    def test_delete_available_release(
            self,
            _mock_sc,
            _mock_reload,
            _mock_init,
            mock_swrc):
        c = _make_controller()
        c.get_ostree_tar_filename = MagicMock(return_value="/tmp/fake.tar")
        rc = mock_swrc.return_value
        rel = ComparableRelease("24.09.1", state=states.AVAILABLE)
        rc.get_release_by_id.return_value = rel
        rc.iterate_releases.return_value = []

        with patch('software.software_controller.ReleaseState') as mock_rs:
            mock_rs.return_value.is_major_release_deployment.return_value = (
                False)
            with patch('software.software_controller.PatchFile'):
                with patch('software.software_controller.apt_utils'):
                    with patch('os.path.isfile', return_value=False):
                        with patch('os.path.exists', return_value=False):
                            with patch('os.remove'):
                                with patch(
                                        'software.software_controller'
                                        '.utils.get_major_release_version',
                                        return_value="24.09"):
                                    result = c.software_release_delete_api(
                                        ["stx-24.09.1"])
        self.assertEqual(result["error"], "")

    @patch('software.software_controller.reload_release_data')
    @patch(
        'software.software_controller.is_system_controller',
        return_value=False)
    def test_delete_deployed_release_error(
            self, _mock_sc, _mock_reload, _mock_init, mock_swrc):
        c = _make_controller()
        rc = mock_swrc.return_value
        rel = ComparableRelease("24.09.1", state=states.DEPLOYED)
        rc.get_release_by_id.return_value = rel

        with self.assertRaises(SoftwareServiceError):
            c.software_release_delete_api(["stx-24.09.1"])

    @patch('software.software_controller.reload_release_data')
    @patch(
        'software.software_controller.is_system_controller',
        return_value=False)
    def test_delete_nonexistent_release(
            self, _mock_sc, _mock_reload, _mock_init, mock_swrc):
        c = _make_controller()
        rc = mock_swrc.return_value
        rc.get_release_by_id.return_value = None

        with self.assertRaises(SoftwareServiceError):
            c.software_release_delete_api(["stx-99.99.99"])
