#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for PatchController API methods."""

import shutil
import subprocess
import threading
import unittest
from unittest import mock

from software.tests import base as test_base  # noqa: F401
from software.exceptions import InvalidOperation
from software.exceptions import SoftwareError
from software.exceptions import SoftwareServiceError
from software.software_controller import PatchController
from software.states import DEPLOY_HOST_STATES
from software.states import DEPLOY_STATES
from software import constants
from software import states
from software.exceptions import MaxReleaseExceeded
from software.exceptions import UpgradeNotSupported

_SC = 'software.software_controller'


INIT_PATCH = mock.patch(
    'software.software_controller.PatchController.__init__',
    return_value=None
)


def _make_controller(**overrides):
    """Helper to create a PatchController with
    common mocked attributes.
    """
    controller = PatchController()
    controller.db_api_instance = mock.MagicMock()
    controller.hosts = {}
    controller.controller_neighbours = {}
    controller.interim_state = {}
    controller.hosts_lock = threading.RLock()
    controller.socket_lock = threading.RLock()
    controller.controller_neighbours_lock = threading.RLock()
    controller.sock_out = mock.MagicMock()
    controller.fm_api = mock.MagicMock()
    controller.patch_op_counter = 1
    controller.hostname = constants.CONTROLLER_0_HOSTNAME
    controller.allow_insvc_patching = True
    controller.app_dependencies = {}
    controller.pre_bootstrap = False
    controller.install_local = False
    controller.ignore_errors = 'False'
    controller.base_pkgdata = mock.MagicMock()
    for key, val in overrides.items():
        setattr(controller, key, val)
    return controller


class TestSoftwareDeployShowApi(unittest.TestCase):

    @INIT_PATCH
    @mock.patch('software.software_controller.get_SWReleaseCollection')
    @mock.patch('software.software_controller.SW_VERSION', '24.09')
    def test_show_with_from_to(self, mock_swrc, _init):
        c = _make_controller()
        c.db_api_instance.get_deploy.return_value = {
            "to_release": "24.09.1",
            "from_release": "24.09.0",
            "state": "start-done"}
        mock_rel = mock.MagicMock()
        mock_rel.sw_release = "24.09.1"
        mock_rel.reboot_required = True
        mock_rel.prepatched_iso = False
        mock_rel.__gt__ = mock.MagicMock(return_value=True)
        mock_col = mock.MagicMock()
        mock_col.get_release_id_by_sw_release.return_value = "stx-24.09.1"
        mock_col.get_release_by_id.return_value = mock_rel
        mock_col.running_release = mock.MagicMock()
        mock_swrc.return_value = mock_col
        result = c.software_deploy_show_api("24.09.0", "24.09.1")
        self.assertIn("to_release", result)

    @INIT_PATCH
    @mock.patch('software.software_controller.get_SWReleaseCollection')
    def test_show_no_deploy(self, _mock_swrc, _init):
        c = _make_controller()
        c.db_api_instance.get_deploy_all.return_value = []
        result = c.software_deploy_show_api()
        self.assertFalse(result)

    @INIT_PATCH
    @mock.patch('software.software_controller.get_SWReleaseCollection')
    @mock.patch('software.software_controller.SW_VERSION', '24.09')
    def test_show_list_format(self, mock_swrc, _init):
        c = _make_controller()
        c.db_api_instance.get_deploy_all.return_value = [
            {"to_release": "24.09.1",
             "from_release": "24.09.0",
             "state": "start-done"}
        ]
        mock_rel = mock.MagicMock()
        mock_rel.sw_release = "24.09.1"
        mock_rel.reboot_required = False
        mock_rel.prepatched_iso = False
        mock_rel.__gt__ = mock.MagicMock(return_value=True)
        mock_col = mock.MagicMock()
        mock_col.get_release_id_by_sw_release.return_value = "stx-24.09.1"
        mock_col.get_release_by_id.return_value = mock_rel
        mock_col.running_release = mock.MagicMock()
        mock_swrc.return_value = mock_col
        result = c.software_deploy_show_api()
        self.assertIsInstance(result, list)
        self.assertIn("major_release", result[0])


class TestSoftwareDeployCompleteApi(unittest.TestCase):

    @INIT_PATCH
    @mock.patch('software.software_controller.trigger_evaluate_apps_reapply')
    @mock.patch('software.deploy_state.DeployState.get_deploy_state',
                return_value=DEPLOY_STATES.ACTIVATE_DONE)
    def test_complete_success(self, _get_state, _mock_trigger, _init):
        c = _make_controller()
        c.db_api_instance.get_deploy_host.return_value = [
            {"state": DEPLOY_HOST_STATES.DEPLOYED.value}
        ]
        mock_ds = mock.MagicMock()
        mock.patch(
            'software.deploy_state.DeployState.get_instance',
            return_value=mock_ds).start()
        result = c.software_deploy_complete_api()
        self.assertIn("Deployment has been completed", result["info"])
        mock_ds.completed.assert_called_once()

    @INIT_PATCH
    @mock.patch('software.deploy_state.DeployState.get_deploy_state',
                return_value=DEPLOY_STATES.ACTIVATE_DONE)
    def test_complete_hosts_not_deployed(self, _get_state, _init):
        c = _make_controller()
        c.db_api_instance.get_deploy_host.return_value = [
            {"state": DEPLOY_HOST_STATES.PENDING.value}
        ]
        mock.patch(
            'software.deploy_state.DeployState.get_instance',
            return_value=mock.MagicMock()).start()
        with self.assertRaises(SoftwareServiceError):
            c.software_deploy_complete_api()

    @INIT_PATCH
    @mock.patch('software.deploy_state.DeployState.get_deploy_state',
                return_value=DEPLOY_STATES.START_DONE)
    def test_complete_wrong_state(self, _get_state, _init):
        c = _make_controller()
        with self.assertRaises(InvalidOperation):
            c.software_deploy_complete_api()

    @INIT_PATCH
    @mock.patch('software.software_controller.trigger_evaluate_apps_reapply',
                side_effect=Exception("vim error"))
    @mock.patch('software.deploy_state.DeployState.get_deploy_state',
                return_value=DEPLOY_STATES.ACTIVATE_DONE)
    def test_complete_trigger_failure_still_completes(self, _get_state,
                                                      _mock_trigger, _init):
        c = _make_controller()
        c.db_api_instance.get_deploy_host.return_value = [
            {"state": DEPLOY_HOST_STATES.DEPLOYED.value}
        ]
        mock_ds = mock.MagicMock()
        mock.patch(
            'software.deploy_state.DeployState.get_instance',
            return_value=mock_ds).start()
        result = c.software_deploy_complete_api()
        self.assertIn("Deployment has been completed", result["info"])


class TestSoftwareDeployActivateApi(unittest.TestCase):

    @INIT_PATCH
    @mock.patch('software.deploy_state.DeployState.get_instance')
    @mock.patch(
        _SC + '.are_all_hosts_unlocked_and_online',
        return_value=True)
    @mock.patch('software.deploy_state.DeployState.get_deploy_state',
                return_value=DEPLOY_STATES.HOST_DONE)
    def test_activate_success(
            self,
            _get_state,
            _hosts_ok,
            mock_get_inst,
            _init):
        c = _make_controller()
        c.db_api_instance.get_deploy_host.return_value = [
            {"state": states.DEPLOYED}
        ]
        mock_ds = mock.MagicMock()
        mock_get_inst.return_value = mock_ds
        with mock.patch.object(c, '_activate', return_value=True):
            result = c.software_deploy_activate_api()
        self.assertIn("Deploy activate has started", result["info"])
        mock_ds.activate.assert_called_once()

    @INIT_PATCH
    @mock.patch('software.deploy_state.DeployState.get_deploy_state',
                return_value=DEPLOY_STATES.START_DONE)
    def test_activate_wrong_state(self, _get_state, _init):
        c = _make_controller()
        with self.assertRaises(InvalidOperation):
            c.software_deploy_activate_api()

    @INIT_PATCH
    @mock.patch(
        _SC + '.are_all_hosts_unlocked_and_online',
        return_value=False)
    @mock.patch('software.deploy_state.DeployState.get_deploy_state',
                return_value=DEPLOY_STATES.HOST_DONE)
    def test_activate_hosts_not_online(self, _get_state, _hosts, _init):
        c = _make_controller()
        with self.assertRaises(SoftwareServiceError):
            c.software_deploy_activate_api()

    @INIT_PATCH
    @mock.patch('software.deploy_state.DeployState.get_instance')
    @mock.patch(
        _SC + '.are_all_hosts_unlocked_and_online',
        return_value=True)
    @mock.patch('software.deploy_state.DeployState.get_deploy_state',
                return_value=DEPLOY_STATES.HOST_DONE)
    def test_activate_exception_sets_failed(
            self, _get_state, _hosts, mock_get_inst, _init):
        c = _make_controller()
        c.db_api_instance.get_deploy_all.return_value = [
            {"from_release": "24.09.0", "to_release": "24.09.1"}
        ]
        c.db_api_instance.get_deploy_host.return_value = [
            {"state": states.DEPLOYED}
        ]
        mock_ds = mock.MagicMock()
        mock_get_inst.return_value = mock_ds
        with mock.patch.object(
                c, '_activate',
                side_effect=SoftwareError("fail")):
            with self.assertRaises(SoftwareError):
                c.software_deploy_activate_api()
        mock_ds.activate_failed.assert_called_once()


class TestSoftwareDeployAbortApi(unittest.TestCase):

    @mock.patch('software.deploy_state.DeployState.get_deploy_state',
                return_value=DEPLOY_STATES.HOST_DONE)
    @INIT_PATCH
    @mock.patch('software.software_controller.ostree_utils')
    @mock.patch('software.software_controller.DeployHostState')
    @mock.patch('software.software_controller.ReleaseState')
    @mock.patch('software.software_controller.get_SWReleaseCollection')
    def test_abort_major_release(self, _get_state, mock_swrc, mock_rs,
                                 _mock_dhs, _mock_ostree, _init):
        c = _make_controller()
        mock_ds = mock.MagicMock()
        mock.patch(
            'software.deploy_state.DeployState.get_instance',
            return_value=mock_ds).start()
        c.db_api_instance.get_current_deploy.return_value = {
            "from_release": "24.09.0", "to_release": "25.03.0"
        }
        c.db_api_instance.get_deploy_host.return_value = [
            {"hostname": "controller-0"}
        ]
        mock_rel = mock.MagicMock()
        mock_rel.commit_id = "abc123"
        mock_col = mock.MagicMock()
        mock_col.get_release_id_by_sw_release.return_value = "stx-24.09.0"
        mock_col.get_release_by_id.return_value = mock_rel
        mock_swrc.return_value = mock_col
        mock_rs_inst = mock.MagicMock()
        mock_rs_inst.is_major_release_deployment.return_value = True
        mock_rs.return_value = mock_rs_inst
        result = c.software_deploy_abort_api()
        self.assertIn("aborted", result["info"])
        mock_ds.abort.assert_called_once()

    @mock.patch('software.deploy_state.DeployState.get_deploy_state',
                return_value=DEPLOY_STATES.START_DONE)
    @INIT_PATCH
    def test_abort_wrong_state(self, _get_state, _init):
        c = _make_controller()
        with self.assertRaises(InvalidOperation):
            c.software_deploy_abort_api()

    @mock.patch('software.deploy_state.DeployState.get_deploy_state',
                return_value=DEPLOY_STATES.HOST_DONE)
    @INIT_PATCH
    @mock.patch('software.software_controller.ostree_utils')
    @mock.patch('software.software_controller.DeployHostState')
    @mock.patch('software.software_controller.ReleaseState')
    @mock.patch('software.software_controller.get_SWReleaseCollection')
    def test_abort_patch_release(self, _get_state, mock_swrc, mock_rs,
                                 _mock_dhs, _mock_ostree, _init):
        c = _make_controller()
        mock_ds = mock.MagicMock()
        mock.patch(
            'software.deploy_state.DeployState.get_instance',
            return_value=mock_ds).start()
        c.db_api_instance.get_current_deploy.return_value = {
            "from_release": "24.09.0", "to_release": "24.09.1"
        }
        c.db_api_instance.get_deploy_host.return_value = []
        mock_rel = mock.MagicMock()
        mock_rel.commit_id = "abc123"
        mock_col = mock.MagicMock()
        mock_col.get_release_id_by_sw_release.return_value = "stx-24.09.0"
        mock_col.get_release_by_id.return_value = mock_rel
        mock_swrc.return_value = mock_col
        mock_rs_inst = mock.MagicMock()
        mock_rs_inst.is_major_release_deployment.return_value = False
        mock_rs_inst.has_release_id.return_value = False
        mock_rs.return_value = mock_rs_inst
        with mock.patch.object(c, 'reset_feed_commit'):
            with mock.patch.object(c, 'send_latest_feed_commit_to_agent'):
                with mock.patch.object(c, 'software_sync'):
                    result = c.software_deploy_abort_api()
        self.assertIn("aborted", result["info"])


class TestSoftwareDeployDeleteApi(unittest.TestCase):

    @mock.patch('software.deploy_state.DeployState.get_deploy_state',
                return_value=DEPLOY_STATES.START_DONE)
    @INIT_PATCH
    @mock.patch('software.software_controller.DeployPluginRunner')
    @mock.patch('software.software_controller.ReleaseState')
    @mock.patch('software.software_controller.get_SWReleaseCollection')
    @mock.patch('os.path.isfile', return_value=False)
    @mock.patch('software.software_controller.utils.get_software_deploy_script',
                return_value=[])
    def test_delete_start_done_patch(self, _get_state, _isfile, mock_swrc,
                                     mock_rs, _mock_plugin, _script, _init):
        c = _make_controller()
        mock_ds = mock.MagicMock()
        mock_ds.get_deploy_state.return_value = DEPLOY_STATES.START_DONE
        mock.patch(
            'software.deploy_state.DeployState.get_instance',
            return_value=mock_ds).start()
        c.db_api_instance.get_current_deploy.return_value = {
            "from_release": "24.09.0", "to_release": "24.09.1"
        }
        c.db_api_instance.get_deploy_host.return_value = [
            {"state": DEPLOY_HOST_STATES.PENDING.value}
        ]
        mock_rs_inst = mock.MagicMock()
        mock_rs_inst.is_major_release_deployment.return_value = False
        mock_rs_inst.has_release_id.return_value = True
        mock_rs_inst.get_release_ids.return_value = ["stx-24.09.1"]
        mock_rs.return_value = mock_rs_inst
        mock_rel = mock.MagicMock()
        mock_rel.sw_release = "24.09.0"
        mock_col = mock.MagicMock()
        mock_col.get_release_by_id.return_value = mock_rel
        mock_col.iterate_releases.return_value = []
        mock_swrc.return_value = mock_col
        with mock.patch.object(c, 'reset_feed_commit'):
            with mock.patch.object(c, 'remove_tags_from_metadata'):
                with mock.patch.object(c, 'delete_all_patch_activate_scripts'):
                    result = c.software_deploy_delete_api()
        self.assertIn("Deploy deleted with success", result["info"])
        c.db_api_instance.delete_deploy.assert_called_once()

    @mock.patch('software.deploy_state.DeployState.get_deploy_state',
                return_value=DEPLOY_STATES.HOST_DONE)
    @INIT_PATCH
    def test_delete_wrong_state(self, _get_state, _init):
        c = _make_controller()
        with self.assertRaises(InvalidOperation):
            c.software_deploy_delete_api()

    @mock.patch('software.deploy_state.DeployState.get_deploy_state',
                return_value=DEPLOY_STATES.START_DONE)
    @INIT_PATCH
    @mock.patch('software.software_controller.ReleaseState')
    @mock.patch('software.software_controller.get_SWReleaseCollection')
    @mock.patch('os.path.isfile', return_value=False)
    def test_delete_hosts_deployed_raises(self, _get_state, _isfile, mock_swrc,
                                          mock_rs, _init):
        c = _make_controller()
        mock_ds = mock.MagicMock()
        mock_ds.get_deploy_state.return_value = DEPLOY_STATES.START_DONE
        mock.patch(
            'software.deploy_state.DeployState.get_instance',
            return_value=mock_ds).start()
        c.db_api_instance.get_current_deploy.return_value = {
            "from_release": "24.09.0", "to_release": "24.09.1"
        }
        c.db_api_instance.get_deploy_host.return_value = [
            {"state": DEPLOY_HOST_STATES.DEPLOYED.value}
        ]
        mock_rs_inst = mock.MagicMock()
        mock_rs_inst.is_major_release_deployment.return_value = False
        mock_rs_inst.has_release_id.return_value = True
        mock_rs.return_value = mock_rs_inst
        mock_swrc.return_value = mock.MagicMock()
        with self.assertRaises(SoftwareServiceError):
            c.software_deploy_delete_api()


class TestSoftwareDeployHostApi(unittest.TestCase):

    @mock.patch('software.deploy_state.DeployState.get_deploy_state',
                return_value=DEPLOY_STATES.ACTIVATE_DONE)
    @INIT_PATCH
    def test_deploy_host_wrong_state(self, _get_state, _init):
        c = _make_controller()
        with self.assertRaises(InvalidOperation):
            c.software_deploy_host_api("controller-0", False)

    @mock.patch('software.deploy_state.DeployState.get_deploy_state',
                return_value=DEPLOY_STATES.START_DONE)
    @INIT_PATCH
    def test_deploy_host_calls_deploy_host(self, _get_state, _init):
        c = _make_controller()
        with mock.patch.object(
                c, '_deploy_host',
                return_value={"info": "ok",
                              "warning": "",
                              "error": ""}) as m:
            result = c.software_deploy_host_api("controller-0", False)
        m.assert_called_once_with("controller-0", False, False)
        self.assertEqual(result["info"], "ok")

    @mock.patch('software.deploy_state.DeployState.get_deploy_state',
                return_value=DEPLOY_STATES.HOST_FAILED)
    @INIT_PATCH
    def test_deploy_host_from_host_failed(self, _get_state, _init):
        c = _make_controller()
        with mock.patch.object(
                c, '_deploy_host',
                return_value={"info": "ok",
                              "warning": "",
                              "error": ""}):
            result = c.software_deploy_host_api("controller-0", True)
        self.assertEqual(result["info"], "ok")


class TestSoftwareDeployHostRollbackApi(unittest.TestCase):

    @mock.patch('software.deploy_state.DeployState.get_deploy_state',
                return_value=DEPLOY_STATES.START_DONE)
    @INIT_PATCH
    def test_rollback_host_wrong_state(self, _get_state, _init):
        c = _make_controller()
        with self.assertRaises(InvalidOperation):
            c.software_deploy_host_rollback_api("controller-0", False)

    @mock.patch('software.deploy_state.DeployState.get_deploy_state',
                return_value=DEPLOY_STATES.HOST_ROLLBACK_FAILED)
    @INIT_PATCH
    def test_rollback_host_from_failed(self, _get_state, _init):
        c = _make_controller()
        with mock.patch.object(
                c, '_deploy_host',
                return_value={"info": "ok",
                              "warning": "",
                              "error": ""}):
            result = c.software_deploy_host_rollback_api("controller-0", False)
        self.assertEqual(result["info"], "ok")


class TestDeployPrecheck(unittest.TestCase):

    @INIT_PATCH
    @mock.patch('software.software_controller.subprocess.run')
    @mock.patch('software.software_controller.configparser.ConfigParser')
    @mock.patch('os.path.isfile', return_value=True)
    @mock.patch('software.software_controller.get_SWReleaseCollection')
    def test_precheck_success(
            self,
            mock_swrc,
            _isfile,
            mock_cp,
            mock_run,
            _init):
        c = _make_controller()
        mock_col = mock.MagicMock()
        mock_col.iterate_releases.return_value = []
        mock_swrc.return_value = mock_col
        cp_inst = mock.MagicMock()
        cp_inst.has_section.return_value = True
        cp_inst.__getitem__ = mock.MagicMock(return_value={
            "auth_url": "http://auth", "username": "admin",
            "password": "pass", "project_name": "admin",
            "user_domain_name": "Default", "project_domain_name": "Default"
        })
        mock_cp.return_value = cp_inst
        mock_run.return_value = mock.MagicMock(
            returncode=constants.RC_SUCCESS, stdout="System is healthy\n"
        )
        with mock.patch.object(c, '_save_precheck_result'):
            with mock.patch.object(
                    c, '_get_software_upgrade',
                    return_value=None):
                result = c._deploy_precheck("24.09.1")
        self.assertTrue(result["system_healthy"])

    @INIT_PATCH
    @mock.patch('os.path.isfile', return_value=False)
    def test_precheck_no_script_patch(self, _isfile, _init):
        c = _make_controller()
        c.pre_bootstrap = False
        with mock.patch.object(c, '_save_precheck_result'):
            result = c._deploy_precheck("24.09.1", patch=True)
        self.assertTrue(result["system_healthy"])
        self.assertIn("No deploy-precheck script", result["info"])

    @INIT_PATCH
    @mock.patch('os.path.isfile', return_value=False)
    def test_precheck_no_script_major(self, _isfile, _init):
        c = _make_controller()
        c.pre_bootstrap = False
        with mock.patch.object(c, '_save_precheck_result'):
            result = c._deploy_precheck("25.03.0")
        self.assertIn("error", result)
        self.assertIn("Fail to perform deploy precheck", result["error"])

    @INIT_PATCH
    @mock.patch('os.path.isfile', return_value=True)
    def test_precheck_pre_bootstrap_major(self, _isfile, _init):
        c = _make_controller()
        c.pre_bootstrap = True
        with mock.patch.object(c, '_save_precheck_result'):
            result = c._deploy_precheck("25.03.0")
        self.assertTrue(result["system_healthy"])

    @INIT_PATCH
    @mock.patch('software.software_controller.subprocess.run')
    @mock.patch('software.software_controller.configparser.ConfigParser')
    @mock.patch('os.path.isfile', return_value=True)
    @mock.patch('software.software_controller.get_SWReleaseCollection')
    def test_precheck_unhealthy(
            self,
            mock_swrc,
            _isfile,
            mock_cp,
            mock_run,
            _init):
        c = _make_controller()
        mock_col = mock.MagicMock()
        mock_col.iterate_releases.return_value = []
        mock_swrc.return_value = mock_col
        cp_inst = mock.MagicMock()
        cp_inst.has_section.return_value = True
        cp_inst.__getitem__ = mock.MagicMock(return_value={
            "auth_url": "http://auth", "username": "admin",
            "password": "pass", "project_name": "admin",
            "user_domain_name": "Default", "project_domain_name": "Default"
        })
        mock_cp.return_value = cp_inst
        mock_run.return_value = mock.MagicMock(
            returncode=constants.RC_UNHEALTHY, stdout="Alarms found\n"
        )
        with mock.patch.object(c, '_save_precheck_result'):
            with mock.patch.object(
                    c, '_get_software_upgrade',
                    return_value=None):
                result = c._deploy_precheck("24.09.1")
        self.assertFalse(result["system_healthy"])


class TestSoftwareDeployStartApi(unittest.TestCase):

    @mock.patch('software.deploy_state.DeployState.get_deploy_state',
                return_value=DEPLOY_STATES.HOST_DONE)
    @INIT_PATCH
    def test_start_wrong_state(self, _get_state, _init):
        c = _make_controller()
        with self.assertRaises(InvalidOperation):
            c.software_deploy_start_api("stx-24.09.1", False)


class TestDeployComplete(unittest.TestCase):

    @INIT_PATCH
    def test_all_hosts_deployed(self, _init):
        c = _make_controller()
        c.db_api_instance.get_deploy_host.return_value = [
            {"state": DEPLOY_HOST_STATES.DEPLOYED.value},
            {"state": DEPLOY_HOST_STATES.DEPLOYED.value}
        ]
        self.assertTrue(c._deploy_complete())

    @INIT_PATCH
    def test_not_all_hosts_deployed(self, _init):
        c = _make_controller()
        c.db_api_instance.get_deploy_host.return_value = [
            {"state": DEPLOY_HOST_STATES.DEPLOYED.value},
            {"state": DEPLOY_HOST_STATES.PENDING.value}
        ]
        with self.assertRaises(SoftwareServiceError):
            c._deploy_complete()

    @INIT_PATCH
    def test_empty_hosts(self, _init):
        c = _make_controller()
        c.db_api_instance.get_deploy_host.return_value = []
        self.assertTrue(c._deploy_complete())


class TestActivate(unittest.TestCase):

    @INIT_PATCH
    @mock.patch('software.software_controller.subprocess.Popen')
    @mock.patch('software.software_controller.ReleaseState')
    @mock.patch('software.software_controller.utils.get_endpoints_token',
                return_value=("token", "http://endpoint/v1"))
    @mock.patch('os.environ.copy', return_value={})
    def test_activate_success(self, _env, _token, mock_rs, mock_popen, _init):
        c = _make_controller()
        c.pre_bootstrap = False
        c.db_api_instance.get_deploy_all.return_value = [
            {"from_release": "24.09.0", "to_release": "24.09.1"}
        ]
        mock_rs_inst = mock.MagicMock()
        mock_rs_inst.is_major_release_deployment.return_value = False
        mock_rs.return_value = mock_rs_inst
        result = c._activate()
        self.assertTrue(result)
        mock_popen.assert_called_once()

    @INIT_PATCH
    def test_activate_no_deploy(self, _init):
        c = _make_controller()
        c.db_api_instance.get_deploy_all.return_value = []
        with self.assertRaises(InvalidOperation):
            c._activate()

    @INIT_PATCH
    @mock.patch('software.software_controller.subprocess.Popen',
                side_effect=subprocess.SubprocessError("fail"))
    @mock.patch('software.software_controller.ReleaseState')
    @mock.patch('software.software_controller.utils.get_endpoints_token',
                return_value=("token", "http://endpoint/v1"))
    @mock.patch('os.environ.copy', return_value={})
    def test_activate_popen_fails(self, _env, _token, mock_rs, _popen, _init):
        c = _make_controller()
        c.pre_bootstrap = False
        c.db_api_instance.get_deploy_all.return_value = [
            {"from_release": "24.09.0", "to_release": "24.09.1"}
        ]
        mock_rs_inst = mock.MagicMock()
        mock_rs_inst.is_major_release_deployment.return_value = False
        mock_rs.return_value = mock_rs_inst
        result = c._activate()
        self.assertFalse(result)

    @INIT_PATCH
    @mock.patch('software.software_controller.subprocess.Popen')
    @mock.patch('software.software_controller.ReleaseState')
    def test_activate_pre_bootstrap(self, mock_rs, _mock_popen, _init):
        c = _make_controller()
        c.pre_bootstrap = True
        c.db_api_instance.get_deploy_all.return_value = [
            {"from_release": "24.09.0", "to_release": "24.09.1"}
        ]
        mock_rs_inst = mock.MagicMock()
        mock_rs_inst.is_major_release_deployment.return_value = False
        mock_rs.return_value = mock_rs_inst
        result = c._activate()
        self.assertTrue(result)


class TestCheckPreActivate(unittest.TestCase):

    @INIT_PATCH
    @mock.patch(
        _SC + '.are_all_hosts_unlocked_and_online',
        return_value=False)
    def test_pre_activate_hosts_not_online(self, _hosts, _init):
        c = _make_controller()
        with self.assertRaises(SoftwareServiceError):
            c._check_pre_activate()

    @INIT_PATCH
    @mock.patch(
        _SC + '.are_all_hosts_unlocked_and_online',
        return_value=True)
    @mock.patch('software.deploy_state.DeployState.get_deploy_state',
                return_value=DEPLOY_STATES.START_DONE)
    def test_pre_activate_wrong_state(self, _get_state, _hosts, _init):
        c = _make_controller()
        with self.assertRaises(InvalidOperation):
            c._check_pre_activate()

    @INIT_PATCH
    @mock.patch(
        _SC + '.are_all_hosts_unlocked_and_online',
        return_value=True)
    @mock.patch('software.deploy_state.DeployState.get_deploy_state',
                return_value=DEPLOY_STATES.HOST_DONE)
    def test_pre_activate_invalid_hosts(self, _get_state, _hosts, _init):
        c = _make_controller()
        c.db_api_instance.get_deploy_host.return_value = [
            {"state": DEPLOY_HOST_STATES.PENDING.value, "hostname": "worker-0"}
        ]
        with self.assertRaises(InvalidOperation):
            c._check_pre_activate()


class TestActivateRollback(unittest.TestCase):

    @INIT_PATCH
    def test_rollback_no_deploy(self, _init):
        c = _make_controller()
        c.db_api_instance.get_current_deploy.return_value = None
        with self.assertRaises(InvalidOperation):
            c._activate_rollback()


class TestExecuteDeleteActions(unittest.TestCase):

    @INIT_PATCH
    @mock.patch('software.software_controller.DeployPluginRunner')
    def test_execute_delete_actions(self, mock_runner_cls, _init):
        c = _make_controller()
        c.db_api_instance.get_current_deploy.return_value = {
            "from_release": "24.09.0", "to_release": "25.03.0"
        }
        mock_runner = mock.MagicMock()
        mock_runner_cls.return_value = mock_runner
        c.execute_delete_actions(["stx-25.03.0"])
        mock_runner.execute.assert_called_once()
        call_arg = mock_runner.execute.call_args[0][0]
        self.assertIn("software-deploy-action", call_arg)
        self.assertIn("24.09.0", call_arg)
        self.assertIn("25.03.0", call_arg)

    @INIT_PATCH
    @mock.patch('software.software_controller.DeployPluginRunner')
    def test_execute_delete_actions_includes_major_flag(
            self, mock_runner_cls, _init):
        c = _make_controller()
        c.db_api_instance.get_current_deploy.return_value = {
            "from_release": "24.09.0", "to_release": "25.03.0"
        }
        mock_runner = mock.MagicMock()
        mock_runner_cls.return_value = mock_runner
        c.execute_delete_actions(["stx-25.03.0"])
        call_arg = mock_runner.execute.call_args[0][0]
        self.assertIn("--is_major_release", call_arg)


class TestInstallReleases(unittest.TestCase):

    @INIT_PATCH
    @mock.patch('software.software_controller.get_SWReleaseCollection')
    def test_install_releases_no_hosts(self, mock_swrc, _init):
        c = _make_controller()
        c.hosts = {}
        mock_rel = mock.MagicMock()
        mock_rel.sw_version = "24.09"
        mock_rel.sw_release = "24.09.1"
        mock_rel.commit_id = None
        mock_rel.packages = ["pkg1_1.0"]
        mock_rel.activation_scripts = []
        mock_rel.pre_start = None
        mock_rel.post_start = None
        mock_rel.state = states.AVAILABLE
        mock_col = mock.MagicMock()
        mock_col.get_release_by_id.return_value = mock_rel
        mock_swrc.return_value = mock_col
        with mock.patch('software.software_controller.'
                        'ostree_utils') as mock_ostree:
            mock_ostree.get_all_feed_commits.return_value = ["commit_old"]
            mock_ostree.get_feed_latest_commit.return_value = "commit_new"
            with mock.patch('software.software_controller.apt_utils'):
                with mock.patch(
                        _SC + '.reload_release_data'):
                    with mock.patch('xml.etree.ElementTree.parse'):
                        with self.assertRaises(SoftwareError):
                            c.install_releases(["stx-24.09.1"], "/feed/repo")


class TestRunStartScript(unittest.TestCase):

    @INIT_PATCH
    @mock.patch('software.software_controller.subprocess.check_output',
                side_effect=subprocess.CalledProcessError(
                    1, "cmd", output="err"))
    @mock.patch('os.path.isfile', return_value=True)
    def test_run_script_failure(self, _isfile, _check, _init):
        c = _make_controller()
        with self.assertRaises(SoftwareError):
            c._run_start_script("pre_start.sh", "stx-24.09.1", constants.APPLY)


class TestCopyPatchActivateScripts(unittest.TestCase):

    @INIT_PATCH
    @mock.patch('os.listdir', return_value=[])
    @mock.patch('shutil.copyfile', side_effect=shutil.Error("fail"))
    def test_copy_failure(self, _copy, _listdir, _init):
        c = _make_controller()
        with self.assertRaises(SoftwareError):
            c.copy_patch_activate_scripts("stx-24.09.1", ["activate.sh"])

        # no error expected


class TestDeleteAllPatchActivateScripts(unittest.TestCase):

    @INIT_PATCH
    @mock.patch('os.remove')
    @mock.patch('os.listdir', return_value=["script1.sh", "script2.sh"])
    @mock.patch('os.path.exists', return_value=True)
    @mock.patch('os.path.join', side_effect=lambda *a: "/".join(a))
    def test_delete_all(self, _join, _exists, _listdir, mock_remove, _init):
        c = _make_controller()
        c.delete_all_patch_activate_scripts()
        self.assertEqual(mock_remove.call_count, 2)


class TestGetReleaseAdditionalInfo(unittest.TestCase):

    @INIT_PATCH
    @mock.patch('software.software_controller.get_SWReleaseCollection')
    @mock.patch('software.software_controller.SW_VERSION', '24.09')
    def test_patch_release_info(self, mock_swrc, _init):
        c = _make_controller()
        mock_rel = mock.MagicMock()
        mock_rel.sw_release = "24.09.1"
        mock_rel.reboot_required = True
        mock_rel.prepatched_iso = False
        mock_rel.__gt__ = mock.MagicMock(return_value=True)
        mock_running = mock.MagicMock()
        mock_col = mock.MagicMock()
        mock_col.running_release = mock_running
        mock_swrc.return_value = mock_col
        result = c._get_release_additional_info(mock_rel)
        self.assertFalse(result["major_release"])
        self.assertTrue(result["reboot_required"])
        self.assertFalse(result["prepatched_iso"])
        self.assertTrue(result["apply_operation"])

    @INIT_PATCH
    @mock.patch('software.software_controller.get_SWReleaseCollection')
    @mock.patch('software.software_controller.SW_VERSION', '24.09')
    def test_major_release_info(self, mock_swrc, _init):
        c = _make_controller()
        mock_rel = mock.MagicMock()
        mock_rel.sw_release = "25.03.0"
        mock_rel.reboot_required = True
        mock_rel.prepatched_iso = False
        mock_rel.__gt__ = mock.MagicMock(return_value=True)
        mock_running = mock.MagicMock()
        mock_col = mock.MagicMock()
        mock_col.running_release = mock_running
        mock_swrc.return_value = mock_col
        result = c._get_release_additional_info(mock_rel)
        self.assertTrue(result["major_release"])

    @INIT_PATCH
    @mock.patch('software.software_controller.get_SWReleaseCollection')
    @mock.patch('software.software_controller.SW_VERSION', '24.09')
    def test_remove_operation(self, mock_swrc, _init):
        c = _make_controller()
        mock_rel = mock.MagicMock()
        mock_rel.sw_release = "24.09.0"
        mock_rel.reboot_required = False
        mock_rel.prepatched_iso = True
        mock_rel.__gt__ = mock.MagicMock(return_value=False)
        mock_running = mock.MagicMock()
        mock_col = mock.MagicMock()
        mock_col.running_release = mock_running
        mock_swrc.return_value = mock_col
        result = c._get_release_additional_info(mock_rel)
        self.assertFalse(result["apply_operation"])
        self.assertTrue(result["prepatched_iso"])


class TestGetSystemDeploy(unittest.TestCase):

    @INIT_PATCH
    def test_returns_system_deploy(self, _init):
        c = _make_controller()
        c.db_api_instance.get_system_deploy.return_value = {
            "id": "default", "to_release": "stx-24.09.1"
        }
        result = c._get_system_deploy()
        self.assertEqual(result["to_release"], "stx-24.09.1")

    @INIT_PATCH
    def test_returns_none(self, _init):
        c = _make_controller()
        c.db_api_instance.get_system_deploy.return_value = None
        self.assertIsNone(c._get_system_deploy())


class TestIsHostNextToBeDeployedApi(unittest.TestCase):

    @mock.patch('software.deploy_state.DeployState.get_deploy_state',
                return_value=DEPLOY_STATES.HOST)
    @INIT_PATCH
    @mock.patch('software.software_controller.validate_host_deploy_order')
    @mock.patch('software.software_controller.ReleaseState')
    def test_host_is_next(self, _get_state, mock_rs, _mock_validate, _init):
        c = _make_controller()
        mock_rs_inst = mock.MagicMock()
        mock_rs_inst.is_major_release_deployment.return_value = False
        mock_rs.return_value = mock_rs_inst
        result = c.is_host_next_to_be_deployed_api("controller-0")
        self.assertTrue(result)

    @INIT_PATCH
    @mock.patch('software.software_controller.validate_host_deploy_order',
                side_effect=SoftwareServiceError("not next"))
    @mock.patch('software.deploy_state.DeployState.get_deploy_state',
                return_value=DEPLOY_STATES.HOST)
    @mock.patch('software.software_controller.ReleaseState')
    def test_host_not_next(self, _get_state, mock_rs, _validate, _init):
        c = _make_controller()
        mock_rs_inst = mock.MagicMock()
        mock_rs_inst.is_major_release_deployment.return_value = False
        mock_rs.return_value = mock_rs_inst
        result = c.is_host_next_to_be_deployed_api("worker-0")
        self.assertFalse(result)

    @mock.patch('software.deploy_state.DeployState.get_deploy_state',
                return_value=None)
    @INIT_PATCH
    @mock.patch('software.software_controller.ReleaseState')
    def test_no_deploy_in_progress(self, _get_state, mock_rs, _init):
        c = _make_controller()
        mock_rs_inst = mock.MagicMock()
        mock_rs.return_value = mock_rs_inst
        result = c.is_host_next_to_be_deployed_api("controller-0")
        self.assertFalse(result)

    @INIT_PATCH
    @mock.patch('software.software_controller.validate_host_deploy_order',
                side_effect=Exception("unexpected"))
    @mock.patch('software.deploy_state.DeployState.get_deploy_state',
                return_value=DEPLOY_STATES.HOST)
    @mock.patch('software.software_controller.ReleaseState')
    def test_unexpected_error(self, _get_state, mock_rs, _validate, _init):
        c = _make_controller()
        mock_rs_inst = mock.MagicMock()
        mock_rs_inst.is_major_release_deployment.return_value = False
        mock_rs.return_value = mock_rs_inst
        result = c.is_host_next_to_be_deployed_api("controller-0")
        self.assertFalse(result)

    @mock.patch('software.deploy_state.DeployState.get_deploy_state',
                return_value=DEPLOY_STATES.HOST_ROLLBACK)
    @INIT_PATCH
    @mock.patch('software.software_controller.validate_host_deploy_order')
    @mock.patch('software.software_controller.ReleaseState')
    def test_rollback_state(self, _get_state, mock_rs, _mock_validate, _init):
        c = _make_controller()
        mock_rs_inst = mock.MagicMock()
        mock_rs_inst.is_major_release_deployment.return_value = True
        mock_rs.return_value = mock_rs_inst
        result = c.is_host_next_to_be_deployed_api("controller-0")
        self.assertTrue(result)


class TestCheckUpgradeInProgress(unittest.TestCase):

    @INIT_PATCH
    def test_major_upgrade_in_progress(self, _init):
        c = _make_controller()
        c.db_api_instance.get_deploy_all.return_value = [
            {"from_release": "24.09.0",
             "to_release": "25.03.0",
             "state": "start-done"}
        ]
        self.assertTrue(c.check_upgrade_in_progress())

    @INIT_PATCH
    def test_patch_not_upgrade(self, _init):
        c = _make_controller()
        c.db_api_instance.get_deploy_all.return_value = [
            {"from_release": "24.09.0",
             "to_release": "24.09.1",
             "state": "start-done"}
        ]
        self.assertFalse(c.check_upgrade_in_progress())

    @INIT_PATCH
    def test_no_deploy(self, _init):
        c = _make_controller()
        c.db_api_instance.get_deploy_all.return_value = []
        self.assertFalse(c.check_upgrade_in_progress())

    @INIT_PATCH
    def test_minor_version_change(self, _init):
        c = _make_controller()
        c.db_api_instance.get_deploy_all.return_value = [
            {"from_release": "24.09.0",
             "to_release": "24.12.0",
             "state": "start-done"}
        ]
        self.assertTrue(c.check_upgrade_in_progress())


class TestMajorReleaseUploadCheck(unittest.TestCase):

    @INIT_PATCH
    @mock.patch('socket.gethostname', return_value="controller-1")
    def test_upload_check_wrong_host(self, _hostname, _init):
        c = _make_controller()
        with self.assertRaises(SoftwareServiceError):
            c.major_release_upload_check()

    @INIT_PATCH
    @mock.patch('socket.gethostname',
                return_value=constants.CONTROLLER_0_HOSTNAME)
    @mock.patch('software.software_controller.is_system_controller',
                return_value=False)
    @mock.patch('software.software_controller.get_SWReleaseCollection')
    def test_upload_check_max_exceeded(
            self, mock_swrc, _is_sc, _hostname, _init):
        c = _make_controller()
        rel1 = mock.MagicMock()
        rel1.sw_version = "24.09"
        rel2 = mock.MagicMock()
        rel2.sw_version = "25.03"
        rel3 = mock.MagicMock()
        rel3.sw_version = "25.09"
        mock_col = mock.MagicMock()
        mock_col.iterate_releases.return_value = [rel1, rel2, rel3]
        mock_swrc.return_value = mock_col
        with self.assertRaises(MaxReleaseExceeded):
            c.major_release_upload_check()


class TestProcessUploadUpgradeFiles(unittest.TestCase):

    @INIT_PATCH
    @mock.patch('software.software_controller.SW_VERSION', '24.09')
    @mock.patch('software.software_controller.get_SWReleaseCollection')
    def test_process_upload_success(self, mock_swrc, _init):
        c = _make_controller()
        mock_swrc.return_value = mock.MagicMock()
        with mock.patch.object(c, 'major_release_upload_check'):
            with mock.patch.object(c, '_run_load_import',
                                   return_value=("info", "", "", {})):
                result = c._process_upload_upgrade_files(
                    "24.09", "25.03.0", "/mnt/iso",
                    [{"version": "24.09"}],
                    {constants.ISO_EXTENSION: "test.iso",
                     constants.SIG_EXTENSION: "test.sig"}
                )
        self.assertEqual(result[0], "info")

    @INIT_PATCH
    @mock.patch('software.software_controller.SW_VERSION', '24.09')
    def test_process_upload_unsupported_version(self, _init):
        c = _make_controller()
        with mock.patch.object(c, 'major_release_upload_check'):
            with self.assertRaises(UpgradeNotSupported):
                c._process_upload_upgrade_files(
                    "24.09", "25.03.0", "/mnt/iso",
                    [{"version": "23.09"}],
                    {constants.ISO_EXTENSION: "test.iso",
                     constants.SIG_EXTENSION: "test.sig"}
                )

    @INIT_PATCH
    @mock.patch('software.software_controller.SW_VERSION', '24.09')
    def test_process_upload_check_fails(self, _init):
        c = _make_controller()
        with mock.patch.object(c, 'major_release_upload_check',
                               side_effect=SoftwareServiceError("fail")):
            with self.assertRaises(SoftwareServiceError):
                c._process_upload_upgrade_files(
                    "24.09", "25.03.0", "/mnt/iso",
                    [{"version": "24.09"}],
                    {constants.ISO_EXTENSION: "test.iso",
                     constants.SIG_EXTENSION: "test.sig"}
                )


class TestProcessInactiveUpgradeFiles(unittest.TestCase):

    @INIT_PATCH
    @mock.patch('software.software_controller.SW_VERSION', '25.03')
    @mock.patch('software.software_controller.read_upgrade_support_versions',
                return_value=[{"version": "24.09"}])
    @mock.patch('software.software_controller.get_SWReleaseCollection')
    def test_process_inactive_success(self, mock_swrc, _read_versions, _init):
        c = _make_controller()
        mock_col = mock.MagicMock()
        mock_col.iterate_releases.return_value = []
        mock_swrc.return_value = mock_col
        with mock.patch.object(c, 'major_release_upload_check'):
            with mock.patch.object(c, '_run_load_import',
                                   return_value=("info", "", "", {})):
                result = c._process_inactive_upgrade_files(
                    None, "24.09.0", "/mnt/iso",
                    {constants.ISO_EXTENSION: "test.iso",
                     constants.SIG_EXTENSION: "test.sig"}
                )
        self.assertEqual(result[0], "info")

    @INIT_PATCH
    @mock.patch('software.software_controller.SW_VERSION', '25.03')
    @mock.patch('software.software_controller.read_upgrade_support_versions',
                return_value=[{"version": "24.09"}])
    def test_process_inactive_unsupported(self, _read_versions, _init):
        c = _make_controller()
        with mock.patch.object(c, 'major_release_upload_check'):
            with self.assertRaises(UpgradeNotSupported):
                c._process_inactive_upgrade_files(
                    None, "23.09.0", "/mnt/iso",
                    {constants.ISO_EXTENSION: "test.iso",
                     constants.SIG_EXTENSION: "test.sig"}
                )


@mock.patch('software.software_controller.get_SWReleaseCollection')
@mock.patch(
    'software.software_controller.PatchController.__init__',
    return_value=None)
class TestUploadApi(unittest.TestCase):
    """Tests for software_release_upload_api."""

    @mock.patch('software.software_controller.reload_release_data')
    def test_upload_patch_only(self, _mock_reload, _mock_init, _mock_swrc):
        c = PatchController()
        c.base_pkgdata = mock.MagicMock()
        c.hostname = "controller-0"
        c._process_upload_patch_files = mock.MagicMock(
            return_value=("P1 uploaded\n", "", "",
                          [{"P1.patch": {"id": "P1",
                                         "sw_release": "24.09.1"}}]))
        result = c.software_release_upload_api(["/tmp/P1.patch"])
        self.assertIn("uploaded", result["info"])
        self.assertEqual(result["error"], "")

    @mock.patch('software.software_controller.reload_release_data')
    def test_upload_no_files(self, _mock_reload, _mock_init, _mock_swrc):
        c = PatchController()
        c.base_pkgdata = mock.MagicMock()
        c.hostname = "controller-0"
        result = c.software_release_upload_api([])
        self.assertEqual(result["info"], "")
