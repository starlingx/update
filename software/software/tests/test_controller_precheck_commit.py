#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for software_controller.py -
deploy/upload API methods.
"""

from software import states
import threading
import unittest
from unittest.mock import patch
from unittest.mock import MagicMock

from software.tests import base as test_base  # noqa: F401
from software.tests.test_helpers import create_software_controller  # noqa: E402
from software.software_controller import PatchController
from software import constants
from software.exceptions import SoftwareFail
from software.exceptions import OSTreeCommandFail
from software.exceptions import SoftwareServiceError
from software.exceptions import APTOSTreeCommandFail


def _create_controller():
    """Create a PatchController mock with host attributes."""
    return create_software_controller(
        hosts={},
        hosts_lock=threading.RLock(),
        controller_neighbours={},
        controller_neighbours_lock=threading.RLock(),
        hostname="controller-0",
    )


class TestDeployPrecheck(unittest.TestCase):
    """Tests for _deploy_precheck."""

    def test_no_precheck_script_patch(self):
        sc = _create_controller()
        with patch('os.path.isfile', return_value=False):
            result = PatchController._deploy_precheck(sc, "24.09.1", patch=True)
        self.assertTrue(result["system_healthy"])
        self.assertIn("No deploy-precheck", result["info"])

    def test_no_precheck_script_upgrade(self):
        sc = _create_controller()
        with patch('os.path.isfile', return_value=False):
            result = PatchController._deploy_precheck(sc, "25.03")
        self.assertIn("damaged", result["error"])

    def test_pre_bootstrap_major(self):
        sc = _create_controller()
        sc.pre_bootstrap = True
        with patch('os.path.isfile', return_value=True):
            result = PatchController._deploy_precheck(sc, "25.03", patch=False)
        self.assertTrue(result["system_healthy"])

    def test_pre_bootstrap_no_force(self):
        sc = _create_controller()
        sc.pre_bootstrap = True
        with patch('os.path.isfile', return_value=True):
            result = PatchController._deploy_precheck(sc, "24.09.1", patch=True, force=False)
        self.assertIn("--force", result["warning"])

    @patch('subprocess.run')
    @patch('configparser.ConfigParser.read')
    @patch('configparser.ConfigParser.has_section', return_value=True)
    @patch('configparser.ConfigParser.__getitem__', return_value={
        "auth_url": "http://localhost:5000",
        "username": "admin", "password": "pass",
        "project_name": "admin",
        "user_domain_name": "Default",
        "project_domain_name": "Default"
    })
    @patch('os.path.isfile', return_value=True)
    def test_precheck_success(self, _mock_isfile, _mock_cp_item, _mock_has,
                              _mock_read, mock_run):
        sc = _create_controller()
        sc._get_software_upgrade.return_value = None
        sc.software_release_query_cached.return_value = [
            {"release_id": "stx-24.09", "prepatched_iso": False,
             "packages": [], "summary": "", "description": "",
             "install_instructions": "", "warnings": "", "component": ""}
        ]
        mock_run.return_value = MagicMock(
            returncode=constants.RC_SUCCESS, stdout="All checks passed")
        result = PatchController._deploy_precheck(sc, "24.09.1")
        self.assertTrue(result["system_healthy"])

    @patch('configparser.ConfigParser.read',
           side_effect=Exception("bad config"))
    @patch('os.path.isfile', return_value=True)
    def test_config_parse_error(self, _mock_isfile, _mock_read):
        sc = _create_controller()
        sc._get_software_upgrade.return_value = None
        result = PatchController._deploy_precheck(sc, "24.09.1")
        self.assertIn("Internal error", result["error"])


class TestPatchCommit(unittest.TestCase):
    """Tests for patch_commit."""

    @patch('os.path.exists', return_value=True)
    @patch('software.software_controller.reload_release_data')
    @patch('shutil.move')
    def test_commit_success(self, _mock_move, _mock_reload, _mock_exists):
        sc = _create_controller()
        rel = MagicMock(status=constants.STATUS_RELEASED)
        sc.release_collection.iterate_releases.return_value = [rel]
        r = MagicMock(state=states.DEPLOYED)
        sc.release_collection.get_release_by_id.return_value = r
        sc.get_dependencies.return_value = ["P1"]
        result = PatchController.patch_commit(sc, ["P1"])
        self.assertIn("committed", result["info"])

    @patch('os.path.exists', return_value=True)
    def test_non_rel_patches_rejected(self, _mock_exists):
        sc = _create_controller()
        rel = MagicMock(status="DEV", id="P1")
        sc.release_collection.iterate_releases.return_value = [rel]
        result = PatchController.patch_commit(sc, ["P1"])
        self.assertIn("non-REL", result["error"])

    @patch('os.path.exists', return_value=True)
    def test_unrecognized_patch(self, _mock_exists):
        sc = _create_controller()
        sc.release_collection.iterate_releases.return_value = []
        sc.release_collection.get_release_by_id.return_value = None
        result = PatchController.patch_commit(sc, ["BAD"])
        self.assertIn("unrecognized", result["error"])

    @patch('os.path.exists', return_value=True)
    def test_not_deployed_rejected(self, _mock_exists):
        sc = _create_controller()
        sc.release_collection.iterate_releases.return_value = []
        r = MagicMock(state=states.AVAILABLE)
        sc.release_collection.get_release_by_id.return_value = r
        sc.get_dependencies.return_value = ["P1"]
        result = PatchController.patch_commit(sc, ["P1"])
        self.assertIn("not applied", result["error"])

    @patch('os.path.exists', return_value=True)
    def test_dry_run(self, _mock_exists):
        sc = _create_controller()
        sc.release_collection.iterate_releases.return_value = []
        r = MagicMock(state=states.DEPLOYED)
        sc.release_collection.get_release_by_id.return_value = r
        sc.get_dependencies.return_value = ["P1"]
        result = PatchController.patch_commit(sc, ["P1"], dry_run=True)
        self.assertIn("MiB", result["info"])

    @patch('os.path.exists', return_value=False)
    @patch('os.makedirs', side_effect=OSError("fail"))
    def test_mkdir_fails(self, _mock_mkdir, _mock_exists):
        sc = _create_controller()
        with self.assertRaises(SoftwareFail):
            PatchController.patch_commit(sc, ["P1"])


class TestCheckoutCommitToDcVault(unittest.TestCase):
    """Tests for _checkout_commit_to_dc_vault_playbook_dir."""

    @patch('software.software_controller.ostree_utils')
    @patch('os.makedirs')
    def test_get_commit_fails(self, _mock_makedirs, mock_ostree):
        sc = _create_controller()
        mock_ostree.get_feed_latest_commit.side_effect = OSTreeCommandFail(
            "fail")
        with self.assertRaises(OSTreeCommandFail):
            PatchController._checkout_commit_to_dc_vault_playbook_dir(sc, "24.09")

    @patch('shutil.rmtree')
    @patch('os.path.exists', return_value=True)
    @patch('software.software_controller.ostree_utils')
    @patch('os.makedirs')
    def test_checkout_fails_cleans_up(self, _mock_makedirs, mock_ostree,
                                      _mock_exists, mock_rmtree):
        sc = _create_controller()
        mock_ostree.get_feed_latest_commit.return_value = "abc123"
        mock_ostree.checkout_commit_to_dir.side_effect = Exception("fail")
        with self.assertRaises(Exception):  # noqa: H202
            PatchController._checkout_commit_to_dc_vault_playbook_dir(sc, "24.09")
        mock_rmtree.assert_called_once()


class TestGetReleaseMetaInfo(unittest.TestCase):
    """Tests for get_release_meta_info."""

    @patch('software.software_controller.parse_release_metadata',
           return_value={"id": "stx-24.09", "sw_version": "24.09"})
    @patch('software.software_controller.utils.find_file_by_regex',
           return_value=["stx-24.09-metadata.xml"])
    def test_success(self, _mock_find, _mock_parse):
        sc = _create_controller()
        files = {constants.ISO_EXTENSION: "/path/test.iso",
                 constants.SIG_EXTENSION: "/path/test.sig"}
        result = PatchController.get_release_meta_info(sc, "/mnt/iso", files)
        self.assertEqual(result["test.iso"]["id"], "stx-24.09")

    @patch(
        'software.software_controller.utils.find_file_by_regex',
        return_value=[])
    def test_no_metadata_raises(self, _mock_find):
        sc = _create_controller()
        files = {constants.ISO_EXTENSION: "/path/test.iso",
                 constants.SIG_EXTENSION: "/path/test.sig"}
        with self.assertRaises(SoftwareServiceError):
            PatchController.get_release_meta_info(sc, "/mnt/iso", files)


class TestReleaseRemoveOrder(unittest.TestCase):
    """Tests for release_remove_order.

    The method walks the deployed releases backwards along the
    commit_id -> base_commit_id chain, from the running release down to
    (but excluding) the target.
    """

    @staticmethod
    def _release(rel_id, commit_id, base_commit_id):
        rel = MagicMock()
        rel.id = rel_id
        rel.commit_id = commit_id
        rel.base_commit_id = base_commit_id
        return rel

    def _controller(self, releases):
        sc = _create_controller()
        sc.release_collection.iterate_releases_by_state.return_value = releases
        return sc

    def test_release_from_other_major_version_is_skipped(self):
        """A target outside the running major version cannot be removed."""
        sc = self._controller([])
        result = PatchController.release_remove_order(sc, "stx-25.03.1", "stx-24.09.2", "24.09")
        self.assertEqual(result, [])

    def test_target_equal_to_running_removes_nothing(self):
        """Nothing to remove when the target is already the running release."""
        sc = self._controller([])
        result = PatchController.release_remove_order(sc, "stx-24.09.0", "stx-24.09.0", "24.09")
        self.assertEqual(result, [])

    def test_single_step_chain(self):
        """Running release is removed to get back to the target."""
        releases = [
            self._release("stx-24.09.1", "commit1", "commit0"),
            self._release("stx-24.09.0", "commit0", None),
        ]
        sc = self._controller(releases)
        result = PatchController.release_remove_order(sc, "stx-24.09.0", "stx-24.09.1", "24.09")
        self.assertEqual(result, ["stx-24.09.1"])

    def test_multi_step_chain_is_ordered_newest_first(self):
        """The chain is walked backwards and returned newest-first."""
        releases = [
            self._release("stx-24.09.3", "commit3", "commit2"),
            self._release("stx-24.09.2", "commit2", "commit1"),
            self._release("stx-24.09.1", "commit1", "commit0"),
            self._release("stx-24.09.0", "commit0", None),
        ]
        sc = self._controller(releases)
        result = PatchController.release_remove_order(sc, "stx-24.09.0", "stx-24.09.3", "24.09")
        self.assertEqual(result,
                         ["stx-24.09.3", "stx-24.09.2", "stx-24.09.1"])

    def test_partial_chain_stops_at_target(self):
        """Walking stops at the target rather than the oldest release."""
        releases = [
            self._release("stx-24.09.3", "commit3", "commit2"),
            self._release("stx-24.09.2", "commit2", "commit1"),
            self._release("stx-24.09.1", "commit1", "commit0"),
            self._release("stx-24.09.0", "commit0", None),
        ]
        sc = self._controller(releases)
        result = PatchController.release_remove_order(sc, "stx-24.09.1", "stx-24.09.3", "24.09")
        self.assertEqual(result, ["stx-24.09.3", "stx-24.09.2"])

    def test_missing_release_in_map_raises(self):
        """A running release absent from the deployed set is an error."""
        releases = [self._release("stx-24.09.0", "commit0", None)]
        sc = self._controller(releases)
        with self.assertRaises(SoftwareServiceError):
            PatchController.release_remove_order(sc, "stx-24.09.0", "stx-24.09.9", "24.09")

    def test_broken_commit_chain_raises(self):
        """A base_commit_id with no matching release is an error."""
        releases = [
            self._release("stx-24.09.1", "commit1", "missing-commit"),
            self._release("stx-24.09.0", "commit0", None),
        ]
        sc = self._controller(releases)
        with self.assertRaises(SoftwareServiceError):
            PatchController.release_remove_order(sc, "stx-24.09.0", "stx-24.09.1", "24.09")


class TestResetFeedCommit(unittest.TestCase):
    """Tests for reset_feed_commit."""

    @patch('software.software_controller.apt_utils')
    def test_failure_raises(self, mock_apt):
        sc = _create_controller()
        release = MagicMock(commit_id="abc", sw_version="24.09")
        mock_apt.run_rollback.side_effect = APTOSTreeCommandFail("fail")
        with self.assertRaises(APTOSTreeCommandFail):
            PatchController.reset_feed_commit(sc, release)


class TestQueryHostCache(unittest.TestCase):
    """Tests for query_host_cache."""

    def test_empty_hosts(self):
        sc = _create_controller()
        sc.hosts = {}
        result = PatchController.query_host_cache(sc)
        self.assertEqual(result, [])


@patch(
    'software.software_controller.PatchController.__init__',
    return_value=None)
class TestDeployPrecheck2(unittest.TestCase):

    @patch('subprocess.run')
    @patch('os.path.isfile', return_value=True)
    def test_precheck_unhealthy(self, _mock_isfile, mock_run, _mock_init):
        c = PatchController()
        c.pre_bootstrap = False
        c._get_software_upgrade = MagicMock(return_value=None)
        c._save_precheck_result = MagicMock()
        c.software_release_query_cached = MagicMock(return_value=[
            {"release_id": "stx-24.09", "prepatched_iso": False,
             "packages": [], "summary": "", "description": "",
             "install_instructions": "", "warnings": "", "component": ""}
        ])
        mock_run.return_value = MagicMock(
            returncode=constants.RC_UNHEALTHY,
            stdout="System not healthy: alarm active")
        with patch('configparser.ConfigParser.read'):
            with patch(
                    'configparser.ConfigParser.has_section',
                    return_value=True):
                with patch(
                        'configparser.ConfigParser'
                        '.__getitem__',
                        return_value={
                            "auth_url": "http://x",
                            "username": "a",
                            "password": "p",
                            "project_name": "a",
                            "user_domain_name": "D",
                            "project_domain_name": "D",
                        }):
                    result = c._deploy_precheck("24.09.1")
        self.assertFalse(result["system_healthy"])
        self.assertIn("not healthy", result["info"])

    @patch('subprocess.run')
    @patch('os.path.isfile', return_value=True)
    def test_precheck_script_error(self, _mock_isfile, mock_run, _mock_init):
        c = PatchController()
        c.pre_bootstrap = False
        c._get_software_upgrade = MagicMock(return_value=None)
        c._save_precheck_result = MagicMock()
        c.software_release_query_cached = MagicMock(return_value=[
            {"release_id": "stx-24.09", "prepatched_iso": False,
             "packages": [], "summary": "", "description": "",
             "install_instructions": "", "warnings": "", "component": ""}
        ])
        mock_run.return_value = MagicMock(
            returncode=2, stdout="Script crashed")
        with patch('configparser.ConfigParser.read'):
            with patch(
                    'configparser.ConfigParser.has_section',
                    return_value=True):
                with patch(
                        'configparser.ConfigParser'
                        '.__getitem__',
                        return_value={
                            "auth_url": "http://x",
                            "username": "a",
                            "password": "p",
                            "project_name": "a",
                            "user_domain_name": "D",
                            "project_domain_name": "D",
                        }):
                    result = c._deploy_precheck("24.09.1")
        self.assertIsNone(result["system_healthy"])
        self.assertIn("crashed", result["error"])

    @patch('os.path.isfile', return_value=True)
    def test_precheck_force_pre_bootstrap(self, _mock_isfile, _mock_init):
        c = PatchController()
        c.pre_bootstrap = True
        c._save_precheck_result = MagicMock()
        c._get_software_upgrade = MagicMock(return_value=None)
        c.software_release_query_cached = MagicMock(return_value=[])
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="ok")
            with patch('configparser.ConfigParser.read'):
                with patch(
                        'configparser.ConfigParser.has_section',
                        return_value=True):
                    with patch(
                            'configparser.ConfigParser'
                            '.__getitem__',
                            return_value={
                                "auth_url": "http://x",
                                "username": "a",
                                "password": "p",
                                "project_name": "a",
                                "user_domain_name": "D",
                                "project_domain_name":
                                    "D",
                            }):
                        result = c._deploy_precheck(
                            "24.09.1", force=True, patch=True)
        self.assertTrue(result["system_healthy"])
