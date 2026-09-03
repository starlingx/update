#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for software_controller.py."""

from software import states
import subprocess
import unittest
from unittest import mock
from unittest.mock import patch
from unittest.mock import MagicMock

from software.tests import base as test_base  # noqa: F401
from software.tests.test_helpers import create_software_controller  # noqa: E402
from software.software_controller import PatchController
from software.exceptions import SoftwareServiceError


class TestReleaseApplyOrder(unittest.TestCase):
    """Tests for release_apply_order."""

    def test_basic(self):
        sc = create_software_controller()
        sc.release_apply_order = PatchController.release_apply_order.__get__(
            sc)
        r1 = MagicMock(
            id="stx-24.09.1",
            state=states.AVAILABLE,
            prepatched_iso=False)
        r2 = MagicMock(
            id="stx-24.09.0",
            state=states.DEPLOYED,
            prepatched_iso=False)
        sc.release_collection.iterate_releases.return_value = [r1, r2]
        sc.get_release_dependency_list.return_value = []
        result = sc.release_apply_order("stx-24.09.1", "24.09")
        self.assertEqual(result, ["stx-24.09.1"])

    def test_filters_wrong_version(self):
        sc = create_software_controller()
        sc.release_apply_order = PatchController.release_apply_order.__get__(
            sc)
        r1 = MagicMock(
            id="stx-25.03.1",
            state=states.AVAILABLE,
            prepatched_iso=False)
        sc.release_collection.iterate_releases.return_value = [r1]
        sc.get_release_dependency_list.return_value = []
        result = sc.release_apply_order("stx-25.03.1", "24.09")
        self.assertEqual(result, [])

    def test_excludes_deployed(self):
        sc = create_software_controller()
        sc.release_apply_order = PatchController.release_apply_order.__get__(
            sc)
        r1 = MagicMock(
            id="stx-24.09.1",
            state=states.DEPLOYED,
            prepatched_iso=False)
        sc.release_collection.iterate_releases.return_value = [r1]
        sc.get_release_dependency_list.return_value = []
        result = sc.release_apply_order("stx-24.09.1", "24.09")
        self.assertEqual(result, [])


class TestPreviousReleaseApplyOrder(unittest.TestCase):
    """Tests for previous_release_apply_order."""

    @patch('software.software_controller.SW_VERSION', '25.03')
    def test_basic(self):
        sc = create_software_controller()
        sc.previous_release_apply_order = (
            PatchController.previous_release_apply_order.__get__(
                sc))
        r = MagicMock(id="stx-24.09.1", sw_version="24.09.1",
                      commit_id="abc", prepatched_iso=False)
        sc.release_collection.iterate_releases.return_value = [r]
        sc.get_release_dependency_list.return_value = []
        result = sc.previous_release_apply_order("stx-24.09.2")
        self.assertIn("stx-24.09.2", result)

    @patch('software.software_controller.SW_VERSION', '25.03')
    def test_excludes_already_deployed(self):
        sc = create_software_controller()
        sc.previous_release_apply_order = (
            PatchController.previous_release_apply_order.__get__(
                sc))
        r = MagicMock(id="stx-24.09.1", sw_version="24.09.1",
                      commit_id="abc", prepatched_iso=False)
        sc.release_collection.iterate_releases.return_value = [r]
        sc.get_release_dependency_list.return_value = ["stx-24.09.1"]
        result = sc.previous_release_apply_order("stx-24.09.2")
        self.assertNotIn("stx-24.09.1", result)


class TestReleaseRemoveOrder(unittest.TestCase):
    """Tests for release_remove_order."""

    def test_wrong_version(self):
        sc = create_software_controller()
        sc.release_remove_order = PatchController.release_remove_order.__get__(
            sc)
        result = sc.release_remove_order("stx-25.03.1", "stx-24.09.0", "24.09")
        self.assertEqual(result, [])


class TestSoftwareReleaseQueryCached(unittest.TestCase):
    """Tests for software_release_query_cached."""

    def test_query_all(self):
        sc = create_software_controller()
        sc.software_release_query_cached = (
            PatchController.software_release_query_cached.__get__(
                sc))
        r = MagicMock()
        r.to_query_dict.return_value = {"id": "stx-24.09.1"}
        sc.release_collection.iterate_releases.return_value = [r]
        result = sc.software_release_query_cached()
        self.assertEqual(len(result), 1)

    def test_query_by_state(self):
        sc = create_software_controller()
        sc.software_release_query_cached = (
            PatchController.software_release_query_cached.__get__(
                sc))
        r = MagicMock()
        r.to_query_dict.return_value = {"id": "stx-24.09.1"}
        sc.release_collection.iterate_releases_by_state.return_value = [r]
        result = sc.software_release_query_cached(show=states.AVAILABLE)
        self.assertEqual(len(result), 1)

    def test_query_by_release(self):
        sc = create_software_controller()
        sc.software_release_query_cached = (
            PatchController.software_release_query_cached.__get__(
                sc))
        r = MagicMock(id="stx-24.09.1", sw_version="24.09")
        r.to_query_dict.return_value = {"id": "stx-24.09.1"}
        sc.release_collection.iterate_releases.return_value = [r]
        result = sc.software_release_query_cached(release=["24.09"])
        self.assertEqual(len(result), 1)

    def test_query_invalid_state(self):
        sc = create_software_controller()
        sc.software_release_query_cached = (
            PatchController.software_release_query_cached.__get__(
                sc))
        sc.release_collection.iterate_releases.return_value = []
        result = sc.software_release_query_cached(show="bad")
        self.assertEqual(result, [])


class TestSoftwareSync(unittest.TestCase):
    """Tests for software_sync."""

    def test_no_sock(self):
        sc = create_software_controller()
        sc.software_sync = PatchController.software_sync.__get__(sc)
        sc.sock_out = None
        result = sc.software_sync()
        self.assertTrue(result)

    def test_install_local(self):
        sc = create_software_controller()
        sc.software_sync = PatchController.software_sync.__get__(sc)
        sc.sock_out = MagicMock()
        sc.install_local = True
        result = sc.software_sync()
        self.assertTrue(result)


class TestSyncFromNbr(unittest.TestCase):
    """Tests for PatchController.sync_from_nbr
    (with ostree_lock mocked).
    """

    @patch('os.listdir', return_value=[])
    @patch('subprocess.check_output', return_value="synced ok")
    @patch('software.ostree_utils.constants.OSTREE_LOCK',
           '/tmp/.test_ostree_lock')
    def test_success(self, _mock_rsync, _mock_listdir):
        sc = create_software_controller()
        sc.sync_from_nbr = PatchController.sync_from_nbr.__get__(sc)
        sc.hosts = {}
        result = sc.sync_from_nbr("10.0.0.1")
        self.assertNotEqual(result, False)

    @patch('subprocess.check_output',
           side_effect=subprocess.CalledProcessError(
               1, 'rsync', output=b'err'))
    @patch('software.ostree_utils.constants.OSTREE_LOCK',
           '/tmp/.test_ostree_lock')
    def test_first_rsync_fails(self, _mock_rsync):
        sc = create_software_controller()
        sc.sync_from_nbr = PatchController.sync_from_nbr.__get__(sc)
        result = sc.sync_from_nbr("10.0.0.1")
        self.assertFalse(result)

    @patch('subprocess.check_output',
           side_effect=["ok", subprocess.CalledProcessError(
               1, 'rsync', output=b'err')])
    @patch('software.ostree_utils.constants.OSTREE_LOCK',
           '/tmp/.test_ostree_lock')
    def test_second_rsync_fails(self, _mock_rsync):
        sc = create_software_controller()
        sc.sync_from_nbr = PatchController.sync_from_nbr.__get__(sc)
        result = sc.sync_from_nbr("10.0.0.1")
        self.assertFalse(result)


class TestSoftwareReleaseDeleteApi(unittest.TestCase):
    """Tests for PatchController
    software_release_delete_api.
    """

    @patch(
        'software.software_controller.is_system_controller',
        return_value=False)
    def test_not_found(self, _mock_sc):
        sc = create_software_controller()
        sc.software_release_delete_api = (
            PatchController.software_release_delete_api.__get__(
                sc))
        sc._verify_releases_to_delete = (
            PatchController._verify_releases_to_delete.__get__(
                sc))
        sc.release_collection.get_release_by_id.return_value = None
        with self.assertRaises(SoftwareServiceError):
            sc.software_release_delete_api(["bad-id"])

    @patch(
        'software.software_controller.is_system_controller',
        return_value=False)
    def test_not_deletable(self, _mock_sc):
        sc = create_software_controller()
        sc.software_release_delete_api = (
            PatchController.software_release_delete_api.__get__(
                sc))
        sc._verify_releases_to_delete = (
            PatchController._verify_releases_to_delete.__get__(
                sc))
        rel = MagicMock()
        rel.is_deletable = False
        sc.release_collection.get_release_by_id.return_value = rel
        with self.assertRaises(SoftwareServiceError):
            sc.software_release_delete_api(["stx-24.09.1"])

    @patch(
        'software.software_controller.is_system_controller',
        return_value=True)
    @patch('software.software_controller.get_subcloud_groupby_version',
           return_value={"24.09": [{"name": "sc1"}]})
    def test_used_by_subcloud(self, _mock_subclouds, _mock_sc):
        sc = create_software_controller()
        sc.software_release_delete_api = (
            PatchController.software_release_delete_api.__get__(
                sc))
        sc._verify_releases_to_delete = (
            PatchController._verify_releases_to_delete.__get__(
                sc))
        rel = MagicMock()
        rel.is_deletable = True
        rel.is_ga_release = True
        rel.sw_version = "24.09"
        sc.release_collection.get_release_by_id.return_value = rel
        with self.assertRaises(SoftwareServiceError):
            sc.software_release_delete_api(["stx-24.09.0"])

    @patch(
        'software.software_controller.is_system_controller',
        return_value=False)
    def test_delete_duplicates_deduped(self, _mock_sc):
        sc = create_software_controller()
        sc.software_release_delete_api = (
            PatchController.software_release_delete_api.__get__(
                sc))
        sc._verify_releases_to_delete = (
            PatchController._verify_releases_to_delete.__get__(
                sc))
        sc.release_collection.get_release_by_id.return_value = None
        with self.assertRaises(SoftwareServiceError):
            sc.software_release_delete_api(["bad-id", "bad-id"])


class TestReadStateFile(unittest.TestCase):
    """Tests for PatchController.read_state_file."""

    @patch('builtins.open', mock.mock_open(
        read_data='[runtime]\npatch_op_counter=5\n'))
    def test_reads_counter(self):
        sc = create_software_controller()
        sc.read_state_file = PatchController.read_state_file.__get__(sc)
        sc.patch_op_counter = 0
        sc.read_state_file()
        self.assertEqual(sc.patch_op_counter, 5)


class TestIncPatchOpCounter(unittest.TestCase):
    """Tests for PatchController.inc_patch_op_counter."""

    @patch('builtins.open', mock.mock_open())
    def test_increments(self):
        sc = create_software_controller()
        sc.inc_patch_op_counter = PatchController.inc_patch_op_counter.__get__(
            sc)
        sc.patch_op_counter = 5
        sc.inc_patch_op_counter()
        self.assertEqual(sc.patch_op_counter, 6)
