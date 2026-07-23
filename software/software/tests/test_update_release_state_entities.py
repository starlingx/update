#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for software.release_state and software.software_entities.

DeployHandler / DeployHostHandler tests use REAL file I/O against a
temp software.json — only the constants pointing at the file are patched.
"""

import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from software.tests import base  # noqa: F401
from software import states
from software.exceptions import DeployAlreadyExist
from software.exceptions import DeployDoNotExist
from software.exceptions import ReleaseNotFound
from software.exceptions import SystemDeployNotExist
from software.release_state import RELEASE_STATE_TRANSITION
from software.release_state import ReleaseState
from software.software_entities import DeployHandler
from software.software_entities import DeployHostHandler
from software.software_entities import SystemDeployHandler
from software.states import DEPLOY_HOST_STATES
from software.states import DEPLOY_STATES
from software.states import SYSTEM_DEPLOY_STATES


class TestReleaseStateTransitionMap(unittest.TestCase):
    """Tests for RELEASE_STATE_TRANSITION map correctness."""

    def test_available_transitions(self):
        """AVAILABLE can go to DEPLOYING, UNAVAILABLE, DEPLOY_SELECTED."""
        valid = RELEASE_STATE_TRANSITION[states.AVAILABLE]
        self.assertIn(states.DEPLOYING, valid)
        self.assertIn(states.UNAVAILABLE, valid)
        self.assertIn(states.DEPLOY_SELECTED, valid)

    def test_deploying_transitions(self):
        """DEPLOYING can go to DEPLOYED or back to AVAILABLE."""
        valid = RELEASE_STATE_TRANSITION[states.DEPLOYING]
        self.assertIn(states.DEPLOYED, valid)
        self.assertIn(states.AVAILABLE, valid)

    def test_deployed_transitions(self):
        """DEPLOYED can go to REMOVING, UNAVAILABLE, COMMITTED, REMOVE_SELECTED."""
        valid = RELEASE_STATE_TRANSITION[states.DEPLOYED]
        self.assertIn(states.REMOVING, valid)
        self.assertIn(states.UNAVAILABLE, valid)
        self.assertIn(states.COMMITTED, valid)
        self.assertIn(states.REMOVE_SELECTED, valid)

    def test_committed_is_terminal(self):
        """COMMITTED has no outgoing transitions."""
        self.assertEqual(RELEASE_STATE_TRANSITION[states.COMMITTED], [])

    def test_unavailable_is_terminal(self):
        """UNAVAILABLE has no outgoing transitions."""
        self.assertEqual(RELEASE_STATE_TRANSITION[states.UNAVAILABLE], [])

    def test_deploy_selected_transitions(self):
        """DEPLOY_SELECTED can start deploying or be unselected."""
        valid = RELEASE_STATE_TRANSITION[states.DEPLOY_SELECTED]
        self.assertIn(states.DEPLOYING, valid)
        self.assertIn(states.AVAILABLE, valid)

    def test_remove_selected_transitions(self):
        """REMOVE_SELECTED can start removing or be unselected."""
        valid = RELEASE_STATE_TRANSITION[states.REMOVE_SELECTED]
        self.assertIn(states.REMOVING, valid)
        self.assertIn(states.DEPLOYED, valid)


class TestReleaseStateInit(unittest.TestCase):
    """Tests for ReleaseState.__init__ — release resolution logic."""

    def setUp(self):
        ReleaseState._callbacks = []

    def test_no_params_returns_empty(self):
        """No release_ids or state gives empty release list."""
        rs = ReleaseState()
        self.assertEqual(rs.get_release_ids(), [])
        self.assertFalse(rs.has_release_id())

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_legacy_release_id_kept_as_is(self, mock_coll):
        """Legacy (non-product) release ID is used directly."""
        rel = mock.MagicMock()
        rel.is_product_release = False
        mock_coll.return_value.__getitem__.return_value = rel

        rs = ReleaseState(release_ids=["PATCH_001"])
        self.assertEqual(rs.get_release_ids(), ["PATCH_001"])
        self.assertTrue(rs.has_release_id())

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_product_release_expands_to_metapackages(self, mock_coll):
        """Product release expands into its metapackage IDs."""
        rel = mock.MagicMock()
        rel.is_product_release = True
        rel.metapackages = {"platform_24.09": {}, "networking_24.09": {}}
        mock_coll.return_value.__getitem__.return_value = rel

        rs = ReleaseState(release_ids=["starlingx-24.09"])
        self.assertEqual(sorted(rs.get_release_ids()),
                         ["networking_24.09", "platform_24.09"])

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_missing_release_raises(self, mock_coll):
        """Unknown release ID raises ReleaseNotFound."""
        mock_coll.return_value.__getitem__.return_value = None

        with self.assertRaises(ReleaseNotFound):
            ReleaseState(release_ids=["NOPE"])

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_state_query_collects_legacy_and_metapackages(self, mock_coll):
        """Querying by state collects legacy releases + metapackages."""
        legacy = mock.MagicMock()
        legacy.id = "PATCH_001"
        legacy.is_legacy_release = True
        mp = mock.MagicMock()
        mp.id = "platform_24.09"
        mp.is_pre_upgrade_deploy_release = False

        mock_coll.return_value.iterate_releases_by_state.return_value = [legacy]
        mock_coll.return_value.iterate_metapackages_by_state.return_value = [mp]

        rs = ReleaseState(release_state=states.AVAILABLE)
        self.assertEqual(sorted(rs.get_release_ids()),
                         ["PATCH_001", "platform_24.09"])

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_pre_upgrade_deploy_filters_metapackages(self, mock_coll):
        """pre_upgrade_deploy=True only returns pre-upgrade metapackages."""
        mp_pre = mock.MagicMock()
        mp_pre.id = "platform_25.03"
        mp_pre.is_pre_upgrade_deploy_release = True
        mp_normal = mock.MagicMock()
        mp_normal.id = "platform_24.09"
        mp_normal.is_pre_upgrade_deploy_release = False

        mock_coll.return_value.iterate_metapackages_by_state.return_value = [
            mp_pre, mp_normal]

        rs = ReleaseState(release_state=states.AVAILABLE, pre_upgrade_deploy=True)
        self.assertEqual(rs.get_release_ids(), ["platform_25.03"])


class TestReleaseStateCheckTransition(unittest.TestCase):
    """Tests for ReleaseState.check_transition."""

    def setUp(self):
        ReleaseState._callbacks = []

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_valid_transition_returns_true(self, mock_coll):
        """AVAILABLE -> DEPLOYING is valid."""
        rel = mock.MagicMock()
        rel.state = states.AVAILABLE
        rel.is_product_release = False
        mock_coll.return_value.__getitem__.return_value = rel

        rs = ReleaseState(release_ids=["PATCH_001"])
        self.assertTrue(rs.check_transition(states.DEPLOYING))

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_invalid_transition_returns_false(self, mock_coll):
        """AVAILABLE -> COMMITTED is not valid."""
        rel = mock.MagicMock()
        rel.state = states.AVAILABLE
        rel.is_product_release = False
        mock_coll.return_value.__getitem__.return_value = rel

        rs = ReleaseState(release_ids=["PATCH_001"])
        self.assertFalse(rs.check_transition(states.COMMITTED))

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_missing_release_returns_false(self, mock_coll):
        """Release disappearing between init and check returns False."""
        rel = mock.MagicMock()
        rel.state = states.AVAILABLE
        rel.is_product_release = False
        mock_coll.return_value.__getitem__.side_effect = [rel, None]

        rs = ReleaseState(release_ids=["PATCH_001"])
        self.assertFalse(rs.check_transition(states.DEPLOYING))


class TestReleaseStateMajorReleaseDetection(unittest.TestCase):
    """Tests for is_major_release_deployment / is_patched_major_release_deployment."""

    def setUp(self):
        ReleaseState._callbacks = []

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_ga_release_is_major(self, mock_coll):
        """GA release means major release deployment."""
        rel = mock.MagicMock()
        rel.is_product_release = False
        mock_coll.return_value.__getitem__.return_value = rel

        target = mock.MagicMock()
        target.is_ga_release = True
        target.prepatched_iso = False
        mock_coll.return_value.get_release_by_id.return_value = target

        rs = ReleaseState(release_ids=["starlingx-25.03"])
        self.assertTrue(rs.is_major_release_deployment())

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_prepatched_iso_is_major(self, mock_coll):
        """Prepatched ISO also counts as major release deployment."""
        rel = mock.MagicMock()
        rel.is_product_release = False
        mock_coll.return_value.__getitem__.return_value = rel

        target = mock.MagicMock()
        target.is_ga_release = False
        target.prepatched_iso = True
        mock_coll.return_value.get_release_by_id.return_value = target

        rs = ReleaseState(release_ids=["starlingx-25.03"])
        self.assertTrue(rs.is_major_release_deployment())
        self.assertTrue(rs.is_patched_major_release_deployment())

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_patch_is_not_major(self, mock_coll):
        """Plain patch is not a major release deployment."""
        rel = mock.MagicMock()
        rel.is_product_release = False
        mock_coll.return_value.__getitem__.return_value = rel

        target = mock.MagicMock()
        target.is_ga_release = False
        target.prepatched_iso = False
        mock_coll.return_value.get_release_by_id.return_value = target

        rs = ReleaseState(release_ids=["PATCH_001"])
        self.assertFalse(rs.is_major_release_deployment())
        self.assertFalse(rs.is_patched_major_release_deployment())

    def test_empty_release_list_is_not_major(self):
        """No releases means not a major deployment."""
        rs = ReleaseState()
        with mock.patch('software.release_state.get_SWReleaseCollection'):
            self.assertFalse(rs.is_major_release_deployment())


class TestReleaseStateTransformCallbacks(unittest.TestCase):
    """Tests for ReleaseState.transform — state update + callbacks."""

    def setUp(self):
        ReleaseState._callbacks = []

    @mock.patch('software.release_state.reload_release_data')
    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_valid_transform_updates_state(self, mock_coll, _mock_reload):
        """Valid transition calls update_state with the release IDs."""
        rel = mock.MagicMock()
        rel.state = states.AVAILABLE
        rel.is_product_release = False
        mock_coll.return_value.__getitem__.return_value = rel

        rs = ReleaseState(release_ids=["PATCH_001"])
        rs.start_deploy()
        mock_coll.return_value.update_state.assert_called_once_with(
            ["PATCH_001"], states.DEPLOYING, pre_upgrade_deploy=False)

    @mock.patch('software.release_state.reload_release_data')
    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_invalid_transform_skips_update(self, mock_coll, _mock_reload):
        """Invalid transition does not call update_state."""
        rel = mock.MagicMock()
        rel.state = states.COMMITTED
        rel.is_product_release = False
        mock_coll.return_value.__getitem__.return_value = rel

        rs = ReleaseState(release_ids=["PATCH_001"])
        rs.start_deploy()
        mock_coll.return_value.update_state.assert_not_called()

    @mock.patch('software.release_state.reload_release_data')
    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_transform_invokes_callbacks(self, mock_coll, _mock_reload):
        """Callbacks receive the target state."""
        rel = mock.MagicMock()
        rel.state = states.AVAILABLE
        rel.is_product_release = False
        mock_coll.return_value.__getitem__.return_value = rel

        seen = []
        ReleaseState.register_event_listener(seen.append)

        rs = ReleaseState(release_ids=["PATCH_001"])
        rs.start_deploy()
        self.assertEqual(seen, [states.DEPLOYING])

    @mock.patch('software.release_state.reload_release_data')
    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_transform_always_reloads_data(self, mock_coll, mock_reload):
        """reload_release_data is called even when transition invalid."""
        rel = mock.MagicMock()
        rel.state = states.COMMITTED
        rel.is_product_release = False
        mock_coll.return_value.__getitem__.return_value = rel

        rs = ReleaseState(release_ids=["PATCH_001"])
        rs.available()
        mock_reload.assert_called_once()

    def test_register_none_listener_ignored(self):
        """Registering None does not add a callback."""
        ReleaseState.register_event_listener(None)
        self.assertEqual(ReleaseState._callbacks, [])

    def test_register_duplicate_listener_once(self):
        """Duplicate callbacks are only registered once."""
        def cb(_state):
            pass
        ReleaseState.register_event_listener(cb)
        ReleaseState.register_event_listener(cb)
        self.assertEqual(len(ReleaseState._callbacks), 1)


class TestDeployHandlerRealFile(unittest.TestCase):
    """Tests for DeployHandler using REAL software.json file I/O."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.json_file = os.path.join(self.tmpdir, "software.json")
        with open(self.json_file, 'w') as f:
            json.dump({}, f)
        self.patcher = mock.patch.multiple(
            'software.software_entities.constants',
            SOFTWARE_JSON_FILE=self.json_file)
        self.patcher.start()
        self.utils_patcher = mock.patch(
            'software.software_entities.get_software_filesystem_data',
            side_effect=lambda data_file=None: self._read())
        self.utils_patcher.start()
        self.handler = DeployHandler()

    def tearDown(self):
        self.utils_patcher.stop()
        self.patcher.stop()
        shutil.rmtree(self.tmpdir)

    def _read(self):
        with open(self.json_file) as f:
            return json.load(f)

    def test_create_writes_deploy_entry(self):
        """create() persists a deploy entry with all fields."""
        self.handler.create("24.09.0", "25.03.0", "/feed", "commit1",
                            True, ["platform_25.03"])
        data = self._read()
        self.assertEqual(len(data["deploy"]), 1)
        entry = data["deploy"][0]
        self.assertEqual(entry["from_release"], "24.09.0")
        self.assertEqual(entry["to_release"], "25.03.0")
        self.assertEqual(entry["feed_repo"], "/feed")
        self.assertEqual(entry["commit_id"], "commit1")
        self.assertTrue(entry["reboot_required"])
        self.assertEqual(entry["metapackages"], ["platform_25.03"])
        self.assertEqual(entry["state"], DEPLOY_STATES.START.value)

    def test_create_duplicate_raises(self):
        """Creating the same from/to deploy twice raises DeployAlreadyExist."""
        self.handler.create("24.09.0", "25.03.0", "/feed", "c1", True, [])
        with self.assertRaises(DeployAlreadyExist):
            self.handler.create("24.09.0", "25.03.0", "/feed", "c1", True, [])

    def test_query_returns_matching_deploy(self):
        """query() finds deploy by from/to release."""
        self.handler.create("24.09.0", "25.03.0", "/feed", "c1", True, [])
        result = self.handler.query("24.09.0", "25.03.0")
        self.assertEqual(result["to_release"], "25.03.0")

    def test_query_no_match_returns_empty(self):
        """query() returns empty list when no match."""
        self.handler.create("24.09.0", "25.03.0", "/feed", "c1", True, [])
        self.assertEqual(self.handler.query("24.09.0", "26.01.0"), [])

    def test_query_all_returns_list(self):
        """query_all() returns every deploy entry."""
        self.handler.create("24.09.0", "25.03.0", "/feed", "c1", True, [])
        self.assertEqual(len(self.handler.query_all()), 1)

    def test_update_changes_state(self):
        """update() changes the deploy state on disk."""
        self.handler.create("24.09.0", "25.03.0", "/feed", "c1", True, [])
        self.handler.update(new_state=DEPLOY_STATES.START_DONE)
        self.assertEqual(self._read()["deploy"][0]["state"],
                         DEPLOY_STATES.START_DONE.value)

    def test_update_changes_commit_id(self):
        """update() can change commit_id without touching state."""
        self.handler.create("24.09.0", "25.03.0", "/feed", "c1", True, [])
        self.handler.update(commit_id="c2")
        entry = self._read()["deploy"][0]
        self.assertEqual(entry["commit_id"], "c2")
        self.assertEqual(entry["state"], DEPLOY_STATES.START.value)

    def test_update_without_deploy_raises(self):
        """update() with no deploy raises DeployDoNotExist."""
        with self.assertRaises(DeployDoNotExist):
            self.handler.update(new_state=DEPLOY_STATES.START_DONE)

    def test_delete_clears_deploy(self):
        """delete() empties the deploy list."""
        self.handler.create("24.09.0", "25.03.0", "/feed", "c1", True, [])
        self.handler.delete()
        self.assertEqual(self._read()["deploy"], [])

    def test_delete_without_deploy_raises(self):
        """delete() with no deploy raises DeployDoNotExist."""
        with self.assertRaises(DeployDoNotExist):
            self.handler.delete()

    def test_create_stores_pre_upgrade_deploy_kwarg(self):
        """pre_upgrade_deploy kwarg is persisted."""
        self.handler.create("24.09.0", "25.03.0", "/feed", "c1", True, [],
                            pre_upgrade_deploy=True)
        self.assertTrue(self._read()["deploy"][0]["pre_upgrade_deploy"])

    def test_create_defaults_pre_upgrade_deploy_false(self):
        """pre_upgrade_deploy defaults to False."""
        self.handler.create("24.09.0", "25.03.0", "/feed", "c1", True, [])
        self.assertFalse(self._read()["deploy"][0]["pre_upgrade_deploy"])


class TestDeployHostHandlerRealFile(unittest.TestCase):
    """Tests for DeployHostHandler using REAL software.json file I/O."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.json_file = os.path.join(self.tmpdir, "software.json")
        with open(self.json_file, 'w') as f:
            json.dump({}, f)
        self.patcher = mock.patch.multiple(
            'software.software_entities.constants',
            SOFTWARE_JSON_FILE=self.json_file)
        self.patcher.start()
        self.utils_patcher = mock.patch(
            'software.software_entities.get_software_filesystem_data',
            side_effect=lambda data_file=None: self._read())
        self.utils_patcher.start()
        self.handler = DeployHostHandler()

    def tearDown(self):
        self.utils_patcher.stop()
        self.patcher.stop()
        shutil.rmtree(self.tmpdir)

    def _read(self):
        with open(self.json_file) as f:
            return json.load(f)

    def test_create_writes_host_entry(self):
        """create() persists a deploy host with PENDING state."""
        self.handler.create("controller-0")
        hosts = self._read()["deploy_host"]
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]["hostname"], "controller-0")
        self.assertEqual(hosts[0]["state"], DEPLOY_HOST_STATES.PENDING.value)

    def test_create_with_explicit_state(self):
        """create() accepts an explicit state."""
        self.handler.create("worker-0", DEPLOY_HOST_STATES.DEPLOYING)
        self.assertEqual(self._read()["deploy_host"][0]["state"],
                         DEPLOY_HOST_STATES.DEPLOYING.value)

    def test_create_duplicate_raises(self):
        """Creating same host twice raises DeployAlreadyExist."""
        self.handler.create("controller-0")
        with self.assertRaises(DeployAlreadyExist):
            self.handler.create("controller-0")

    def test_query_returns_host(self):
        """query() finds a host by name."""
        self.handler.create("controller-0")
        result = self.handler.query("controller-0")
        self.assertEqual(result["hostname"], "controller-0")

    def test_query_unknown_returns_none(self):
        """query() returns None for unknown host."""
        self.handler.create("controller-0")
        self.assertIsNone(self.handler.query("worker-9"))

    def test_query_all_returns_all_hosts(self):
        """query_all() returns every host entry."""
        self.handler.create("controller-0")
        self.handler.create("worker-0")
        self.assertEqual(len(self.handler.query_all()), 2)

    def test_update_changes_host_state(self):
        """update() changes the host state on disk."""
        self.handler.create("controller-0")
        result = self.handler.update("controller-0", DEPLOY_HOST_STATES.DEPLOYED)
        self.assertEqual(result["state"], DEPLOY_HOST_STATES.DEPLOYED.value)
        self.assertEqual(self._read()["deploy_host"][0]["state"],
                         DEPLOY_HOST_STATES.DEPLOYED.value)

    def test_update_unknown_host_raises(self):
        """update() on unknown host raises."""
        with self.assertRaises(Exception):  # noqa: H202
            self.handler.update("ghost-0", DEPLOY_HOST_STATES.DEPLOYED)

    def test_delete_removes_host(self):
        """delete() removes only the named host."""
        self.handler.create("controller-0")
        self.handler.create("worker-0")
        self.handler.delete("controller-0")
        hosts = self._read()["deploy_host"]
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]["hostname"], "worker-0")

    def test_delete_unknown_raises(self):
        """delete() on unknown host raises DeployDoNotExist."""
        self.handler.create("controller-0")
        with self.assertRaises(DeployDoNotExist):
            self.handler.delete("ghost-0")

    def test_delete_all_clears_hosts(self):
        """delete_all() empties the host list."""
        self.handler.create("controller-0")
        self.handler.create("worker-0")
        self.handler.delete_all()
        self.assertEqual(self._read()["deploy_host"], [])


class TestSystemDeployHandlerRealFile(unittest.TestCase):
    """Tests for SystemDeployHandler using REAL JSON file I/O."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.json_file = os.path.join(self.tmpdir, "system_deploy.json")
        with open(self.json_file, 'w') as f:
            json.dump({}, f)
        self.patcher = mock.patch.multiple(
            'software.software_entities.constants',
            SYSTEM_DEPLOY_JSON_FILE=self.json_file)
        self.patcher.start()
        self.utils_patcher = mock.patch(
            'software.software_entities.get_software_filesystem_data',
            side_effect=lambda data_file=None: self._read())
        self.utils_patcher.start()
        self.handler = SystemDeployHandler()

    def tearDown(self):
        self.utils_patcher.stop()
        self.patcher.stop()
        shutil.rmtree(self.tmpdir)

    def _read(self):
        with open(self.json_file) as f:
            return json.load(f)

    def test_create_writes_system_deploy(self):
        """create() persists the system deploy entry."""
        self.handler.create("sd-1", "25.03.0", "v1.29.2")
        entry = self._read()["system_deploy"]
        self.assertEqual(entry["id"], "sd-1")
        self.assertEqual(entry["to_release"], "25.03.0")
        self.assertEqual(entry["to_k8s_version"], "v1.29.2")
        self.assertEqual(entry["state"], SYSTEM_DEPLOY_STATES.START.value)

    def test_query_returns_entry(self):
        """query() returns the stored system deploy."""
        self.handler.create("sd-1", "25.03.0", "v1.29.2")
        result = self.handler.query()
        self.assertEqual(result["id"], "sd-1")

    def test_query_empty_returns_empty_list(self):
        """query() returns [] when nothing stored."""
        self.assertEqual(self.handler.query(), [])

    def test_update_without_deploy_raises(self):
        """update() with no system deploy raises SystemDeployNotExist."""
        with self.assertRaises(SystemDeployNotExist):
            self.handler.update(SYSTEM_DEPLOY_STATES.START_DONE)

    def test_update_returns_new_entry(self):
        """update() returns the entry with the new state."""
        self.handler.create("sd-1", "25.03.0", "v1.29.2")
        result = self.handler.update(SYSTEM_DEPLOY_STATES.START_DONE)
        self.assertEqual(result["state"], SYSTEM_DEPLOY_STATES.START_DONE.value)
        self.assertEqual(result["id"], "sd-1")

    def test_delete_removes_entry(self):
        """delete() removes the system_deploy key."""
        self.handler.create("sd-1", "25.03.0", "v1.29.2")
        self.handler.delete()
        self.assertNotIn("system_deploy", self._read())

    def test_delete_when_empty_is_noop(self):
        """delete() with nothing stored does not raise."""
        self.handler.delete()
        self.assertNotIn("system_deploy", self._read())
