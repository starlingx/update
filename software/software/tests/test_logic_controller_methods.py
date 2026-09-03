#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for PatchController methods — check_releases_state,
deploy_host_list, _get_software_upgrade, check_upgrade_in_progress,
get_all_software_host_upgrade, ControllerNeighbour, AgentNeighbour.
"""

import unittest
from unittest import mock

from software.tests import base  # noqa: F401
from software import states
from software.software_controller import AgentNeighbour
from software.software_controller import ControllerNeighbour
from software.software_controller import PatchController


class TestControllerNeighbour(unittest.TestCase):
    """Tests for ControllerNeighbour — simple state tracking."""

    def test_initial_state(self):
        """New neighbour has no ack and not synced."""
        nbr = ControllerNeighbour()
        self.assertFalse(nbr.get_synced())
        self.assertGreater(nbr.get_age(), 0)

    def test_rx_ack_updates_timestamp(self):
        """rx_ack updates last_ack time."""
        nbr = ControllerNeighbour()
        nbr.rx_ack()
        self.assertLessEqual(nbr.get_age(), 1)

    def test_rx_synced_sets_flag(self):
        """rx_synced sets synced to True."""
        nbr = ControllerNeighbour()
        nbr.rx_synced()
        self.assertTrue(nbr.get_synced())

    def test_clear_synced_resets_flag(self):
        """clear_synced resets synced to False."""
        nbr = ControllerNeighbour()
        nbr.rx_synced()
        nbr.clear_synced()
        self.assertFalse(nbr.get_synced())


class TestAgentNeighbour(unittest.TestCase):
    """Tests for AgentNeighbour — agent state tracking."""

    def test_initial_state(self):
        """New agent neighbour has correct defaults."""
        agent = AgentNeighbour("10.10.10.3")
        self.assertEqual(agent.ip, "10.10.10.3")
        self.assertEqual(agent.hostname, "n/a")
        self.assertFalse(agent.out_of_date)
        self.assertFalse(agent.requires_reboot)
        self.assertFalse(agent.patch_failed)
        self.assertEqual(agent.sw_version, "unknown")
        self.assertFalse(agent.is_alive)

    def test_rx_ack_updates_fields(self):
        """rx_ack updates hostname, sw_version, state."""
        agent = AgentNeighbour("10.10.10.3")
        agent.rx_ack("controller-0", False, False, 1, False, "24.09", "idle")
        self.assertEqual(agent.hostname, "controller-0")
        self.assertEqual(agent.sw_version, "24.09")
        self.assertEqual(agent.state, "idle")
        self.assertLessEqual(agent.get_age(), 1)

    def test_rx_ack_detects_out_of_date_change(self):
        """rx_ack logs when out_of_date changes."""
        agent = AgentNeighbour("10.10.10.3")
        agent.rx_ack("worker-0", True, False, 1, False, "24.09", "idle")
        self.assertTrue(agent.out_of_date)
        self.assertFalse(agent.requires_reboot)

    def test_rx_ack_detects_reboot_required_change(self):
        """rx_ack updates requires_reboot flag."""
        agent = AgentNeighbour("10.10.10.3")
        agent.rx_ack("worker-0", False, True, 1, False, "24.09", "idle")
        self.assertTrue(agent.requires_reboot)

    def test_handle_query_detailed_resp_clears_stale(self):
        """handle_query_detailed_resp updates fields and clears stale."""
        agent = AgentNeighbour("10.10.10.3")
        agent.stale = True
        agent.pending_query = True
        agent.handle_query_detailed_resp(
            "commit_abc", "controller", "24.09", ["controller", "worker"], "idle")
        self.assertEqual(agent.latest_sysroot_commit, "commit_abc")
        self.assertEqual(agent.nodetype, "controller")
        self.assertEqual(agent.sw_version, "24.09")
        self.assertEqual(agent.subfunctions, ["controller", "worker"])
        self.assertFalse(agent.stale)
        self.assertFalse(agent.pending_query)

    def test_get_dict_returns_correct_structure(self):
        """get_dict returns proper host info dictionary."""
        agent = AgentNeighbour("10.10.10.3")
        agent.rx_ack("controller-0", False, False, 1, False, "24.09", "idle")
        agent.handle_query_detailed_resp(
            "commit_abc", "controller", "24.09", ["controller"], "idle")
        d = agent.get_dict()
        self.assertEqual(d["ip"], "10.10.10.3")
        self.assertEqual(d["hostname"], "controller-0")
        self.assertTrue(d["deployed"])  # not out_of_date
        self.assertFalse(d["patch_failed"])
        self.assertEqual(d["latest_sysroot_commit"], "commit_abc")

    def test_is_alive_property(self):
        """is_alive property getter/setter works."""
        agent = AgentNeighbour("10.10.10.3")
        self.assertFalse(agent.is_alive)
        agent.is_alive = True
        self.assertTrue(agent.is_alive)


class TestCheckReleasesState(unittest.TestCase):
    """Tests for PatchController.check_releases_state."""

    def _make_controller(self):
        sc = mock.MagicMock()
        sc.check_releases_state = PatchController.check_releases_state.__get__(sc)
        sc.is_available = PatchController.is_available.__get__(sc)
        sc.is_deployed = PatchController.is_deployed.__get__(sc)
        sc.is_committed = PatchController.is_committed.__get__(sc)
        return sc

    def test_all_match_returns_true(self):
        """Returns True when all releases match state."""
        sc = self._make_controller()
        rel1 = mock.MagicMock()
        rel1.state = states.AVAILABLE
        rel2 = mock.MagicMock()
        rel2.state = states.AVAILABLE
        sc.release_collection.get_release_by_id.side_effect = [rel1, rel2]

        result = sc.check_releases_state(["r1", "r2"], states.AVAILABLE)
        self.assertTrue(result)

    def test_one_mismatch_returns_false(self):
        """Returns False when any release doesn't match."""
        sc = self._make_controller()
        rel1 = mock.MagicMock()
        rel1.state = states.AVAILABLE
        rel2 = mock.MagicMock()
        rel2.state = states.DEPLOYED
        sc.release_collection.get_release_by_id.side_effect = [rel1, rel2]

        result = sc.check_releases_state(["r1", "r2"], states.AVAILABLE)
        self.assertFalse(result)

    def test_missing_release_returns_false(self):
        """Returns False when release not found."""
        sc = self._make_controller()
        sc.release_collection.get_release_by_id.return_value = None

        result = sc.check_releases_state(["missing"], states.AVAILABLE)
        self.assertFalse(result)

    def test_is_available_delegates(self):
        """is_available calls check_releases_state with AVAILABLE."""
        sc = self._make_controller()
        rel = mock.MagicMock()
        rel.state = states.AVAILABLE
        sc.release_collection.get_release_by_id.return_value = rel

        self.assertTrue(sc.is_available(["r1"]))

    def test_is_deployed_delegates(self):
        """is_deployed calls check_releases_state with DEPLOYED."""
        sc = self._make_controller()
        rel = mock.MagicMock()
        rel.state = states.DEPLOYED
        sc.release_collection.get_release_by_id.return_value = rel

        self.assertTrue(sc.is_deployed(["r1"]))


class TestGetSoftwareUpgrade(unittest.TestCase):
    """Tests for PatchController._get_software_upgrade."""

    def _make_controller(self):
        sc = mock.MagicMock()
        sc._get_software_upgrade = PatchController._get_software_upgrade.__get__(sc)
        return sc

    def test_no_deploy_returns_none(self):
        """Returns None when no deploys exist."""
        sc = self._make_controller()
        sc.db_api_instance.get_deploy_all.return_value = []
        self.assertIsNone(sc._get_software_upgrade())

    def test_returns_versions_and_state(self):
        """Returns from/to major versions and state."""
        sc = self._make_controller()
        sc.db_api_instance.get_deploy_all.return_value = [{
            "from_release": "24.09.0",
            "to_release": "25.03.0",
            "state": "host",
            "pre_upgrade_deploy": False,
        }]
        result = sc._get_software_upgrade()
        self.assertEqual(result["from_release"], "24.09")
        self.assertEqual(result["to_release"], "25.03")
        self.assertEqual(result["state"], "host")
        self.assertFalse(result["pre_upgrade_deploy"])


class TestCheckUpgradeInProgress(unittest.TestCase):
    """Tests for PatchController.check_upgrade_in_progress."""

    def _make_controller(self):
        sc = mock.MagicMock()
        sc._get_software_upgrade = PatchController._get_software_upgrade.__get__(sc)
        sc.check_upgrade_in_progress = PatchController.check_upgrade_in_progress.__get__(sc)
        return sc

    def test_no_deploy_not_in_progress(self):
        """No deploy means upgrade not in progress."""
        sc = self._make_controller()
        sc.db_api_instance.get_deploy_all.return_value = []
        self.assertFalse(sc.check_upgrade_in_progress())

    def test_same_major_minor_is_patch_not_upgrade(self):
        """Same MM.mm is patch, not upgrade."""
        sc = self._make_controller()
        sc.db_api_instance.get_deploy_all.return_value = [{
            "from_release": "24.09.0",
            "to_release": "24.09.1",
            "state": "host",
            "pre_upgrade_deploy": False,
        }]
        self.assertFalse(sc.check_upgrade_in_progress())

    def test_different_minor_is_upgrade(self):
        """Different minor version is upgrade."""
        sc = self._make_controller()
        sc.db_api_instance.get_deploy_all.return_value = [{
            "from_release": "24.09.0",
            "to_release": "25.03.0",
            "state": "host",
            "pre_upgrade_deploy": False,
        }]
        self.assertTrue(sc.check_upgrade_in_progress())

    def test_pre_upgrade_deploy_is_not_upgrade(self):
        """pre_upgrade_deploy is always patch operation."""
        sc = self._make_controller()
        sc.db_api_instance.get_deploy_all.return_value = [{
            "from_release": "24.09.0",
            "to_release": "25.03.0",
            "state": "host",
            "pre_upgrade_deploy": True,
        }]
        self.assertFalse(sc.check_upgrade_in_progress())


class TestDeployHostList(unittest.TestCase):
    """Tests for PatchController.deploy_host_list."""

    def _make_controller(self):
        sc = mock.MagicMock()
        sc.deploy_host_list = PatchController.deploy_host_list.__get__(sc)
        return sc

    def test_no_deploy_returns_empty(self):
        """Returns empty list when no deploy."""
        sc = self._make_controller()
        sc.db_api_instance.get_deploy_host.return_value = []
        sc.db_api_instance.get_deploy_all.return_value = []
        self.assertEqual(sc.deploy_host_list(), [])

    def test_returns_host_info(self):
        """Returns list of host deploy info."""
        sc = self._make_controller()
        sc.db_api_instance.get_deploy_all.return_value = [{
            "from_release": "24.09.0",
            "to_release": "25.03.0",
            "reboot_required": True,
            "pre_upgrade_deploy": False,
        }]
        sc.db_api_instance.get_deploy_host.return_value = [
            {"hostname": "controller-0", "state": "deployed"},
            {"hostname": "worker-0", "state": "deploying"},
        ]
        result = sc.deploy_host_list()
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["hostname"], "controller-0")
        self.assertEqual(result[0]["software_release"], "24.09.0")
        self.assertEqual(result[0]["target_release"], "25.03.0")
        self.assertEqual(result[0]["host_state"], "deployed")
        self.assertEqual(result[1]["hostname"], "worker-0")
        self.assertEqual(result[1]["host_state"], "deploying")


class TestGetAllSoftwareHostUpgrade(unittest.TestCase):
    """Tests for PatchController.get_all_software_host_upgrade."""

    def _make_controller(self):
        sc = mock.MagicMock()
        sc._get_software_upgrade = PatchController._get_software_upgrade.__get__(sc)
        sc.get_all_software_host_upgrade = PatchController.get_all_software_host_upgrade.__get__(sc)
        sc.get_one_software_host_upgrade = PatchController.get_one_software_host_upgrade.__get__(sc)
        return sc

    def test_no_deploy_returns_none(self):
        """Returns None when no deploy exists."""
        sc = self._make_controller()
        sc.db_api_instance.get_deploy_all.return_value = []
        sc.db_api_instance.get_deploy_host.return_value = []
        self.assertIsNone(sc.get_all_software_host_upgrade())

    def test_deployed_host_shows_to_release_as_current(self):
        """Deployed host has current_sw_version = to_release."""
        sc = self._make_controller()
        sc.db_api_instance.get_deploy_all.return_value = [{
            "from_release": "24.09.0",
            "to_release": "25.03.0",
            "state": "host-done",
            "pre_upgrade_deploy": False,
        }]
        sc.db_api_instance.get_deploy_host.return_value = [
            {"hostname": "controller-0", "state": "deployed"},
        ]
        result = sc.get_all_software_host_upgrade()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["hostname"], "controller-0")
        self.assertEqual(result[0]["current_sw_version"], "25.03")
        self.assertEqual(result[0]["target_sw_version"], "25.03")

    def test_pending_host_shows_from_release_as_current(self):
        """Non-deployed host has current_sw_version = from_release."""
        sc = self._make_controller()
        sc.db_api_instance.get_deploy_all.return_value = [{
            "from_release": "24.09.0",
            "to_release": "25.03.0",
            "state": "host",
            "pre_upgrade_deploy": False,
        }]
        sc.db_api_instance.get_deploy_host.return_value = [
            {"hostname": "worker-0", "state": "pending"},
        ]
        result = sc.get_all_software_host_upgrade()
        self.assertEqual(result[0]["current_sw_version"], "24.09")
        self.assertEqual(result[0]["target_sw_version"], "25.03")

    def test_get_one_host_filters(self):
        """get_one_software_host_upgrade returns only matching host."""
        sc = self._make_controller()
        sc.db_api_instance.get_deploy_all.return_value = [{
            "from_release": "24.09.0",
            "to_release": "25.03.0",
            "state": "host",
            "pre_upgrade_deploy": False,
        }]
        sc.db_api_instance.get_deploy_host.return_value = [
            {"hostname": "controller-0", "state": "deployed"},
            {"hostname": "worker-0", "state": "pending"},
        ]
        result = sc.get_one_software_host_upgrade("worker-0")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["hostname"], "worker-0")

    def test_get_one_host_not_found_returns_none(self):
        """get_one_software_host_upgrade returns None for unknown host."""
        sc = self._make_controller()
        sc.db_api_instance.get_deploy_all.return_value = [{
            "from_release": "24.09.0",
            "to_release": "25.03.0",
            "state": "host",
            "pre_upgrade_deploy": False,
        }]
        sc.db_api_instance.get_deploy_host.return_value = [
            {"hostname": "controller-0", "state": "deployed"},
        ]
        result = sc.get_one_software_host_upgrade("unknown-host")
        self.assertIsNone(result)
