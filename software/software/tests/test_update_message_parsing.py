#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for message decoding, ostree output parsing, and dependency resolution.

These test real logic with proper boundary mocking:
- decode() methods: ZERO mocks — pure data parsing
- ostree functions: mock subprocess only, assert parsed output
- dependency resolution: mock release_collection, assert graph traversal
"""

import subprocess
import unittest
from unittest import mock

from software.tests import base  # noqa: F401
from software import messages
from software.states import DEPLOY_STATES
from software.states import DEPLOY_HOST_STATES
from software.software_controller import PatchController
from software.software_controller import PatchMessageHelloAgentAck
from software.software_controller import PatchMessageQueryDetailedResp
from software.software_controller import SWMessageDeployStateChanged
from software.exceptions import OSTreeCommandFail
from software.exceptions import SoftwareServiceError
from software.ostree_utils import get_ostree_latest_commit


class TestPatchMessageHelloAgentAckDecode(unittest.TestCase):
    """Tests for PatchMessageHelloAgentAck.decode() — pure data parsing."""

    def test_decodes_all_fields(self):
        """All fields decoded from message data."""
        msg = PatchMessageHelloAgentAck()
        msg.decode({
            'msgtype': messages.PATCHMSG_HELLO_AGENT_ACK,
            'msgversion': 1,
            'query_id': 42,
            'out_of_date': True,
            'hostname': 'controller-0',
            'requires_reboot': True,
            'patch_failed': False,
            'sw_version': '24.09.1',
            'state': 'idle',
        })
        self.assertEqual(msg.query_id, 42)
        self.assertTrue(msg.agent_out_of_date)
        self.assertEqual(msg.agent_hostname, 'controller-0')
        self.assertTrue(msg.agent_requires_reboot)
        self.assertFalse(msg.agent_patch_failed)
        self.assertEqual(msg.agent_sw_version, '24.09.1')
        self.assertEqual(msg.agent_state, 'idle')

    def test_missing_fields_keep_defaults(self):
        """Missing fields retain default values."""
        msg = PatchMessageHelloAgentAck()
        msg.decode({'msgtype': messages.PATCHMSG_HELLO_AGENT_ACK, 'msgversion': 1})
        self.assertEqual(msg.query_id, 0)
        self.assertFalse(msg.agent_out_of_date)
        self.assertEqual(msg.agent_hostname, 'n/a')
        self.assertFalse(msg.agent_requires_reboot)
        self.assertEqual(msg.agent_sw_version, 'unknown')

    def test_partial_fields(self):
        """Only provided fields are updated."""
        msg = PatchMessageHelloAgentAck()
        msg.decode({
            'msgtype': messages.PATCHMSG_HELLO_AGENT_ACK,
            'msgversion': 1,
            'hostname': 'worker-0',
            'sw_version': '25.03.0',
        })
        self.assertEqual(msg.agent_hostname, 'worker-0')
        self.assertEqual(msg.agent_sw_version, '25.03.0')
        self.assertEqual(msg.query_id, 0)  # not provided, keeps default


class TestPatchMessageQueryDetailedRespDecode(unittest.TestCase):
    """Tests for PatchMessageQueryDetailedResp.decode() — pure data parsing."""

    def test_decodes_all_fields(self):
        """All fields decoded from response data."""
        msg = PatchMessageQueryDetailedResp()
        msg.decode({
            'msgtype': messages.PATCHMSG_QUERY_DETAILED_RESP,
            'msgversion': 1,
            'latest_sysroot_commit': 'abc123def456',
            'nodetype': 'controller',
            'sw_version': '24.09.0',
            'subfunctions': ['controller', 'worker'],
            'state': 'idle',
        })
        self.assertEqual(msg.latest_sysroot_commit, 'abc123def456')
        self.assertEqual(msg.nodetype, 'controller')
        self.assertEqual(msg.agent_sw_version, '24.09.0')
        self.assertEqual(msg.subfunctions, ['controller', 'worker'])
        self.assertEqual(msg.agent_state, 'idle')

    def test_missing_fields_keep_defaults(self):
        """Missing fields retain default values."""
        msg = PatchMessageQueryDetailedResp()
        msg.decode({'msgtype': messages.PATCHMSG_QUERY_DETAILED_RESP, 'msgversion': 1})
        self.assertEqual(msg.latest_sysroot_commit, 'unknown')
        self.assertEqual(msg.nodetype, 'unknown')
        self.assertEqual(msg.subfunctions, [])


class TestSWMessageDeployStateChangedDecode(unittest.TestCase):
    """Tests for SWMessageDeployStateChanged.decode() — message validation.

    This has 6+ branches. Zero mocks needed — tests pure parsing logic.
    """

    def test_valid_deploy_state_message(self):
        """Valid deploy-state message is accepted."""
        msg = SWMessageDeployStateChanged()
        msg.decode({
            'msgtype': messages.PATCHMSG_DEPLOY_STATE_CHANGED,
            'msgversion': 1,
            'agent': 'deploy-start',
            'deploy-state': 'start-done',
        })
        self.assertTrue(msg.valid)
        self.assertEqual(msg.agent, 'deploy-start')
        self.assertEqual(msg.deploy_state, DEPLOY_STATES.START_DONE)
        self.assertIsNone(msg.hostname)
        self.assertIsNone(msg.host_state)

    def test_valid_host_state_message(self):
        """Valid host-state message is accepted."""
        msg = SWMessageDeployStateChanged()
        msg.decode({
            'msgtype': messages.PATCHMSG_DEPLOY_STATE_CHANGED,
            'msgversion': 1,
            'agent': 'admin',
            'hostname': 'worker-0',
            'host-state': 'deployed',
        })
        self.assertTrue(msg.valid)
        self.assertEqual(msg.hostname, 'worker-0')
        self.assertEqual(msg.host_state, DEPLOY_HOST_STATES.DEPLOYED)
        self.assertIsNone(msg.deploy_state)

    def test_unknown_agent_invalid(self):
        """Unknown agent makes message invalid."""
        msg = SWMessageDeployStateChanged()
        msg.decode({
            'msgtype': messages.PATCHMSG_DEPLOY_STATE_CHANGED,
            'msgversion': 1,
            'agent': 'bad-agent',
        })
        self.assertFalse(msg.valid)

    def test_missing_agent_invalid(self):
        """Missing agent field makes message invalid."""
        msg = SWMessageDeployStateChanged()
        msg.decode({
            'msgtype': messages.PATCHMSG_DEPLOY_STATE_CHANGED,
            'msgversion': 1,
            'deploy-state': 'start-done',
        })
        self.assertFalse(msg.valid)
        self.assertEqual(msg.agent, 'unknown')

    def test_invalid_deploy_state_value(self):
        """Invalid deploy-state value makes message invalid."""
        msg = SWMessageDeployStateChanged()
        msg.decode({
            'msgtype': messages.PATCHMSG_DEPLOY_STATE_CHANGED,
            'msgversion': 1,
            'agent': 'deploy-start',
            'deploy-state': 'bogus-state',
        })
        self.assertFalse(msg.valid)

    def test_both_deploy_and_host_state_invalid(self):
        """Having both deploy-state AND hostname+host-state is invalid."""
        msg = SWMessageDeployStateChanged()
        msg.decode({
            'msgtype': messages.PATCHMSG_DEPLOY_STATE_CHANGED,
            'msgversion': 1,
            'agent': 'admin',
            'deploy-state': 'start-done',
            'hostname': 'worker-0',
            'host-state': 'deployed',
        })
        self.assertFalse(msg.valid)

    def test_neither_deploy_nor_host_state_invalid(self):
        """Having neither deploy-state nor hostname is invalid."""
        msg = SWMessageDeployStateChanged()
        msg.decode({
            'msgtype': messages.PATCHMSG_DEPLOY_STATE_CHANGED,
            'msgversion': 1,
            'agent': 'deploy-start',
        })
        self.assertFalse(msg.valid)

    def test_empty_deploy_state_invalid(self):
        """Empty string deploy-state is invalid."""
        msg = SWMessageDeployStateChanged()
        msg.decode({
            'msgtype': messages.PATCHMSG_DEPLOY_STATE_CHANGED,
            'msgversion': 1,
            'agent': 'deploy-start',
            'deploy-state': '',
        })
        self.assertFalse(msg.valid)

    def test_all_valid_agents(self):
        """All valid agents are accepted."""
        for agent in ['deploy-start', 'deploy-activate',
                      'deploy-activate-rollback', 'admin']:
            msg = SWMessageDeployStateChanged()
            msg.decode({
                'msgtype': messages.PATCHMSG_DEPLOY_STATE_CHANGED,
                'msgversion': 1,
                'agent': agent,
                'deploy-state': 'start-done',
            })
            self.assertTrue(msg.valid, f"Agent {agent} should be valid")

    def test_all_valid_deploy_states(self):
        """All valid deploy states are accepted."""
        valid_states = ['start-done', 'start-failed', 'activate-done',
                        'activate-failed', 'activate-rollback-done',
                        'activate-rollback-failed', 'host-failed']
        for state in valid_states:
            msg = SWMessageDeployStateChanged()
            msg.decode({
                'msgtype': messages.PATCHMSG_DEPLOY_STATE_CHANGED,
                'msgversion': 1,
                'agent': 'deploy-start',
                'deploy-state': state,
            })
            self.assertTrue(msg.valid, f"State {state} should be valid")


class TestGetOstreeLatestCommit(unittest.TestCase):
    """Tests for get_ostree_latest_commit — mocks subprocess only."""

    @mock.patch('software.ostree_utils.subprocess.run')
    def test_parses_commit_from_output(self, mock_run):
        """Parses the commit hash from ostree log output."""
        mock_run.return_value = mock.MagicMock(
            stdout=b"commit 478bc21c1702b9b667b5a75fac62a3ef9203cc1767cbe95e89dface6dc7f205e\n"
                   b"ContentChecksum:  61fc5bb4398d73027595a4d839daeb\n"
                   b"Date:  2022-04-28 18:58:57 +0000\n"
        )
        result = get_ostree_latest_commit("starlingx", "/var/www/pages/feed/rel-24.09/ostree_repo")
        self.assertEqual(result, "478bc21c1702b9b667b5a75fac62a3ef9203cc1767cbe95e89dface6dc7f205e")

    @mock.patch('software.ostree_utils.subprocess.run',
                side_effect=subprocess.CalledProcessError(1, 'cmd', stderr=b'error'))
    def test_raises_on_command_failure(self, _mock_run):
        """Raises OSTreeCommandFail on subprocess error."""
        with self.assertRaises(OSTreeCommandFail):
            get_ostree_latest_commit("starlingx", "/bad/path")


class TestGetReleaseDependencyList(unittest.TestCase):
    """Tests for PatchController.get_release_dependency_list — recursive graph."""

    def _make_controller(self):
        sc = mock.MagicMock()
        sc.get_release_dependency_list = (
            PatchController.get_release_dependency_list.__get__(sc))
        return sc

    def _make_release(self, requires):
        rel = mock.MagicMock()
        rel.requires_release_ids = requires
        return rel

    def test_no_dependencies(self):
        """Release with no requirements returns empty list."""
        sc = self._make_controller()
        sc.release_collection.get_release_by_id.return_value = self._make_release([])
        result = sc.get_release_dependency_list("R1")
        self.assertEqual(result, [])

    def test_single_dependency(self):
        """Release with one requirement returns it."""
        sc = self._make_controller()
        r2 = self._make_release([])
        r1 = self._make_release(["R2"])
        sc.release_collection.get_release_by_id.side_effect = lambda rid: {
            "R1": r1, "R2": r2
        }[rid]
        result = sc.get_release_dependency_list("R1")
        self.assertEqual(result, ["R2"])

    def test_recursive_dependencies(self):
        """Resolves transitive dependencies: R5 -> R4 -> R3 -> R1."""
        sc = self._make_controller()
        releases = {
            "R5": self._make_release(["R4", "R1"]),
            "R4": self._make_release(["R3", "R1"]),
            "R3": self._make_release(["R1"]),
            "R1": self._make_release([]),
        }
        sc.release_collection.get_release_by_id.side_effect = lambda rid: releases[rid]
        result = sc.get_release_dependency_list("R5")
        # R4, R1 from R5; R3 from R4 (R1 already visited)
        self.assertIn("R4", result)
        self.assertIn("R1", result)
        self.assertIn("R3", result)
        # No duplicates
        self.assertEqual(len(result), len(set(result)))

    def test_preinstalled_patches_skipped(self):
        """Preinstalled patches are not recursed into."""
        sc = self._make_controller()
        releases = {
            "R3": self._make_release(["R2", "R1"]),
            "R2": self._make_release(["R1"]),
            "R1": self._make_release([]),
        }
        sc.release_collection.get_release_by_id.side_effect = lambda rid: releases[rid]
        # R2 is preinstalled, so we don't recurse into it
        result = sc.get_release_dependency_list("R3", preinstalled_patches=["R2"])
        self.assertIn("R2", result)
        self.assertIn("R1", result)
        # R2's dependency R1 is still found via R3's direct dep
        self.assertEqual(len(result), 2)

    def test_missing_release_raises(self):
        """Missing release raises SoftwareServiceError."""
        sc = self._make_controller()
        sc.release_collection.get_release_by_id.return_value = None
        with self.assertRaises(SoftwareServiceError):
            sc.get_release_dependency_list("MISSING")
