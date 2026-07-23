#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for software.states module.

Only invariants that code depends on are tested here. Assertions that
merely restate a constant's literal value are deliberately absent — they
duplicate the source rather than verifying behaviour.
"""

import unittest

from software.states import AVAILABLE
from software.states import DEPLOY_HOST_STATES
from software.states import DEPLOY_STATES
from software.states import DEPLOYED
from software.states import DEPLOYING
from software.states import INTERRUPTION_RECOVERY_STATES
from software.states import RELEASE_STATE_VALID_TRANSITION
from software.states import REMOVING
from software.states import UNAVAILABLE
from software.states import VALID_HOST_DEPLOY_STATE


class TestReleaseStateTransitions(unittest.TestCase):
    """The release state transition map encodes which state changes are
    legal. Removing an entry here would silently break deployments.
    """

    def test_available_can_start_deploying(self):
        """AVAILABLE -> DEPLOYING must be permitted."""
        self.assertIn(DEPLOYING, RELEASE_STATE_VALID_TRANSITION[AVAILABLE])

    def test_deploying_can_complete_or_revert(self):
        """DEPLOYING must be able to reach DEPLOYED or fall back to AVAILABLE."""
        valid = RELEASE_STATE_VALID_TRANSITION[DEPLOYING]
        self.assertIn(DEPLOYED, valid)
        self.assertIn(AVAILABLE, valid)

    def test_deployed_can_be_removed_or_superseded(self):
        """DEPLOYED must be able to reach REMOVING or UNAVAILABLE."""
        valid = RELEASE_STATE_VALID_TRANSITION[DEPLOYED]
        self.assertIn(REMOVING, valid)
        self.assertIn(UNAVAILABLE, valid)


class TestValidHostDeployState(unittest.TestCase):
    """VALID_HOST_DEPLOY_STATE gates host state validation."""

    def test_core_states_are_valid(self):
        """The non-rollback host states must all be accepted."""
        for state in (DEPLOY_HOST_STATES.PENDING,
                      DEPLOY_HOST_STATES.DEPLOYING,
                      DEPLOY_HOST_STATES.DEPLOYED,
                      DEPLOY_HOST_STATES.FAILED):
            self.assertIn(state, VALID_HOST_DEPLOY_STATE)

    def test_rollback_states_are_valid(self):
        """The rollback host states must all be accepted."""
        for state in (DEPLOY_HOST_STATES.ROLLBACK_PENDING,
                      DEPLOY_HOST_STATES.ROLLBACK_DEPLOYING,
                      DEPLOY_HOST_STATES.ROLLBACK_DEPLOYED,
                      DEPLOY_HOST_STATES.ROLLBACK_FAILED):
            self.assertIn(state, VALID_HOST_DEPLOY_STATE)


class TestInterruptionRecoveryStates(unittest.TestCase):
    """INTERRUPTION_RECOVERY_STATES drives set_interruption_fail_state():
    only deploys caught in these states are failed after an interruption.
    """

    def test_in_progress_states_are_recoverable(self):
        """Every in-progress state must be marked for interruption recovery."""
        for state in (DEPLOY_STATES.START,
                      DEPLOY_STATES.HOST,
                      DEPLOY_STATES.HOST_ROLLBACK,
                      DEPLOY_STATES.ACTIVATE,
                      DEPLOY_STATES.ACTIVATE_ROLLBACK):
            self.assertIn(state, INTERRUPTION_RECOVERY_STATES)

    def test_terminal_states_are_not_recoverable(self):
        """Completed deploys must not be failed by interruption recovery."""
        self.assertNotIn(DEPLOY_STATES.COMPLETED,
                         INTERRUPTION_RECOVERY_STATES)
        self.assertNotIn(DEPLOY_STATES.START_DONE,
                         INTERRUPTION_RECOVERY_STATES)
