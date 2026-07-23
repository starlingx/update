#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for software.deploy_state,
deploy_host_state, system_deploy_state.
"""

import unittest
from unittest import mock

from software.tests import base  # noqa: F401
from software.states import DEPLOY_HOST_STATES
from software.states import DEPLOY_STATES
from software.states import SYSTEM_DEPLOY_STATES
from software.exceptions import InvalidOperation

from software.deploy_state import deploy_reentrant_states
from software.deploy_state import deploy_state_transition
from software.deploy_state import DeployState
from software.deploy_state import require_deploy_state
from software.deploy_host_state import deploy_host_reentrant_states
from software.deploy_host_state import deploy_host_state_transition
from software.deploy_host_state import DeployHostState
from software.system_deploy_state import system_deploy_state_transition
from software.system_deploy_state import SystemDeployState


class TestDeployStateTransitions(unittest.TestCase):
    """Tests for deploy state transition map."""

    def test_none_to_start(self):
        """Test None -> START is valid."""
        self.assertIn(DEPLOY_STATES.START, deploy_state_transition[None])

    def test_start_transitions(self):
        """Test START transitions."""
        valid = deploy_state_transition[DEPLOY_STATES.START]
        self.assertIn(DEPLOY_STATES.START_DONE, valid)
        self.assertIn(DEPLOY_STATES.START_FAILED, valid)

    def test_start_done_transitions(self):
        """Test START_DONE transitions."""
        valid = deploy_state_transition[DEPLOY_STATES.START_DONE]
        self.assertIn(DEPLOY_STATES.HOST, valid)

    def test_host_transitions(self):
        """Test HOST transitions."""
        valid = deploy_state_transition[DEPLOY_STATES.HOST]
        self.assertIn(DEPLOY_STATES.HOST_DONE, valid)
        self.assertIn(DEPLOY_STATES.HOST_FAILED, valid)
        self.assertIn(DEPLOY_STATES.HOST_ROLLBACK, valid)

    def test_activate_transitions(self):
        """Test ACTIVATE transitions."""
        valid = deploy_state_transition[DEPLOY_STATES.ACTIVATE]
        self.assertIn(DEPLOY_STATES.ACTIVATE_DONE, valid)
        self.assertIn(DEPLOY_STATES.ACTIVATE_FAILED, valid)

    def test_completed_transitions(self):
        """Test COMPLETED transitions."""
        valid = deploy_state_transition[DEPLOY_STATES.COMPLETED]
        self.assertIn(None, valid)
        self.assertIn(DEPLOY_STATES.ACTIVATE_ROLLBACK_PENDING, valid)

    def test_reentrant_states(self):
        """Test reentrant states list."""
        self.assertIn(DEPLOY_STATES.START_DONE, deploy_reentrant_states)
        self.assertIn(DEPLOY_STATES.ACTIVATE_DONE, deploy_reentrant_states)
        self.assertIn(DEPLOY_STATES.ACTIVATE_ROLLBACK_DONE,
                      deploy_reentrant_states)


class TestDeployState(unittest.TestCase):
    """Tests for DeployState class."""

    def setUp(self):
        """Reset singleton and callbacks."""
        DeployState._instance = None
        DeployState._callbacks = []

    def test_get_instance_singleton(self):
        """Test get_instance returns singleton."""
        inst1 = DeployState.get_instance()
        inst2 = DeployState.get_instance()
        self.assertIs(inst1, inst2)

    def test_register_event_listener(self):
        """Test registering event listener."""
        def my_callback(_state):
            pass
        DeployState.register_event_listener(my_callback)
        self.assertIn(my_callback, DeployState._callbacks)

    def test_register_none_listener(self):
        """Test registering None listener is ignored."""
        DeployState.register_event_listener(None)
        self.assertEqual(len(DeployState._callbacks), 0)

    def test_register_duplicate_listener(self):
        """Test duplicate listener not added twice."""
        def my_callback(_state):
            pass
        DeployState.register_event_listener(my_callback)
        DeployState.register_event_listener(my_callback)
        self.assertEqual(len(DeployState._callbacks), 1)

    @mock.patch('software.deploy_state.get_instance')
    def test_get_deploy_state_none(self, mock_db):
        """Test get_deploy_state returns None when no deploys."""
        mock_db.return_value.get_deploy_all.return_value = []
        state = DeployState.get_deploy_state()
        self.assertIsNone(state)

    @mock.patch('software.deploy_state.get_instance')
    def test_get_deploy_state_with_deploy(self, mock_db):
        """Test get_deploy_state returns state."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'start-done'}
        ]
        state = DeployState.get_deploy_state()
        self.assertEqual(state, DEPLOY_STATES.START_DONE)

    @mock.patch('software.deploy_state.get_instance')
    def test_check_transition_valid(self, mock_db):
        """Test valid transition check."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'start'}
        ]
        ds = DeployState()
        self.assertTrue(ds.check_transition(DEPLOY_STATES.START_DONE))

    @mock.patch('software.deploy_state.get_instance')
    def test_check_transition_invalid(self, mock_db):
        """Test invalid transition check."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'start'}
        ]
        ds = DeployState()
        self.assertFalse(ds.check_transition(DEPLOY_STATES.COMPLETED))

    @mock.patch('software.deploy_state.get_instance')
    def test_check_transition_reentrant(self, mock_db):
        """Test reentrant state transition."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'start-done'}
        ]
        ds = DeployState()
        self.assertTrue(ds.check_transition(DEPLOY_STATES.START_DONE))


class TestDeployHostStateTransitions(unittest.TestCase):
    """Tests for deploy host state transition map."""

    def test_pending_transitions(self):
        """Test PENDING transitions."""
        valid = deploy_host_state_transition[DEPLOY_HOST_STATES.PENDING]
        self.assertIn(DEPLOY_HOST_STATES.DEPLOYING, valid)
        self.assertIn(DEPLOY_HOST_STATES.ROLLBACK_DEPLOYED, valid)

    def test_deploying_transitions(self):
        """Test DEPLOYING transitions."""
        valid = deploy_host_state_transition[DEPLOY_HOST_STATES.DEPLOYING]
        self.assertIn(DEPLOY_HOST_STATES.DEPLOYED, valid)
        self.assertIn(DEPLOY_HOST_STATES.FAILED, valid)

    def test_failed_transitions(self):
        """Test FAILED transitions."""
        valid = deploy_host_state_transition[DEPLOY_HOST_STATES.FAILED]
        self.assertIn(DEPLOY_HOST_STATES.DEPLOYING, valid)
        self.assertIn(DEPLOY_HOST_STATES.ROLLBACK_DEPLOYED, valid)

    def test_rollback_deployed_terminal(self):
        """Test ROLLBACK_DEPLOYED is terminal."""
        valid = deploy_host_state_transition[
            DEPLOY_HOST_STATES.ROLLBACK_DEPLOYED]
        self.assertEqual(valid, [])

    def test_reentrant_states(self):
        """Test reentrant states."""
        self.assertIn(DEPLOY_HOST_STATES.FAILED,
                      deploy_host_reentrant_states)
        self.assertIn(DEPLOY_HOST_STATES.ROLLBACK_FAILED,
                      deploy_host_reentrant_states)


class TestDeployHostState(unittest.TestCase):
    """Tests for DeployHostState class."""

    def setUp(self):
        """Reset callbacks."""
        DeployHostState._callbacks = []

    def test_register_event_listener(self):
        """Test registering event listener."""
        def my_callback(_hostname, _state):
            pass
        DeployHostState.register_event_listener(my_callback)
        self.assertIn(my_callback, DeployHostState._callbacks)

    def test_register_duplicate_listener(self):
        """Test duplicate listener not added."""
        def my_callback(_hostname, _state):
            pass
        DeployHostState.register_event_listener(my_callback)
        DeployHostState.register_event_listener(my_callback)
        self.assertEqual(len(DeployHostState._callbacks), 1)

    @mock.patch('software.deploy_host_state.get_instance')
    def test_get_deploy_host_state_none(self, mock_db):
        """Test get state when host not in deployment."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = None
        dhs = DeployHostState("controller-0")
        self.assertIsNone(dhs.get_deploy_host_state())

    @mock.patch('software.deploy_host_state.get_instance')
    def test_get_deploy_host_state(self, mock_db):
        """Test get state returns correct state."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'pending'
        }
        dhs = DeployHostState("controller-0")
        self.assertEqual(dhs.get_deploy_host_state(),
                         DEPLOY_HOST_STATES.PENDING)

    @mock.patch('software.deploy_host_state.get_instance')
    def test_check_transition_valid(self, mock_db):
        """Test valid host transition."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'pending'
        }
        dhs = DeployHostState("controller-0")
        self.assertTrue(
            dhs.check_transition(DEPLOY_HOST_STATES.DEPLOYING))

    @mock.patch('software.deploy_host_state.get_instance')
    def test_check_transition_invalid(self, mock_db):
        """Test invalid host transition."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'pending'
        }
        dhs = DeployHostState("controller-0")
        self.assertFalse(
            dhs.check_transition(DEPLOY_HOST_STATES.DEPLOYED))

    @mock.patch('software.deploy_host_state.get_instance')
    def test_check_transition_reentrant(self, mock_db):
        """Test reentrant host state transition."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'failed'
        }
        dhs = DeployHostState("controller-0")
        self.assertTrue(
            dhs.check_transition(DEPLOY_HOST_STATES.FAILED))

    @mock.patch('software.deploy_host_state.get_instance')
    def test_check_transition_no_host(self, mock_db):
        """Test transition check when host not found."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = None
        dhs = DeployHostState("unknown-host")
        self.assertFalse(
            dhs.check_transition(DEPLOY_HOST_STATES.DEPLOYING))


class TestSystemDeployStateTransitions(unittest.TestCase):
    """Tests for system deploy state transition map."""

    def test_start_transitions(self):
        """Test START transitions."""
        valid = system_deploy_state_transition[SYSTEM_DEPLOY_STATES.START]
        self.assertIn(SYSTEM_DEPLOY_STATES.START_DONE, valid)
        self.assertIn(SYSTEM_DEPLOY_STATES.START_FAILED, valid)


class TestSystemDeployState(unittest.TestCase):
    """Tests for SystemDeployState class."""

    def setUp(self):
        """Reset callbacks."""
        SystemDeployState._callbacks = []

    def test_register_event_listener(self):
        """Test registering event listener."""
        def my_callback(_state):
            pass
        SystemDeployState.register_event_listener(my_callback)
        self.assertIn(my_callback, SystemDeployState._callbacks)

    def test_register_none_listener(self):
        """Test None listener ignored."""
        SystemDeployState.register_event_listener(None)
        self.assertEqual(len(SystemDeployState._callbacks), 0)

    def test_register_duplicate_listener(self):
        """Test duplicate listener not added."""
        def my_callback(_state):
            pass
        SystemDeployState.register_event_listener(my_callback)
        SystemDeployState.register_event_listener(my_callback)
        self.assertEqual(len(SystemDeployState._callbacks), 1)

    @mock.patch('software.system_deploy_state.get_instance')
    def test_get_system_deploy_state_none(self, mock_db):
        """Test get state when no system deploy."""
        mock_db.return_value.get_system_deploy.return_value = None
        state = SystemDeployState.get_system_deploy_state()
        self.assertIsNone(state)

    @mock.patch('software.system_deploy_state.get_instance')
    def test_get_system_deploy_state(self, mock_db):
        """Test get state returns correct state."""
        mock_db.return_value.get_system_deploy.return_value = {
            'state': 'init'
        }
        state = SystemDeployState.get_system_deploy_state()
        self.assertEqual(state, SYSTEM_DEPLOY_STATES.START)

    @mock.patch('software.system_deploy_state.get_instance')
    def test_check_transition_valid(self, mock_db):
        """Test valid system deploy transition."""
        mock_db.return_value.get_system_deploy.return_value = {
            'state': 'init'
        }
        sds = SystemDeployState()
        self.assertTrue(
            sds.check_transition(SYSTEM_DEPLOY_STATES.START_DONE))

    @mock.patch('software.system_deploy_state.get_instance')
    def test_check_transition_invalid(self, mock_db):
        """Test invalid system deploy transition."""
        mock_db.return_value.get_system_deploy.return_value = {
            'state': 'init'
        }
        sds = SystemDeployState()
        # START -> START is not valid
        self.assertFalse(
            sds.check_transition(SYSTEM_DEPLOY_STATES.START))

    @mock.patch('software.system_deploy_state.get_instance')
    def test_check_transition_no_deploy(self, mock_db):
        """Test transition check when no system deploy."""
        mock_db.return_value.get_system_deploy.return_value = None
        sds = SystemDeployState()
        self.assertFalse(
            sds.check_transition(SYSTEM_DEPLOY_STATES.START_DONE))


class TestRequireDeployState(unittest.TestCase):
    """Tests for require_deploy_state decorator."""

    @mock.patch('software.deploy_state.DeployState.get_deploy_state',
                return_value=DEPLOY_STATES.HOST_DONE)
    def test_allowed_state(self, _mock):
        """Test function executes when in allowed state."""
        @require_deploy_state(
            [DEPLOY_STATES.HOST_DONE],
            "Must be in {require_states}")
        def my_func():
            return "ok"
        self.assertEqual(my_func(), "ok")

    @mock.patch('software.deploy_state.DeployState.get_deploy_state',
                return_value=DEPLOY_STATES.START)
    def test_disallowed_state(self, _mock):
        """Test function raises when not in allowed state."""
        @require_deploy_state(
            [DEPLOY_STATES.HOST_DONE],
            "Must be in {require_states}, current: {state}")
        def my_func():
            return "ok"
        with self.assertRaises(InvalidOperation):
            my_func()
