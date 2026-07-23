#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Comprehensive tests for deploy_host_state and system_deploy_state."""

import unittest
from unittest import mock

from software.tests import base  # noqa: F401
from software.states import DEPLOY_HOST_STATES
from software.states import SYSTEM_DEPLOY_STATES
from software.exceptions import InvalidOperation
from software.deploy_host_state import DeployHostState
from software.deploy_host_state import deploy_host_state_transition
from software.deploy_host_state import deploy_host_reentrant_states
from software.system_deploy_state import system_deploy_state_transition


class TestDeployHostStateTransitionMap(unittest.TestCase):
    """Tests for deploy_host_state_transition map."""

    def test_pending_transitions(self):
        valid = deploy_host_state_transition[DEPLOY_HOST_STATES.PENDING]
        self.assertIn(DEPLOY_HOST_STATES.DEPLOYING, valid)
        self.assertIn(DEPLOY_HOST_STATES.ROLLBACK_DEPLOYED, valid)

    def test_deploying_transitions(self):
        valid = deploy_host_state_transition[DEPLOY_HOST_STATES.DEPLOYING]
        self.assertIn(DEPLOY_HOST_STATES.DEPLOYED, valid)
        self.assertIn(DEPLOY_HOST_STATES.FAILED, valid)

    def test_rollback_deployed_is_terminal(self):
        self.assertEqual(
            deploy_host_state_transition
            [DEPLOY_HOST_STATES.ROLLBACK_DEPLOYED],
            [])

    def test_reentrant_states(self):
        self.assertIn(DEPLOY_HOST_STATES.FAILED, deploy_host_reentrant_states)
        self.assertIn(DEPLOY_HOST_STATES.ROLLBACK_FAILED,
                      deploy_host_reentrant_states)


class TestDeployHostStateRegister(unittest.TestCase):
    """Tests for DeployHostState.register_event_listener."""

    def setUp(self):
        DeployHostState._callbacks = []

    def test_register(self):
        def callback(_hostname, _state):
            pass
        DeployHostState.register_event_listener(callback)
        self.assertIn(callback, DeployHostState._callbacks)

    def test_register_duplicate(self):
        def callback(_hostname, _state):
            pass
        DeployHostState.register_event_listener(callback)
        DeployHostState.register_event_listener(callback)
        self.assertEqual(DeployHostState._callbacks.count(callback), 1)


class TestDeployHostStateGetState(unittest.TestCase):
    """Tests for get_deploy_host_state."""

    def setUp(self):
        DeployHostState._callbacks = []

    @mock.patch('software.deploy_host_state.get_instance')
    def test_returns_state(self, mock_db):
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'pending'
        }
        dhs = DeployHostState("host1")
        self.assertEqual(dhs.get_deploy_host_state(),
                         DEPLOY_HOST_STATES.PENDING)

    @mock.patch('software.deploy_host_state.get_instance')
    def test_returns_none_if_not_found(self, mock_db):
        mock_db.return_value.get_deploy_host_by_hostname.return_value = None
        dhs = DeployHostState("host1")
        self.assertIsNone(dhs.get_deploy_host_state())


class TestDeployHostStateCheckTransition(unittest.TestCase):
    """Tests for check_transition."""

    def setUp(self):
        DeployHostState._callbacks = []

    @mock.patch('software.deploy_host_state.get_instance')
    def test_valid_transition(self, mock_db):
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'pending'
        }
        dhs = DeployHostState("host1")
        self.assertTrue(dhs.check_transition(DEPLOY_HOST_STATES.DEPLOYING))

    @mock.patch('software.deploy_host_state.get_instance')
    def test_invalid_transition(self, mock_db):
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'pending'
        }
        dhs = DeployHostState("host1")
        self.assertFalse(dhs.check_transition(DEPLOY_HOST_STATES.DEPLOYED))

    @mock.patch('software.deploy_host_state.get_instance')
    def test_reentrant_failed(self, mock_db):
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'failed'
        }
        dhs = DeployHostState("host1")
        self.assertTrue(dhs.check_transition(DEPLOY_HOST_STATES.FAILED))

    @mock.patch('software.deploy_host_state.get_instance')
    def test_host_not_in_deployment(self, mock_db):
        mock_db.return_value.get_deploy_host_by_hostname.return_value = None
        dhs = DeployHostState("host1")
        self.assertFalse(dhs.check_transition(DEPLOY_HOST_STATES.DEPLOYING))


class TestDeployHostStateTransform(unittest.TestCase):
    """Tests for transform."""

    def setUp(self):
        DeployHostState._callbacks = []

    @mock.patch('software.deploy_host_state.get_instance')
    def test_valid_transform(self, mock_db):
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'pending'
        }
        call_log = []

        def callback(hostname, state):
            call_log.append((hostname, state))

        DeployHostState._callbacks = [callback]
        dhs = DeployHostState("host1")
        dhs.transform(DEPLOY_HOST_STATES.DEPLOYING)
        mock_db.return_value.update_deploy_host.assert_called_once_with(
            "host1", DEPLOY_HOST_STATES.DEPLOYING)
        self.assertEqual(call_log, [("host1", DEPLOY_HOST_STATES.DEPLOYING)])

    @mock.patch('software.deploy_host_state.get_instance')
    def test_invalid_transform_raises(self, mock_db):
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'pending'
        }
        dhs = DeployHostState("host1")
        with self.assertRaises(InvalidOperation):
            dhs.transform(DEPLOY_HOST_STATES.DEPLOYED)
        mock_db.return_value.end_update.assert_called_once()


class TestSystemDeployStateTransitionMap(unittest.TestCase):
    """Tests for system_deploy_state_transition."""

    def test_start_transitions(self):
        valid = system_deploy_state_transition[SYSTEM_DEPLOY_STATES.START]
        self.assertIn(SYSTEM_DEPLOY_STATES.START_DONE, valid)
        self.assertIn(SYSTEM_DEPLOY_STATES.START_FAILED, valid)
