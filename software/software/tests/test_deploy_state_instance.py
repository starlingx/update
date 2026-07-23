#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Comprehensive tests for software.deploy_state module."""

import unittest
from unittest import mock

from software.tests import base  # noqa: F401
from software.states import DEPLOY_STATES
from software.exceptions import InvalidOperation
from software.deploy_state import DeployState
from software.deploy_state import require_deploy_state


class TestDeployStateGetInstance(unittest.TestCase):
    """Tests for DeployState singleton."""

    def setUp(self):
        DeployState._instance = None
        DeployState._callbacks = []

    def test_get_instance_creates_singleton(self):
        inst = DeployState.get_instance()
        self.assertIsInstance(inst, DeployState)

    def test_get_instance_returns_same(self):
        inst1 = DeployState.get_instance()
        inst2 = DeployState.get_instance()
        self.assertIs(inst1, inst2)


class TestDeployStateRegisterCallback(unittest.TestCase):
    """Tests for register_event_listener."""

    def setUp(self):
        DeployState._instance = None
        DeployState._callbacks = []

    def test_register_callback(self):
        def callback(_state):
            pass
        DeployState.register_event_listener(callback)
        self.assertIn(callback, DeployState._callbacks)

    def test_register_none_callback(self):
        DeployState.register_event_listener(None)
        self.assertEqual(len(DeployState._callbacks), 0)

    def test_register_duplicate_callback(self):
        def callback(_state):
            pass
        DeployState.register_event_listener(callback)
        DeployState.register_event_listener(callback)
        self.assertEqual(DeployState._callbacks.count(callback), 1)


class TestDeployStateGetDeployState(unittest.TestCase):
    """Tests for get_deploy_state."""

    def setUp(self):
        DeployState._instance = None
        DeployState._callbacks = []

    @mock.patch('software.deploy_state.get_instance')
    def test_no_deploys_returns_none(self, mock_db):
        mock_db.return_value.get_deploy_all.return_value = []
        result = DeployState.get_deploy_state()
        self.assertIsNone(result)

    @mock.patch('software.deploy_state.get_instance')
    def test_returns_state_from_db(self, mock_db):
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'start'}
        ]
        result = DeployState.get_deploy_state()
        self.assertEqual(result, DEPLOY_STATES.START)


class TestDeployStateCheckTransition(unittest.TestCase):
    """Tests for check_transition."""

    def setUp(self):
        DeployState._instance = None
        DeployState._callbacks = []

    @mock.patch('software.deploy_state.get_instance')
    def test_valid_transition(self, mock_db):
        mock_db.return_value.get_deploy_all.return_value = []
        ds = DeployState()
        self.assertTrue(ds.check_transition(DEPLOY_STATES.START))

    @mock.patch('software.deploy_state.get_instance')
    def test_invalid_transition(self, mock_db):
        mock_db.return_value.get_deploy_all.return_value = []
        ds = DeployState()
        self.assertFalse(ds.check_transition(DEPLOY_STATES.COMPLETED))

    @mock.patch('software.deploy_state.get_instance')
    def test_reentrant_transition(self, mock_db):
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'start-done'}
        ]
        ds = DeployState()
        self.assertTrue(ds.check_transition(DEPLOY_STATES.START_DONE))

    @mock.patch('software.deploy_state.get_instance')
    def test_non_reentrant_same_state(self, mock_db):
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'start'}
        ]
        ds = DeployState()
        self.assertFalse(ds.check_transition(DEPLOY_STATES.START))


class TestDeployStateTransform(unittest.TestCase):
    """Tests for transform method."""

    def setUp(self):
        DeployState._instance = None
        DeployState._callbacks = []

    @mock.patch('software.deploy_state.get_instance')
    def test_invalid_transform_raises(self, mock_db):
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'start'}
        ]
        ds = DeployState()
        with self.assertRaises(InvalidOperation):
            ds.transform(DEPLOY_STATES.COMPLETED)

    @mock.patch('software.deploy_state.get_instance')
    def test_transform_to_none_invalid(self, mock_db):
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'start'}
        ]
        ds = DeployState()
        with self.assertRaises(InvalidOperation):
            ds.transform(None)


class TestRequireDeployState(unittest.TestCase):
    """Tests for require_deploy_state decorator."""

    def setUp(self):
        DeployState._instance = None
        DeployState._callbacks = []

    @mock.patch('software.deploy_state.DeployState.get_deploy_state')
    def test_allowed_state(self, mock_get):
        mock_get.return_value = DEPLOY_STATES.HOST_DONE

        @require_deploy_state([DEPLOY_STATES.HOST_DONE],
                              "Not allowed: {state}")
        def my_func():
            return "ok"

        self.assertEqual(my_func(), "ok")

    @mock.patch('software.deploy_state.DeployState.get_deploy_state')
    def test_disallowed_state(self, mock_get):
        mock_get.return_value = DEPLOY_STATES.START

        @require_deploy_state([DEPLOY_STATES.HOST_DONE],
                              "Not allowed: {state} require {require_states}")
        def my_func():
            return "ok"

        with self.assertRaises(InvalidOperation):
            my_func()

    @mock.patch('software.deploy_state.DeployState.get_deploy_state')
    def test_none_state_in_require(self, mock_get):
        mock_get.return_value = None

        @require_deploy_state([None], "")
        def my_func():
            return "ok"

        self.assertEqual(my_func(), "ok")
