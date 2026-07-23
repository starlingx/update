#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for software.utilities.deploy_set_failed module."""

import unittest
from unittest import mock

from software.tests import base as test_base  # noqa: F401
from software.states import DEPLOY_STATES
from software.states import DEPLOY_HOST_STATES
from software.utilities import deploy_set_failed
from software.utilities.deploy_set_failed import acknowledge_operation
from software.utilities.deploy_set_failed import start_set_fail


class TestDeploySetFailedConstants(unittest.TestCase):
    """Test module-level constants from deploy_set_failed."""

    def test_next_operation_keys(self):
        """Test next_operation has expected keys."""
        self.assertIn(DEPLOY_STATES.START_FAILED.value,
                      deploy_set_failed.next_operation)
        self.assertIn(DEPLOY_STATES.HOST_FAILED.value,
                      deploy_set_failed.next_operation)
        self.assertIn(DEPLOY_STATES.ACTIVATE_FAILED.value,
                      deploy_set_failed.next_operation)

    def test_required_hostname_states(self):
        """Test required_hostname_deploy_states."""
        self.assertIn(DEPLOY_STATES.HOST.value,
                      deploy_set_failed.required_hostname_deploy_states)
        self.assertIn(DEPLOY_STATES.HOST_DONE.value,
                      deploy_set_failed.required_hostname_deploy_states)


class TestGetCurrentDeployState(unittest.TestCase):
    """Tests for get_current_deploy_state."""

    @mock.patch('software.utilities.deploy_set_failed.get_instance')
    def test_returns_state(self, mock_db):
        """Test returns deploy state."""
        get_current_deploy_state = deploy_set_failed.get_current_deploy_state
        mock_db.return_value.get_current_deploy.return_value = {
            'state': 'host'}
        result = get_current_deploy_state()
        self.assertEqual(result, 'host')

    @mock.patch('software.utilities.deploy_set_failed.get_instance')
    def test_no_deploy_exits(self, mock_db):
        """Test exits when no deployment."""
        get_current_deploy_state = deploy_set_failed.get_current_deploy_state
        mock_db.return_value.get_current_deploy.return_value = None
        with self.assertRaises(SystemExit):
            get_current_deploy_state()


class TestAcknowledgeOperation(unittest.TestCase):
    """Tests for acknowledge_operation."""

    @mock.patch(
        'software.utilities.deploy_set_failed'
        '.get_current_deploy_state',
        return_value='host')
    @mock.patch('builtins.input', return_value='no')
    def test_confirm_no_exits(self, _mock_input, _mock_state):
        """Test user declines exits."""
        with self.assertRaises(SystemExit):
            acknowledge_operation(False)


class TestGetDeployHostFailFunction(unittest.TestCase):
    """Tests for get_deploy_host_fail_function."""

    def test_deploying_state(self):
        """Test returns failed func for deploying state."""
        get_deploy_host_fail_function = (
            deploy_set_failed
            .get_deploy_host_fail_function)
        mock_host = mock.MagicMock()
        mock_host.get_deploy_host_state.return_value = \
            DEPLOY_HOST_STATES.DEPLOYING
        result = get_deploy_host_fail_function(mock_host)
        self.assertEqual(result, mock_host.failed)

    def test_no_state_exits(self):
        """Test exits when no deploy host state."""
        get_deploy_host_fail_function = (
            deploy_set_failed
            .get_deploy_host_fail_function)
        mock_host = mock.MagicMock()
        mock_host.get_deploy_host_state.return_value = None
        with self.assertRaises(SystemExit):
            get_deploy_host_fail_function(mock_host)

    def test_invalid_state_exits(self):
        """Test exits for non-faileable state."""
        get_deploy_host_fail_function = (
            deploy_set_failed
            .get_deploy_host_fail_function)
        mock_host = mock.MagicMock()
        mock_host.get_deploy_host_state.return_value = \
            DEPLOY_HOST_STATES.PENDING
        with self.assertRaises(SystemExit):
            get_deploy_host_fail_function(mock_host)


class TestStartSetFail(unittest.TestCase):
    """Tests for start_set_fail."""

    @mock.patch(
        'software.utilities.deploy_set_failed'
        '.get_current_deploy_state',
        return_value='start-failed')
    @mock.patch('software.utilities.deploy_set_failed.is_active_controller',
                return_value=False)
    def test_not_active_controller_exits(self, _mock_ctrl, _mock_state):
        """Test exits when not active controller."""
        with self.assertRaises(SystemExit):
            start_set_fail(True, None)

    @mock.patch(
        'software.utilities.deploy_set_failed'
        '.get_current_deploy_state',
        return_value='completed')
    @mock.patch('software.utilities.deploy_set_failed.is_active_controller',
                return_value=True)
    @mock.patch('software.utilities.deploy_set_failed.DeployState.'
                'get_instance')
    def test_invalid_state_exits(self, _mock_ds, _mock_ctrl, _mock_state):
        """Test exits for state with no fail function."""
        with self.assertRaises(SystemExit):
            start_set_fail(True, None)

    @mock.patch('software.utilities.deploy_set_failed.'
                'get_current_deploy_state')
    @mock.patch('software.utilities.deploy_set_failed.is_active_controller',
                return_value=True)
    @mock.patch('software.utilities.deploy_set_failed.DeployState.'
                'get_instance')
    def test_host_state_no_hostname_exits(self, _mock_ds, _mock_ctrl,
                                          mock_state):
        """Test exits when host state but no hostname."""
        mock_state.return_value = 'host'
        with self.assertRaises(SystemExit):
            start_set_fail(True, None)
