#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for software.utilities.deploy_action module."""

import unittest
from unittest import mock

from software.states import DEPLOY_STATES
from software.tests import base as test_base  # noqa: F401
from software.utilities.deploy_action import do_action
from software.utilities.utils import ACTION_ACTIVATE
from software.utilities.utils import ACTION_ACTIVATE_ROLLBACK
from software.utilities.utils import ACTION_DELETE

# Patch where the names are looked up, not where they are defined.
DA_EXEC = 'software.utilities.deploy_action.execute_migration_scripts'
DA_STATE = 'software.utilities.deploy_action.update_deploy_state'
DA_MAJOR = 'software.utilities.deploy_action.utils.get_major_release_version'


class TestDoActivate(unittest.TestCase):
    """Tests for do_action with ACTION_ACTIVATE."""

    @mock.patch(DA_STATE)
    @mock.patch(DA_MAJOR,
                side_effect=lambda version: '.'.join(version.split('.')[:2]))
    @mock.patch(DA_EXEC)
    def test_major_release_success(self, mock_exec, _mock_major, mock_state):
        """Test successful major release activate."""
        result = do_action('10.0.1', '11.0.0', True, action=ACTION_ACTIVATE)
        self.assertTrue(result)
        mock_exec.assert_called_once_with('10.0', '11.0', ACTION_ACTIVATE)
        mock_state.assert_called_once_with(
            'deploy-activate',
            deploy_state=DEPLOY_STATES.ACTIVATE_DONE.value)

    @mock.patch(DA_STATE, side_effect=Exception('state fail'))
    @mock.patch(DA_EXEC)
    def test_update_state_failure(self, _mock_exec, _mock_state):
        """Test activate returns False when
        update_deploy_state fails.
        """
        result = do_action('10.0.1', '10.0.2', False, action=ACTION_ACTIVATE)
        self.assertFalse(result)


class TestDoActivateRollback(unittest.TestCase):
    """Tests for do_action with ACTION_ACTIVATE_ROLLBACK."""

    @mock.patch(DA_STATE)
    @mock.patch(DA_MAJOR,
                side_effect=lambda version: '.'.join(version.split('.')[:2]))
    @mock.patch(DA_EXEC)
    def test_success(self, mock_exec, _mock_major, mock_state):
        """Test successful activate rollback."""
        result = do_action('10.0.1', '10.0.2', True,
                           action=ACTION_ACTIVATE_ROLLBACK)
        self.assertTrue(result)
        mock_exec.assert_called_once_with(
            '10.0', '10.0', ACTION_ACTIVATE_ROLLBACK)
        mock_state.assert_called_once_with(
            'deploy-activate-rollback',
            deploy_state=DEPLOY_STATES.ACTIVATE_ROLLBACK_DONE.value)

    @mock.patch(DA_STATE)
    @mock.patch(DA_EXEC, side_effect=Exception('fail'))
    def test_migration_failure(self, _mock_exec, mock_state):
        """Test rollback returns False when migration fails."""
        result = do_action('10.0.1', '11.0.0', True,
                           action=ACTION_ACTIVATE_ROLLBACK)
        self.assertFalse(result)
        mock_state.assert_called_once_with(
            'deploy-activate-rollback',
            deploy_state=DEPLOY_STATES.ACTIVATE_ROLLBACK_FAILED.value)

    @mock.patch(DA_STATE, side_effect=Exception('state fail'))
    @mock.patch(DA_EXEC)
    def test_update_state_failure(self, _mock_exec, _mock_state):
        """Test rollback returns False when
        update_deploy_state fails.
        """
        result = do_action('10.0.1', '10.0.2', False,
                           action=ACTION_ACTIVATE_ROLLBACK)
        self.assertFalse(result)


class TestDoDeployDelete(unittest.TestCase):
    """Tests for do_action with ACTION_DELETE."""

    @mock.patch(DA_EXEC)
    def test_non_major_release_returns_true(self, mock_exec):
        """Test non-major release with no metapackages returns True
        without calling scripts.
        """
        result = do_action('10.0.1', '10.0.2', False, action=ACTION_DELETE)
        self.assertTrue(result)
        mock_exec.assert_not_called()

    @mock.patch(DA_EXEC)
    def test_major_release_custom_plugin_path(self, mock_exec):
        """Test major release with metapackages runs per-metapackage."""
        do_action('10.0', '11.0', True,
                  metapackages=['my-meta'],
                  action=ACTION_DELETE)
        mock_exec.assert_called_once_with(
            '10.0', '11.0', 'delete',
            migration_script_dir='/opt/software/releases/11.0/my-meta/upgrade-scripts'
        )
        call_args = mock_exec.call_args
        self.assertEqual(call_args[0][0], '10.0')
        self.assertEqual(call_args[0][1], '11.0')
        self.assertEqual(call_args[0][2], ACTION_DELETE)

    @mock.patch(DA_EXEC, side_effect=Exception('fail'))
    def test_migration_failure(self, _mock_exec):
        """Test deploy delete handles migration failure gracefully."""
        result = do_action('10.0', '11.0', True, action=ACTION_DELETE)
        self.assertFalse(result)
