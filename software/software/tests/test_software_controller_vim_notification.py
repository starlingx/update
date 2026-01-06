#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2025 Wind River Systems, Inc.
#

import unittest
from unittest.mock import MagicMock
from unittest.mock import patch

from software.software_controller import PatchController
from software.states import DEPLOY_STATES

# This import has to be first
from software.tests import base  # pylint: disable=unused-import # noqa: F401


class TestSoftwareControllerVimNotification(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    @patch("software.software_controller.PatchController.__init__", return_value=None)
    @patch("software.software_controller.trigger_vim_host_audit")
    @patch("socket.gethostname", return_value="controller-0")
    def test_notify_vim_on_state_change_supported_states(
        self, mock_gethostname, mock_trigger_vim_host_audit, mock_init
    ):  # pylint: disable=unused-argument
        """Test that VIM is notified for supported states."""
        controller = PatchController()
        controller.pre_bootstrap = False

        # Test all supported states
        supported_states = [
            DEPLOY_STATES.START_DONE,
            DEPLOY_STATES.START_FAILED,
            DEPLOY_STATES.ACTIVATE_DONE,
            DEPLOY_STATES.ACTIVATE_FAILED,
            DEPLOY_STATES.ACTIVATE_ROLLBACK_DONE,
            DEPLOY_STATES.ACTIVATE_ROLLBACK_FAILED,
        ]

        for state in supported_states:
            mock_trigger_vim_host_audit.reset_mock()
            # pylint: disable=protected-access
            controller._notify_vim_on_state_change(state)
            mock_gethostname.assert_called_with()
            mock_trigger_vim_host_audit.assert_called_once_with("controller-0")

    @patch("software.software_controller.PatchController.__init__", return_value=None)
    @patch("software.software_controller.trigger_vim_host_audit")
    @patch("socket.gethostname")
    def test_notify_vim_on_state_change_unsupported_states(
        self, mock_gethostname, mock_trigger_vim_host_audit, mock_init
    ):  # pylint: disable=unused-argument
        """Test that VIM is not notified for unsupported states."""
        controller = PatchController()
        controller.pre_bootstrap = False

        # Test some unsupported states
        unsupported_states = [
            "HELLO?",
            DEPLOY_STATES.START,
            DEPLOY_STATES.ACTIVATE,
        ]

        for state in unsupported_states:
            # pylint: disable=protected-access
            controller._notify_vim_on_state_change(state)
            mock_gethostname.assert_not_called()
            mock_trigger_vim_host_audit.assert_not_called()

    @patch("software.software_controller.PatchController.__init__", return_value=None)
    @patch("software.software_controller.DeployState")
    def test_register_deploy_state_change_listeners(
        self, mock_deploy_state, mock_init
    ):  # pylint: disable=unused-argument
        """Test that the VIM notification listener is registered."""
        controller = PatchController()

        # Mock other methods that are called during registration
        controller._state_changed_sync = MagicMock()  # pylint: disable=protected-access
        # pylint: disable=protected-access
        controller._state_changed_notify = MagicMock()
        controller.create_clean_up_deployment_alarm = MagicMock()

        # Call the method
        controller.register_deploy_state_change_listeners()

        # Verify that _notify_vim_on_state_change is registered as a listener
        # pylint: disable=protected-access
        mock_deploy_state.register_event_listener.assert_any_call(
            controller._notify_vim_on_state_change
        )

    @patch("software.software_controller.PatchController.__init__", return_value=None)
    @patch("software.software_controller.trigger_vim_host_audit")
    @patch("socket.gethostname")
    def test_notify_vim_on_state_change_prebootstrap(
        self, mock_gethostname, mock_trigger_vim_host_audit, mock_init
    ):  # pylint: disable=unused-argument
        """Test that VIM is not notified during prebootstrap."""
        controller = PatchController()
        controller.pre_bootstrap = True

        # pylint: disable=protected-access
        controller._notify_vim_on_state_change(DEPLOY_STATES.START_DONE)
        mock_gethostname.assert_not_called()
        mock_trigger_vim_host_audit.assert_not_called()
