#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for software_controller.py -
utility/helper methods.
"""

import unittest
from unittest.mock import patch

from software.tests import base as test_base  # noqa: F401
from software.tests.test_helpers import create_software_controller  # noqa: E402
from software.software_controller import PatchController


class TestRegisterDeployStateChangeListeners(unittest.TestCase):
    @patch('software.software_controller.ReleaseState')
    @patch('software.software_controller.DeployHostState')
    @patch('software.software_controller.DeployState')
    def test_registers_listeners(self, mock_ds, mock_dhs, mock_rs):
        sc = create_software_controller()
        PatchController.register_deploy_state_change_listeners(sc)
        self.assertTrue(mock_ds.register_event_listener.called)
        self.assertTrue(mock_dhs.register_event_listener.called)
        self.assertTrue(mock_rs.register_event_listener.called)


class TestUpdateConfig(unittest.TestCase):
    @patch('software.software_controller.cfg')
    def test_port_changed(self, mock_cfg):
        sc = create_software_controller()
        mock_cfg.controller_port = 9999
        PatchController.update_config(sc)
        self.assertEqual(sc.port, 9999)

    @patch('software.software_controller.cfg')
    def test_pre_bootstrap(self, mock_cfg):
        sc = create_software_controller()
        sc.pre_bootstrap = True
        mock_cfg.controller_port = 5497
        with patch(
                'software.software_controller.utils.gethostbyname',
                return_value='127.0.0.1'):
            PatchController.update_config(sc)
        self.assertIsNone(sc.mcast_addr)
