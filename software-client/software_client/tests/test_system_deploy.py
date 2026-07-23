#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for v1.client, v1.system_deploy,
and v1.system_deploy_shell modules.
"""

# pylint: disable=unused-argument,protected-access
import unittest
from unittest.mock import MagicMock
from unittest.mock import patch


class TestV1Client(unittest.TestCase):
    """Verify v1.Client wires up sub-managers."""

    def test_init_creates_managers(self):
        """Ensure Client sets release, deploy,
        and system_deploy managers.
        """
        from software_client.v1.client import Client
        mock_http = MagicMock()
        client = Client(mock_http)
        self.assertIs(client.http_client, mock_http)
        self.assertIsNotNone(client.release)
        self.assertIsNotNone(client.deploy)
        self.assertIsNotNone(client.system_deploy)


class TestSystemDeploy(unittest.TestCase):
    """Tests for SystemDeploy resource."""

    def test_repr(self):
        """Verify __repr__ includes info dict."""
        from software_client.v1.system_deploy import SystemDeploy
        resource = SystemDeploy(
            MagicMock(), {"id": "deploy-1"}
        )
        result = repr(resource)
        self.assertIn("system_deploy", result)


class TestSystemDeployManager(unittest.TestCase):
    """Tests for SystemDeployManager API calls."""

    def setUp(self):
        """Set up manager with mocked http client."""
        from software_client.v1.system_deploy import SystemDeployManager
        self.mock_http = MagicMock()
        self.manager = SystemDeployManager(self.mock_http)

    def test_init_without_kube_version(self):
        """Verify init posts to correct path."""
        args = MagicMock()
        args.release_id = "stx-10.0"
        del args.kube_version
        self.manager._post = MagicMock(
            return_value=("resp", "data")
        )
        self.manager.init(args)
        self.manager._post.assert_called_once_with(
            "/v1/system_deploy/stx-10.0/init", body={}
        )

    def test_init_with_kube_version(self):
        """Verify init includes kube_version in body."""
        args = MagicMock()
        args.release_id = "stx-10.0"
        args.kube_version = "v1.28.4"
        self.manager._post = MagicMock(
            return_value=("resp", "data")
        )
        self.manager.init(args)
        self.manager._post.assert_called_once_with(
            "/v1/system_deploy/stx-10.0/init",
            body={"kube_version": "v1.28.4"},
        )

    def test_show(self):
        """Verify show calls _list on correct path."""
        args = MagicMock()
        self.manager._list = MagicMock(
            return_value=("resp", [])
        )
        self.manager.show(args)
        self.manager._list.assert_called_once_with(
            "/v1/system_deploy"
        )


class TestSystemDeployShellInit(unittest.TestCase):
    """Tests for system_deploy_shell.do_init."""

    @patch('software_client.common.utils.check_rc',
           return_value=0)
    @patch('software_client.common.utils.display_info')
    def test_do_init_success(self, mock_display,
                             mock_check):
        """Verify do_init calls init and display_info."""
        from software_client.v1 import system_deploy_shell
        mock_cc = MagicMock()
        mock_cc.system_deploy.init.return_value = (
            MagicMock(status_code=200), {}
        )
        args = MagicMock()
        args.debug = False
        args.kube_version = None
        result = system_deploy_shell.do_init(
            mock_cc, args
        )
        mock_cc.system_deploy.init.assert_called_once()
        self.assertEqual(result, 0)

    @patch('software_client.common.utils.check_rc',
           return_value=0)
    @patch('software_client.common.utils.display_info')
    @patch('software_client.common.utils'
           '.print_result_debug')
    def test_do_init_debug(self, mock_debug,
                           mock_display, mock_check):
        """Verify do_init calls print_result_debug."""
        from software_client.v1 import system_deploy_shell
        mock_cc = MagicMock()
        resp = MagicMock(status_code=200)
        mock_cc.system_deploy.init.return_value = (
            resp, {}
        )
        args = MagicMock()
        args.debug = True
        args.kube_version = None
        system_deploy_shell.do_init(mock_cc, args)
        mock_debug.assert_called_once_with(resp, {})


class TestSystemDeployShellShow(unittest.TestCase):
    """Tests for system_deploy_shell.do_show."""

    @patch('software_client.common.utils.check_rc',
           return_value=0)
    @patch('builtins.print')
    def test_do_show_empty(self, mock_print,
                           mock_check):
        """Verify do_show prints message when empty."""
        from software_client.v1 import system_deploy_shell
        mock_cc = MagicMock()
        mock_cc.system_deploy.show.return_value = (
            MagicMock(status_code=200), []
        )
        args = MagicMock()
        args.debug = False
        result = system_deploy_shell.do_show(
            mock_cc, args
        )
        mock_print.assert_called_with(
            "No system deploy in progress."
        )
        self.assertEqual(result, 0)

    @patch('software_client.common.utils.check_rc',
           return_value=0)
    @patch('software_client.common.utils'
           '.display_result_list')
    def test_do_show_with_data(self, mock_display,
                               mock_check):
        """Verify do_show displays result list."""
        from software_client.v1 import system_deploy_shell
        mock_cc = MagicMock()
        deploy_data = [{"id": "1", "state": "active"}]
        mock_cc.system_deploy.show.return_value = (
            MagicMock(status_code=200), deploy_data
        )
        args = MagicMock()
        args.debug = False
        result = system_deploy_shell.do_show(
            mock_cc, args
        )
        mock_display.assert_called_once()
        self.assertEqual(result, 0)

    @patch('software_client.common.utils.check_rc',
           return_value=1)
    def test_do_show_error(self, mock_check):
        """Verify do_show returns error code."""
        from software_client.v1 import system_deploy_shell
        mock_cc = MagicMock()
        mock_cc.system_deploy.show.return_value = (
            MagicMock(status_code=500), {}
        )
        args = MagicMock()
        args.debug = False
        result = system_deploy_shell.do_show(
            mock_cc, args
        )
        self.assertEqual(result, 1)
