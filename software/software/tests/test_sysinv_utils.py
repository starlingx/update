#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2025 Wind River Systems, Inc.
#

import unittest
from unittest.mock import MagicMock
from unittest.mock import patch

from software.sysinv_utils import trigger_vim_host_audit


class TestSysinvUtils(unittest.TestCase):
    HOSTNAME = "test-host"
    HOST_UUID = "test-uuid"

    def setUp(self):
        # Create shared mock host
        self.mock_host = MagicMock()
        self.mock_host.hostname = self.HOSTNAME
        self.mock_host.uuid = self.HOST_UUID

    @patch("software.sysinv_utils.utils.get_endpoints_token")
    @patch("software.sysinv_utils.get_sysinv_client")
    @patch("software.sysinv_utils.get_ihost_list")
    def test_trigger_vim_host_audit(
        self, mock_get_ihost_list, mock_get_sysinv_client, mock_get_endpoints_token
    ):
        mock_sysinv_client = MagicMock()
        mock_get_sysinv_client.return_value = mock_sysinv_client
        mock_sysinv_client.ihost.get.return_value = self.mock_host
        mock_get_endpoints_token.return_value = ("fake_token", "fake_endpoint")
        mock_get_ihost_list.return_value = [self.mock_host]

        trigger_vim_host_audit(self.HOSTNAME)

        mock_get_endpoints_token.assert_called_once()
        mock_get_sysinv_client.assert_called_once_with(
            token="fake_token", endpoint="fake_endpoint"
        )
        mock_sysinv_client.ihost.get.assert_called_once_with(self.HOSTNAME)
        mock_sysinv_client.ihost.vim_host_audit.assert_called_once_with(self.HOST_UUID)

    @patch("software.sysinv_utils.utils.get_endpoints_token")
    @patch("software.sysinv_utils.get_sysinv_client")
    @patch("software.sysinv_utils.get_ihost_list")
    def test_trigger_vim_host_audit_sysinv_call_fails(
        self, mock_get_ihost_list, mock_get_sysinv_client, mock_get_endpoints_token
    ):
        mock_sysinv_client = MagicMock()
        mock_get_sysinv_client.return_value = mock_sysinv_client
        mock_get_endpoints_token.return_value = ("fake_token", "fake_endpoint")
        mock_get_ihost_list.return_value = [self.mock_host]

        # Configure vim_host_audit to raise an exception
        mock_sysinv_client.ihost.vim_host_audit.side_effect = Exception(
            "VIM audit failed"
        )

        msg = "Failed to trigger VIM host audit: VIM audit failed"
        with self.assertRaises(Exception, msg=msg):  # noqa: H202
            trigger_vim_host_audit(self.HOSTNAME)
