#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import unittest
from unittest.mock import patch
from unittest.mock import MagicMock

from software.tests import base as test_base  # noqa: F401
from software.authapi.policy import authorize
from software.db.api import SoftwareAPI
from software.software_functions import ReleaseData


class TestAuthPolicy(unittest.TestCase):
    """Tests for authapi.policy.authorize."""

    @patch('software.authapi.policy._ENFORCER')
    @patch('software.authapi.policy.init')
    def test_authorize(self, _mock_init, mock_enforcer):
        mock_enforcer.authorize.return_value = True
        result = authorize("rule", {}, {})
        self.assertTrue(result)


class TestDbApiReverseDeploy(unittest.TestCase):
    """Tests for SoftwareAPI.reverse_deploy."""

    def test_reverse_deploy(self):
        api = SoftwareAPI.__new__(SoftwareAPI)
        api.deploy_handler = MagicMock()
        api.begin_update = MagicMock()
        api.end_update = MagicMock()
        api.get_current_deploy = MagicMock(return_value={
            'from_release': '24.09', 'to_release': '25.03'
        })
        api.reverse_deploy("/feed", "commit1")
        args = api.deploy_handler.update.call_args
        self.assertEqual(args[1]['from_release'], '25.03')
        self.assertEqual(args[1]['to_release'], '24.09')


class TestDbApiGetDeployHost(unittest.TestCase):
    """Tests for SoftwareAPI deploy host methods."""

    def test_get_deploy_host(self):
        api = SoftwareAPI.__new__(SoftwareAPI)
        api.deploy_host_handler = MagicMock()
        api.deploy_host_handler.query_all.return_value = [{"hostname": "c0"}]
        result = api.get_deploy_host()
        self.assertEqual(len(result), 1)

    def test_get_deploy_host_by_hostname(self):
        api = SoftwareAPI.__new__(SoftwareAPI)
        api.deploy_host_handler = MagicMock()
        api.deploy_host_handler.query_by_hostname.return_value = {
            "hostname": "c0"}
        result = api.get_deploy_host_by_hostname("c0")
        self.assertIsNotNone(result)


class TestDbApiDeployAll(unittest.TestCase):
    """Tests for SoftwareAPI.get_deploy_all."""

    def test_get_deploy_all(self):
        api = SoftwareAPI.__new__(SoftwareAPI)
        api.deploy_handler = MagicMock()
        api.deploy_handler.query_all.return_value = [{"state": "start"}]
        result = api.get_deploy_all()
        self.assertEqual(len(result), 1)


class TestReleaseDataQueryLine(unittest.TestCase):
    """Tests for ReleaseData edge cases."""

    def test_query_line_missing_key(self):
        rd = ReleaseData()
        rd.metadata = {"P1": {"sw_version": "24.09"}}
        result = rd.query_line("P1", "nonexistent")
        self.assertIsNone(result)
