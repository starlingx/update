#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from software import dc_utils
import json
from unittest.mock import MagicMock
from unittest.mock import patch
import unittest
from software.tests import base  # noqa: F401
from keystoneauth1 import exceptions


class TestGetTokenEndpoint(unittest.TestCase):
    @patch('software.dc_utils.session.Session')
    @patch('software.dc_utils.identity.Password')
    @patch('software.dc_utils.CONF')
    def test_success(self, mock_conf, _mock_password, mock_session_cls):
        mock_conf.get.return_value = MagicMock(
            auth_url='http://keystone:5000/v3',
            username='admin', password='pass',
            project_name='admin',
            user_domain_name='Default',
            project_domain_name='Default',
            region_name='RegionOne'
        )
        mock_sess = MagicMock()
        mock_sess.get_token.return_value = 'token123'
        mock_sess.get_endpoint.return_value = 'http://endpoint'
        mock_session_cls.return_value = mock_sess

        token, endpoint = dc_utils.get_token_endpoint("dcmanager")
        self.assertEqual(token, 'token123')
        self.assertEqual(endpoint, 'http://endpoint')

    @patch('software.dc_utils.session.Session')
    @patch('software.dc_utils.identity.Password')
    @patch('software.dc_utils.CONF')
    def test_unauthorized(self, mock_conf, _mock_password, mock_session_cls):
        mock_conf.get.return_value = MagicMock(
            auth_url='http://keystone:5000/v3',
            username='admin', password='bad',
            project_name='admin',
            user_domain_name='Default',
            project_domain_name='Default',
            region_name='RegionOne'
        )
        mock_sess = MagicMock()
        mock_sess.get_token.side_effect = exceptions.http.Unauthorized()
        mock_session_cls.return_value = mock_sess

        with self.assertRaises(Exception) as ctx:  # noqa: H202
            dc_utils.get_token_endpoint("dcmanager")
        self.assertIn("unauthorized", str(ctx.exception).lower())

    @patch('software.dc_utils.session.Session')
    @patch('software.dc_utils.identity.Password')
    @patch('software.dc_utils.CONF')
    def test_generic_error(self, mock_conf, _mock_password, mock_session_cls):
        mock_conf.get.return_value = MagicMock(
            auth_url='http://keystone:5000/v3',
            username='admin', password='pass',
            project_name='admin',
            user_domain_name='Default',
            project_domain_name='Default',
            region_name='RegionOne'
        )
        mock_sess = MagicMock()
        mock_sess.get_token.side_effect = Exception("connection refused")
        mock_session_cls.return_value = mock_sess

        with self.assertRaises(Exception):  # noqa: H202
            dc_utils.get_token_endpoint("dcmanager")


class TestRestApiRequest(unittest.TestCase):
    @patch('software.dc_utils.six_req.urlopen')
    def test_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"result": "ok"}).encode()
        mock_urlopen.return_value = mock_resp

        result = dc_utils.rest_api_request("token", "GET", "http://api/cmd")
        self.assertEqual(result, {"result": "ok"})

    @patch('software.dc_utils.six_req.urlopen')
    def test_with_payload(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({}).encode()
        mock_urlopen.return_value = mock_resp

        result = dc_utils.rest_api_request("token", "POST", "http://api/cmd",
                                           api_cmd_payload='{"key": "val"}')
        self.assertEqual(result, {})

    @patch('software.dc_utils.six_req.urlopen')
    def test_empty_response(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = ""
        mock_urlopen.return_value = mock_resp

        result = dc_utils.rest_api_request("token", "GET", "http://api/cmd")
        self.assertEqual(result, {})

    @patch('software.dc_utils.six_req.urlopen')
    def test_no_token(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"ok": True}).encode()
        mock_urlopen.return_value = mock_resp

        result = dc_utils.rest_api_request(None, "GET", "http://api/cmd")
        self.assertEqual(result, {"ok": True})


class TestGetSubcloudsFromDcmanager(unittest.TestCase):
    @patch('software.dc_utils.rest_api_request')
    @patch('software.dc_utils.get_token_endpoint')
    def test_success(self, mock_get_token, mock_rest):
        mock_get_token.return_value = ("token", "http://dcmanager")
        mock_rest.return_value = {"subclouds": [
            {"name": "sc1"}, {"name": "sc2"}]}

        result = dc_utils.get_subclouds_from_dcmanager()
        self.assertEqual(len(result), 2)

    @patch('software.dc_utils.rest_api_request')
    @patch('software.dc_utils.get_token_endpoint')
    def test_bad_response(self, mock_get_token, mock_rest):
        mock_get_token.return_value = ("token", "http://dcmanager")
        mock_rest.return_value = {"error": "bad"}

        with self.assertRaises(Exception):  # noqa: H202
            dc_utils.get_subclouds_from_dcmanager()


class TestGetSubcloudGroupbyVersion(unittest.TestCase):
    @patch('software.dc_utils.get_subclouds_from_dcmanager')
    def test_groups_by_version(self, mock_get):
        mock_get.return_value = [
            {"name": "sc1", "software-version": "24.09.1"},
            {"name": "sc2", "software-version": "24.09.2"},
            {"name": "sc3", "software-version": "25.03.1"},
        ]
        result = dc_utils.get_subcloud_groupby_version()
        self.assertIn("24.09", result)
        self.assertIn("25.03", result)
        self.assertEqual(len(result["24.09"]), 2)
        self.assertEqual(len(result["25.03"]), 1)
