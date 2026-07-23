#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Comprehensive tests for parsable_error.py,
dc_utils.py, software_worker.py.
"""

import json
import os
import tempfile
import unittest
from unittest import mock

from keystoneauth1 import exceptions

from software.dc_utils import get_subcloud_groupby_version
from software.dc_utils import get_subclouds_from_dcmanager
from software.dc_utils import get_token_endpoint
from software.dc_utils import rest_api_request
from software.parsable_error import ParsableErrorMiddleware
from software.software_worker import SoftwareWorker
from software.tests import base  # noqa: F401


class TestParsableErrorMiddleware(unittest.TestCase):
    """Tests for ParsableErrorMiddleware."""

    def _make_middleware(self, app_status='200 OK', app_body=None):
        if app_body is None:
            app_body = [b'ok']

        def fake_app(_environ, start_response):
            start_response(app_status, [('Content-Type', 'text/plain'),
                                        ('Content-Length', '2')])
            return app_body

        return ParsableErrorMiddleware(fake_app)

    def test_success_passthrough(self):
        mw = self._make_middleware('200 OK', [b'ok'])
        environ = {'REQUEST_METHOD': 'GET', 'PATH_INFO': '/'}
        result = mw(environ, mock.Mock())
        self.assertEqual(result, [b'ok'])

    def test_error_json_response(self):
        mw = self._make_middleware('500 Internal Server Error',
                                   [b'error message'])
        environ = {
            'REQUEST_METHOD': 'GET',
            'PATH_INFO': '/',
            'HTTP_ACCEPT': 'application/json',
        }
        captured = {}

        def start_response(status, headers, _exc_info=None):
            captured['status'] = status
            captured['headers'] = headers

        result = mw(environ, start_response)
        self.assertTrue(len(result) > 0)

    def test_error_xml_response(self):
        mw = self._make_middleware('404 Not Found', [b'not found'])
        environ = {
            'REQUEST_METHOD': 'GET',
            'PATH_INFO': '/',
            'HTTP_ACCEPT': 'application/json',
        }

        def start_response(_status, _headers, _exc_info=None):
            pass

        result = mw(environ, start_response)
        self.assertTrue(len(result) > 0)

    def test_error_with_webob_separator(self):
        body = b'Some error<br /><br />Detailed explanation here'
        mw = self._make_middleware('400 Bad Request', [body])
        environ = {
            'REQUEST_METHOD': 'POST',
            'PATH_INFO': '/v1/deploy',
            'HTTP_ACCEPT': 'application/json',
        }

        def start_response(_status, _headers, _exc_info=None):
            pass

        result = mw(environ, start_response)
        self.assertTrue(len(result) > 0)
        parsed = json.loads(result[0])
        self.assertIn('error_message', parsed)

    def test_3xx_passthrough(self):
        mw = self._make_middleware('301 Moved', [b'redirect'])
        environ = {'REQUEST_METHOD': 'GET', 'PATH_INFO': '/'}
        result = mw(environ, mock.Mock())
        self.assertEqual(result, [b'redirect'])


class TestDcUtilsGetTokenEndpoint(unittest.TestCase):
    """Tests for dc_utils.get_token_endpoint."""

    @mock.patch('software.dc_utils.session.Session')
    @mock.patch('software.dc_utils.identity.Password')
    @mock.patch('software.dc_utils.CONF')
    def test_success(self, mock_conf, _mock_auth, mock_sess):
        mock_conf.get.return_value = mock.Mock(
            auth_url='http://keystone:5000/v3',
            username='admin',
            password='pass',
            project_name='admin',
            user_domain_name='Default',
            project_domain_name='Default',
            region_name='RegionOne'
        )
        mock_sess.return_value.get_token.return_value = 'token123'
        mock_sess.return_value.get_endpoint.return_value = 'http://endpoint'
        token, endpoint = get_token_endpoint('dcmanager')
        self.assertEqual(token, 'token123')
        self.assertEqual(endpoint, 'http://endpoint')

    @mock.patch('software.dc_utils.session.Session')
    @mock.patch('software.dc_utils.identity.Password')
    @mock.patch('software.dc_utils.CONF')
    def test_unauthorized(self, mock_conf, _mock_auth, mock_sess):
        mock_conf.get.return_value = mock.Mock(
            auth_url='http://keystone:5000/v3',
            username='admin',
            password='pass',
            project_name='admin',
            user_domain_name='Default',
            project_domain_name='Default',
            region_name='RegionOne'
        )
        mock_sess.return_value.get_token.side_effect = \
            exceptions.http.Unauthorized()
        with self.assertRaises(Exception):  # noqa: H202
            get_token_endpoint('dcmanager')

    @mock.patch('software.dc_utils.session.Session')
    @mock.patch('software.dc_utils.identity.Password')
    @mock.patch('software.dc_utils.CONF')
    def test_generic_error(self, mock_conf, _mock_auth, mock_sess):
        mock_conf.get.return_value = mock.Mock(
            auth_url='http://keystone:5000/v3',
            username='admin',
            password='pass',
            project_name='admin',
            user_domain_name='Default',
            project_domain_name='Default',
            region_name='RegionOne'
        )
        mock_sess.return_value.get_token.side_effect = Exception("conn err")
        with self.assertRaises(Exception):  # noqa: H202
            get_token_endpoint('dcmanager')


class TestDcUtilsRestApiRequest(unittest.TestCase):
    """Tests for dc_utils.rest_api_request."""

    @mock.patch('software.dc_utils.six_req.urlopen')
    def test_success(self, mock_urlopen):
        mock_resp = mock.Mock()
        mock_resp.read.return_value = b'{"result": "ok"}'
        mock_urlopen.return_value = mock_resp
        result = rest_api_request('token', 'GET', 'http://api/v1/test')
        self.assertEqual(result, {"result": "ok"})

    @mock.patch('software.dc_utils.six_req.urlopen')
    def test_empty_response(self, mock_urlopen):
        mock_resp = mock.Mock()
        mock_resp.read.return_value = b'{}'
        mock_urlopen.return_value = mock_resp
        result = rest_api_request('token', 'GET', 'http://api/v1/test')
        self.assertEqual(result, {})

    @mock.patch('software.dc_utils.six_req.urlopen')
    def test_with_payload(self, mock_urlopen):
        mock_resp = mock.Mock()
        mock_resp.read.return_value = b'{"ok": true}'
        mock_urlopen.return_value = mock_resp
        result = rest_api_request('token', 'POST', 'http://api/v1/test',
                                  api_cmd_payload='{"data": 1}')
        self.assertEqual(result, {"ok": True})

    @mock.patch('software.dc_utils.six_req.urlopen')
    def test_no_token(self, mock_urlopen):
        mock_resp = mock.Mock()
        mock_resp.read.return_value = b'{"ok": true}'
        mock_urlopen.return_value = mock_resp
        result = rest_api_request(None, 'GET', 'http://api/v1/test')
        self.assertEqual(result, {"ok": True})


class TestDcUtilsGetSubclouds(unittest.TestCase):
    """Tests for get_subclouds_from_dcmanager."""

    @mock.patch('software.dc_utils.rest_api_request')
    @mock.patch('software.dc_utils.get_token_endpoint')
    def test_success(self, mock_gte, mock_req):
        mock_gte.return_value = ('token', 'http://dcmanager')
        mock_req.return_value = {'subclouds': [{'name': 'sc1'}]}
        result = get_subclouds_from_dcmanager()
        self.assertEqual(result, [{'name': 'sc1'}])

    @mock.patch('software.dc_utils.rest_api_request')
    @mock.patch('software.dc_utils.get_token_endpoint')
    def test_bad_response(self, mock_gte, mock_req):
        mock_gte.return_value = ('token', 'http://dcmanager')
        mock_req.return_value = {'error': 'bad'}
        with self.assertRaises(Exception):  # noqa: H202
            get_subclouds_from_dcmanager()


class TestDcUtilsGroupByVersion(unittest.TestCase):
    """Tests for get_subcloud_groupby_version."""

    @mock.patch('software.dc_utils.get_subclouds_from_dcmanager')
    def test_grouping(self, mock_get):
        mock_get.return_value = [
            {'software-version': '24.09.1'},
            {'software-version': '24.09.2'},
            {'software-version': '25.03.0'},
        ]
        result = get_subcloud_groupby_version()
        self.assertIn('24.09', result)
        self.assertIn('25.03', result)
        self.assertEqual(len(result['24.09']), 2)


class TestSoftwareWorkerStatic(unittest.TestCase):
    """Tests for SoftwareWorker static methods."""

    def test_get_key_empty(self):
        self.assertEqual(SoftwareWorker._get_key({}), 1)

    def test_get_key_with_data(self):
        self.assertEqual(SoftwareWorker._get_key({'1': {}, '2': {}}), 3)

    def test_suppress_text_no_match(self):
        self.assertEqual(SoftwareWorker._suppress_text("ls -la"), "ls -la")

    def test_suppress_text_password(self):
        result = SoftwareWorker._suppress_text("cmd password=secret123 other")
        self.assertNotIn("secret123", result)
        self.assertIn("xxxxxxx", result)

    def test_join_stdout_stderr(self):
        output = [
            {"type": "stdout", "output": "line1\n"},
            {"type": "stderr", "output": "err1\n"},
            {"type": "stdout", "output": "line2\n"},
        ]
        stdout, stderr = SoftwareWorker._join_stdout_stderr(output)
        self.assertEqual(stdout, "line1\nline2\n")
        self.assertEqual(stderr, "err1\n")


class TestSoftwareWorkerInit(unittest.TestCase):
    """Tests for SoftwareWorker constructor and file ops."""

    @mock.patch('software.software_worker.os.makedirs')
    def test_init(self, _mock_makedirs):
        with mock.patch.object(SoftwareWorker, '_read_file', return_value={}):
            sw = SoftwareWorker("rel-1", "stage-1")
            self.assertEqual(sw._release, "rel-1")
            self.assertEqual(sw._stage, "stage-1")
            self.assertEqual(sw._run, "1")

    @mock.patch('software.software_worker.os.makedirs')
    def test_read_file_not_found(self, _mock_makedirs):
        sw = SoftwareWorker.__new__(SoftwareWorker)
        sw._filename = "/nonexistent/file.json"
        result = sw._read_file()
        self.assertEqual(result, {})

    @mock.patch('software.software_worker.os.makedirs')
    def test_write_and_read(self, _mock_makedirs):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json',
                                         delete=False) as f:
            tmpfile = f.name
        try:
            sw = SoftwareWorker.__new__(SoftwareWorker)
            sw._filename = tmpfile
            sw._run = "1"
            sw._write_file("op1", "ls -la", 0, "output")
            result = sw._read_file()
            self.assertIn("1", result)
            self.assertIn("op1", result["1"])
        finally:
            os.unlink(tmpfile)

    @mock.patch('software.software_worker.os.makedirs')
    def test_run_func_success(self, _mock_makedirs):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json',
                                         delete=False) as f:
            tmpfile = f.name
        try:
            sw = SoftwareWorker.__new__(SoftwareWorker)
            sw._filename = tmpfile
            sw._run = "1"

            def my_func(value):
                return value * 2

            result = sw.run_func("op1", my_func, 5)
            self.assertEqual(result, 10)
        finally:
            os.unlink(tmpfile)

    @mock.patch('software.software_worker.os.makedirs')
    def test_run_func_failure(self, _mock_makedirs):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json',
                                         delete=False) as f:
            tmpfile = f.name
        try:
            sw = SoftwareWorker.__new__(SoftwareWorker)
            sw._filename = tmpfile
            sw._run = "1"

            def bad_func():
                raise ValueError("boom")

            with self.assertRaises(ValueError):
                sw.run_func("op1", bad_func)
        finally:
            os.unlink(tmpfile)
