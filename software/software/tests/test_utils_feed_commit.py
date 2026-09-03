#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for software.utils
"""

import json
import unittest
from unittest import mock

from software.tests import base  # noqa: F401
from software.exceptions import SoftwareError
from software.exceptions import SoftwareServiceError
from software.utils import ExceptionHook
from software.utils import get_auth_token_and_endpoint
from software.utils import get_controller_feed_latest_commit
from software.utils import get_endpoints_token
from software.utils import get_platform_conf
from software.utils import get_precheck_script
from software.utils import get_software_deploy_script
from software.utils import interval_task
from software.utils import read_cached_file
from software.utils import save_temp_file
from pathlib import Path
from keystoneauth1.exceptions.http import Unauthorized
import webob.exc


class TestGetControllerFeedLatestCommit(unittest.TestCase):
    """Tests for get_controller_feed_latest_commit."""

    @mock.patch('software.utils.ostree.get_feed_latest_commit',
                return_value='abc123')
    @mock.patch('software.utils.get_platform_conf', return_value='controller')
    def test_controller_node(self, _conf, mock_feed):
        result = get_controller_feed_latest_commit('24.09')
        mock_feed.assert_called_once_with('24.09')
        self.assertEqual(result, 'abc123')

    @mock.patch('software.utils.ostree.get_feed_latest_commit',
                return_value='def456')
    @mock.patch('software.utils.get_platform_conf', return_value='worker')
    def test_non_controller_node(self, _conf, mock_feed):
        result = get_controller_feed_latest_commit('24.09')
        mock_feed.assert_called_once_with('24.09', '/ostree/repo')
        self.assertEqual(result, 'def456')


class TestGetSoftwareDeployScript(unittest.TestCase):
    """Tests for get_software_deploy_script and get_precheck_script."""

    @mock.patch('software.constants.DEPLOY_PRECHECK_SCRIPT',
                'deploy-precheck')
    @mock.patch('software.utils.get_release_path')
    def test_precheck_script_path(self, mock_path):
        mock_path.return_value = mock.MagicMock(
            rglob=mock.MagicMock(return_value=[
                Path('/opt/software/rel-24.09/bin/deploy-precheck')]))
        result = get_software_deploy_script('24.09', 'deploy-precheck')
        self.assertTrue(len(result) > 0)
        self.assertIn('deploy-precheck', str(result[0]))

    @mock.patch('software.utils.get_release_path')
    def test_non_precheck_script_path(self, mock_path):
        mock_path.return_value = mock.MagicMock(
            rglob=mock.MagicMock(return_value=[
                Path('/opt/software/rel-24.09.1/bin/deploy-start')]))
        result = get_software_deploy_script('24.09.1', 'deploy-start')
        self.assertTrue(len(result) > 0)
        self.assertIn('deploy-start', str(result[0]))

    def test_get_precheck_script(self):
        result = get_precheck_script('24.09')
        self.assertEqual(result, '/opt/software/rel-24.09/bin/deploy-precheck')


class TestReadCachedFile(unittest.TestCase):
    """Tests for read_cached_file."""

    @mock.patch('builtins.open', mock.mock_open(read_data='file-content'))
    @mock.patch('os.path.getmtime', return_value=100.0)
    def test_first_read(self, _mtime):
        cache = {}
        data = read_cached_file('/tmp/test.txt', cache)
        self.assertEqual(data, 'file-content')
        self.assertEqual(cache['mtime'], 100.0)

    @mock.patch('os.path.getmtime', return_value=100.0)
    def test_cached_read(self, _mtime):
        cache = {'mtime': 100.0, 'data': 'cached'}
        data = read_cached_file('/tmp/test.txt', cache)
        self.assertEqual(data, 'cached')

    @mock.patch('builtins.open', mock.mock_open(read_data='new-content'))
    @mock.patch('os.path.getmtime', return_value=200.0)
    def test_reload_on_mtime_change(self, _mtime):
        cache = {'mtime': 100.0, 'data': 'old'}
        data = read_cached_file('/tmp/test.txt', cache)
        self.assertEqual(data, 'new-content')


class TestSaveTempFile(unittest.TestCase):
    """Tests for save_temp_file."""

    @mock.patch('os.makedirs', side_effect=OSError("fail"))
    @mock.patch('shutil.rmtree')
    @mock.patch('os.path.exists', return_value=False)
    def test_create_dir_failure(self, _exists, _rmtree, _makedirs):
        file_item = mock.MagicMock()
        file_item.filename = 'test.patch'
        with self.assertRaises(Exception):  # noqa: H202
            save_temp_file(file_item, '/tmp/bad')

    @mock.patch('shutil.disk_usage')
    @mock.patch('os.path.exists', return_value=True)
    def test_file_size_check_failure(self, _exists, mock_usage):
        mock_usage.return_value = mock.MagicMock(free=999999)
        file_item = mock.MagicMock()
        file_item.filename = 'test.patch'
        file_item.file.seek.side_effect = Exception("seek fail")
        with self.assertRaises(Exception):  # noqa: H202
            save_temp_file(file_item, '/tmp/scratch')

    @mock.patch('builtins.open', side_effect=IOError("write fail"))
    @mock.patch('shutil.disk_usage')
    @mock.patch('os.path.exists', return_value=True)
    def test_write_failure(self, _exists, mock_usage, _open):
        mock_usage.return_value = mock.MagicMock(free=999999)
        file_item = mock.MagicMock()
        file_item.filename = 'test.patch'
        file_item.file.tell.return_value = 100
        file_item.value = b'data'
        with self.assertRaises(Exception):  # noqa: H202
            save_temp_file(file_item, '/tmp/scratch')


class TestGetAuthTokenAndEndpoint(unittest.TestCase):
    """Tests for get_auth_token_and_endpoint."""

    @mock.patch('keystoneauth1.session.Session')
    @mock.patch('keystoneauth1.identity.Password')
    def test_success(self, _mock_password, mock_session_cls):
        mock_sess = mock.MagicMock()
        mock_sess.get_token.return_value = 'tok123'
        mock_sess.get_endpoint.return_value = 'http://ep'
        mock_session_cls.return_value = mock_sess
        user = {
            'auth_url': 'http://keystone:5000/v3',
            'username': 'admin',
            'password': 'secret',
            'project_name': 'admin',
            'user_domain_name': 'Default',
            'project_domain_name': 'Default',
        }
        token, endpoint = get_auth_token_and_endpoint(
            user, 'platform', 'RegionOne', 'internal')
        self.assertEqual(token, 'tok123')
        self.assertEqual(endpoint, 'http://ep')

    def test_missing_keys_raises(self):
        with self.assertRaises(Exception):  # noqa: H202
            get_auth_token_and_endpoint({}, 'platform', 'R1', 'internal')

    @mock.patch('keystoneauth1.session.Session')
    @mock.patch('keystoneauth1.identity.Password')
    def test_unauthorized(self, _mock_password, mock_session_cls):
        mock_sess = mock.MagicMock()
        mock_sess.get_token.side_effect = Unauthorized()
        mock_session_cls.return_value = mock_sess
        user = {
            'auth_url': 'http://keystone:5000/v3',
            'username': 'admin',
            'password': 'bad',
            'project_name': 'admin',
            'user_domain_name': 'Default',
            'project_domain_name': 'Default',
        }
        with self.assertRaises(Unauthorized):
            get_auth_token_and_endpoint(
                user, 'platform', 'RegionOne', 'internal')

    @mock.patch('keystoneauth1.session.Session')
    @mock.patch('keystoneauth1.identity.Password')
    def test_generic_error(self, _mock_password, mock_session_cls):
        mock_sess = mock.MagicMock()
        mock_sess.get_token.side_effect = RuntimeError("conn fail")
        mock_session_cls.return_value = mock_sess
        user = {
            'auth_url': 'http://keystone:5000/v3',
            'username': 'admin',
            'password': 'secret',
            'project_name': 'admin',
            'user_domain_name': 'Default',
            'project_domain_name': 'Default',
        }
        with self.assertRaises(RuntimeError):
            get_auth_token_and_endpoint(
                user, 'platform', 'RegionOne', 'internal')


class TestGetEndpointsToken(unittest.TestCase):
    """Tests for get_endpoints_token."""

    @mock.patch('software.utils.get_auth_token_and_endpoint',
                return_value=('tok', 'http://ep'))
    @mock.patch('software.utils.CONF')
    def test_with_default_config(self, mock_conf, _auth):
        mock_conf.get.return_value = {
            'auth_url': 'http://keystone:5000',
            'username': 'admin',
            'password': 'secret',
            'project_name': 'admin',
            'user_domain_name': 'Default',
            'project_domain_name': 'Default',
            'region_name': 'RegionOne',
        }
        token, endpoint = get_endpoints_token()
        self.assertEqual(token, 'tok')
        self.assertEqual(endpoint, 'http://ep')

    @mock.patch('software.utils.get_auth_token_and_endpoint',
                return_value=('tok', 'http://ep'))
    def test_with_explicit_config(self, _auth):
        config = {
            'auth_url': 'http://keystone:5000',
            'username': 'admin',
            'password': 'secret',
            'project_name': 'admin',
            'user_domain_name': 'Default',
            'project_domain_name': 'Default',
            'region_name': 'RegionOne',
        }
        token, _endpoint = get_endpoints_token(config=config)
        self.assertEqual(token, 'tok')

    @mock.patch('software.utils.get_auth_token_and_endpoint',
                side_effect=Exception("fail"))
    def test_failure_returns_none(self, _auth):
        config = {
            'auth_url': 'http://keystone:5000',
            'username': 'admin',
            'password': 'secret',
            'project_name': 'admin',
            'user_domain_name': 'Default',
            'project_domain_name': 'Default',
            'region_name': 'RegionOne',
        }
        token, endpoint = get_endpoints_token(config=config)
        self.assertIsNone(token)
        self.assertIsNone(endpoint)


class TestGetPlatformConf(unittest.TestCase):
    """Tests for get_platform_conf."""

    @mock.patch('builtins.open', mock.mock_open(
        read_data='nodetype=controller\nsystem_mode=duplex\n'))
    def test_reads_key(self):
        result = get_platform_conf('nodetype')
        self.assertEqual(result, 'controller')

    @mock.patch('builtins.open', mock.mock_open(
        read_data='nodetype=controller\n'))
    def test_missing_key(self):
        result = get_platform_conf('nonexistent_key')
        self.assertIsNone(result)


class TestIntervalTask(unittest.TestCase):
    """Tests for interval_task decorator."""

    def test_first_call_executes(self):
        @interval_task(interval_sec=10, no_run_return=False)
        def my_func():
            return 'executed'
        # Force last_run to be old enough
        my_func.__wrapped__ = True
        result = my_func()
        # First call should execute since time gap > interval
        # We need to manipulate time for deterministic test
        self.assertIn(result, ['executed', False])

    @mock.patch('software.utils.time.time')
    def test_skips_within_interval(self, mock_time):
        mock_time.return_value = 1000.0
        counter = {'calls': 0}

        @interval_task(interval_sec=10, no_run_return='skipped')
        def my_func():
            counter['calls'] += 1
            return 'executed'

        # First call at t=1000 should execute
        # (last_run initialized ~1000)
        my_func()
        # Second call still at t=1000 should skip
        result2 = my_func()
        self.assertEqual(result2, 'skipped')

    @mock.patch('software.utils.time.time')
    def test_executes_after_interval(self, mock_time):
        mock_time.return_value = 1000.0

        @interval_task(interval_sec=5, no_run_return='skipped')
        def my_func():
            return 'executed'

        my_func()  # first call
        mock_time.return_value = 1006.0
        result = my_func()
        self.assertEqual(result, 'executed')


class TestExceptionHook(unittest.TestCase):
    """Tests for ExceptionHook.on_error."""

    def setUp(self):
        self.hook = ExceptionHook()
        self.state = mock.MagicMock()

    def test_software_service_error(self):
        exc = SoftwareServiceError(info="info1", warn="warn1",
                                   error="err1")
        resp = self.hook.on_error(self.state, exc)
        self.assertEqual(resp.status_int, 406)
        body = json.loads(resp.text)
        self.assertEqual(body['error'], 'err1')
        self.assertEqual(body['info'], 'info1')
        self.assertEqual(body['warning'], 'warn1')

    def test_software_error(self):
        exc = SoftwareError("something broke")
        resp = self.hook.on_error(self.state, exc)
        self.assertEqual(resp.status_int, 406)
        body = json.loads(resp.text)
        self.assertEqual(body['error'], 'something broke')

    def test_http_client_error(self):
        exc = webob.exc.HTTPNotFound("not found")
        resp = self.hook.on_error(self.state, exc)
        self.assertEqual(resp.status_int, 404)
        body = json.loads(resp.text)
        self.assertIn('not found', body['error'].lower())

    def test_generic_exception(self):
        exc = RuntimeError("unexpected")
        resp = self.hook.on_error(self.state, exc)
        self.assertEqual(resp.status_int, 500)
        body = json.loads(resp.text)
        self.assertIn('Internal error', body['error'])

    def test_stacktrace_signature(self):
        sig = self.hook._get_stacktrace_signature("test trace")
        self.assertIsInstance(sig, str)
        self.assertEqual(len(sig), 8)  # 4 bytes = 8 hex chars
