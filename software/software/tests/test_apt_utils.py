#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Comprehensive tests for apt_utils.py,
release_signing.py, plugin.py, base.py.
"""

import os
import subprocess
import tempfile
import unittest
from unittest import mock

from software.tests import base as test_base  # noqa: F401
from software.exceptions import APTOSTreeCommandFail
from software.apt_utils import initialize_apt_ostree
from software.apt_utils import package_list_upload
from software.apt_utils import package_remove
from software.apt_utils import component_remove
from software.apt_utils import run_install
from software.apt_utils import run_rollback
from software.release_signing import sign_files
from software.plugin import DeployPluginRunner
from software.base import PatchService


class TestAptUtilsInitialize(unittest.TestCase):
    """Tests for apt_utils.initialize_apt_ostree."""

    @mock.patch('subprocess.run',
                side_effect=subprocess.CalledProcessError(1,
                                                          'cmd',
                                                          stderr=b'err'))
    def test_failure(self, _mock_run):
        with self.assertRaises(APTOSTreeCommandFail):
            initialize_apt_ostree("/feed/dir")


class TestAptUtilsPackageListUpload(unittest.TestCase):
    """Tests for apt_utils.package_list_upload."""

    @mock.patch('subprocess.run',
                side_effect=subprocess.CalledProcessError(1,
                                                          'cmd',
                                                          stderr=b'err'))
    def test_failure(self, _mock_run):
        with self.assertRaises(APTOSTreeCommandFail):
            package_list_upload("/feed", "24.09.1", ["pkg1.deb"])


class TestAptUtilsPackageRemove(unittest.TestCase):
    """Tests for apt_utils.package_remove."""

    @mock.patch('subprocess.run')
    def test_success(self, mock_run):
        package_remove("/feed", "24.09.1", ["pkg1", "pkg2"])
        self.assertEqual(mock_run.call_count, 2)

    @mock.patch('subprocess.run',
                side_effect=subprocess.CalledProcessError(
                    1, 'cmd', stderr=b'other error'))
    def test_other_error(self, _mock_run):
        with self.assertRaises(APTOSTreeCommandFail):
            package_remove("/feed", "24.09.1", ["pkg1"])


class TestAptUtilsComponentRemove(unittest.TestCase):
    """Tests for apt_utils.component_remove."""

    @mock.patch('subprocess.run',
                side_effect=subprocess.CalledProcessError(1,
                                                          'cmd',
                                                          stderr=b'err'))
    def test_failure(self, _mock_run):
        with self.assertRaises(APTOSTreeCommandFail):
            component_remove("/feed", "24.09.1")


class TestAptUtilsRunInstall(unittest.TestCase):
    """Tests for apt_utils.run_install."""

    @mock.patch('subprocess.run',
                side_effect=subprocess.CalledProcessError(1,
                                                          'cmd',
                                                          stderr=b'err'))
    def test_failure(self, _mock_run):
        with self.assertRaises(APTOSTreeCommandFail):
            run_install("/repo", "24.09", "24.09.1", ["pkg1"])


class TestAptUtilsRunRollback(unittest.TestCase):
    """Tests for apt_utils.run_rollback."""

    @mock.patch('subprocess.run',
                side_effect=subprocess.CalledProcessError(1,
                                                          'cmd',
                                                          stderr=b'err'))
    def test_failure(self, _mock_run):
        with self.assertRaises(APTOSTreeCommandFail):
            run_rollback("/repo", "abc123")


class TestReleaseSigningSignFiles(unittest.TestCase):
    """Tests for release_signing.sign_files."""

    @mock.patch('software.release_signing.PKCS1_PSS.new')
    def test_sign_with_dev_key(self, mock_pss):
        mock_key = mock.Mock()
        mock_signer = mock.Mock()
        mock_signer.sign.return_value = b'signature'
        mock_pss.return_value = mock_signer

        with tempfile.NamedTemporaryFile(delete=False) as data_f:
            data_f.write(b'test data')
            data_file = data_f.name
        with tempfile.NamedTemporaryFile(delete=False) as sig_f:
            sig_file = sig_f.name
        try:
            result = sign_files([data_file], sig_file, private_key=mock_key)
            self.assertFalse(result)
        finally:
            os.unlink(data_file)
            os.unlink(sig_file)

    @mock.patch('software.release_signing.PKCS1_PSS.new')
    def test_sign_with_provided_key(self, mock_pss):
        mock_key = mock.Mock()
        mock_signer = mock.Mock()
        mock_signer.sign.return_value = b'signature'
        mock_pss.return_value = mock_signer

        with tempfile.NamedTemporaryFile(delete=False) as data_f:
            data_f.write(b'test data')
            data_file = data_f.name
        with tempfile.NamedTemporaryFile(delete=False) as sig_f:
            sig_file = sig_f.name
        try:
            result = sign_files([data_file], sig_file, private_key=mock_key)
            self.assertFalse(result)
            # Verify signature was written
            with open(sig_file, 'rb') as f:
                self.assertEqual(f.read(), b'signature')
        finally:
            os.unlink(data_file)
            os.unlink(sig_file)

    @mock.patch('os.path.exists', return_value=False)
    def test_no_key_found_raises(self, _mock_exists):
        with tempfile.NamedTemporaryFile(delete=False) as data_f:
            data_f.write(b'test data')
            data_file = data_f.name
        try:
            with self.assertRaises(AssertionError):
                sign_files([data_file], "/tmp/sig.bin")
        finally:
            os.unlink(data_file)


class TestPluginDeployPluginRunner(unittest.TestCase):
    """Tests for plugin.DeployPluginRunner."""

    @mock.patch('software.plugin.utils.get_endpoints_token',
                return_value=('token', 'http://sysinv/v1'))
    @mock.patch('software.plugin.constants.SW_VERSION', '24.09')
    def test_init_same_version(self, _mock_token):
        deploy = {'from_release': '24.09.0', 'to_release': '24.09.1'}
        runner = DeployPluginRunner(deploy)
        self.assertIsNone(runner._temp_plugin_path)

    @mock.patch('tempfile.mkdtemp', return_value='/tmp/usm-plugin-xxx')
    @mock.patch('software.plugin.utils.get_endpoints_token',
                return_value=('token', 'http://sysinv/v1'))
    @mock.patch('software.plugin.constants.SW_VERSION', '24.09')
    def test_init_different_version(self, _mock_token, _mock_mkdtemp):
        deploy = {'from_release': '24.09.0', 'to_release': '25.03.0'}
        runner = DeployPluginRunner(deploy)
        self.assertIsNotNone(runner._temp_plugin_path)

    def test_get_higher_version(self):
        deploy = {'from_release': '24.09.0', 'to_release': '25.03.0'}
        result = DeployPluginRunner.get_higher_version(deploy)
        self.assertEqual(result, '25.03')

    def test_get_higher_version_same(self):
        deploy = {'from_release': '24.09.0', 'to_release': '24.09.1'}
        result = DeployPluginRunner.get_higher_version(deploy)
        self.assertEqual(result, '24.09')

    @mock.patch('software.plugin.utils.get_endpoints_token',
                return_value=('token', 'http://sysinv/v1'))
    @mock.patch('software.plugin.constants.SW_VERSION', '24.09')
    def test_set_auth_token(self, _mock_token):
        deploy = {'from_release': '24.09.0', 'to_release': '24.09.1'}
        runner = DeployPluginRunner(deploy)
        runner._env = {}
        runner.set_auth_token()
        self.assertEqual(runner._env['OS_AUTH_TOKEN'], 'token')

    @mock.patch('software.plugin.utils.get_endpoints_token',
                return_value=('token', 'http://sysinv/v1'))
    @mock.patch('software.plugin.constants.SW_VERSION', '24.09')
    def test_set_deploy_options(self, _mock_token):
        deploy = {'from_release': '24.09.0', 'to_release': '24.09.1',
                  'options': {'key1': 'val1'}}
        runner = DeployPluginRunner(deploy)
        runner._env = {}
        runner.set_deploy_options()
        self.assertEqual(runner._env['key1'], 'val1')

    @mock.patch('software.plugin.utils.get_endpoints_token',
                return_value=('token', 'http://sysinv/v1'))
    @mock.patch('software.plugin.constants.SW_VERSION', '24.09')
    def test_set_execution_context(self, _mock_token):
        deploy = {'from_release': '24.09.0', 'to_release': '24.09.1'}
        runner = DeployPluginRunner(deploy)
        runner._env = {}
        runner.set_execution_context([('key1', 'val1')])
        self.assertEqual(runner._env['from_release'], '24.09.0')
        self.assertEqual(runner._env['to_release'], '24.09.1')
        self.assertEqual(runner._env['key1'], 'val1')

    @mock.patch('subprocess.run',
                side_effect=subprocess.CalledProcessError(1,
                                                          'cmd',
                                                          output=b'err'))
    @mock.patch('tempfile.mkdtemp', return_value='/tmp/usm-plugin-xxx')
    @mock.patch('software.plugin.utils.get_endpoints_token',
                return_value=('token', 'http://sysinv/v1'))
    @mock.patch('software.plugin.constants.SW_VERSION', '24.09')
    def test_execute_checkout_failure(
            self, _mock_token, _mock_mkdtemp, _mock_run):
        deploy = {'from_release': '24.09.0', 'to_release': '25.03.0'}
        runner = DeployPluginRunner(deploy)
        with self.assertRaises(subprocess.CalledProcessError):
            runner.execute("deploy-delete")


class TestBaseServiceInit(unittest.TestCase):
    """Tests for base.PatchService."""

    def test_init(self):
        ps = PatchService()
        self.assertIsNone(ps.sock_out)
        self.assertIsNone(ps.sock_in)
        self.assertTrue(ps.pre_bootstrap)

    @mock.patch('software.base.cfg.get_mgmt_ip', return_value=None)
    def test_setup_socket_ipv4_no_ip(self, _mock_ip):
        ps = PatchService()
        result = ps.setup_socket_ipv4()
        self.assertIsNone(result)

    @mock.patch('software.base.cfg.get_mgmt_ip', return_value=None)
    def test_setup_socket_ipv6_no_ip(self, _mock_ip):
        ps = PatchService()
        result = ps.setup_socket_ipv6()
        self.assertIsNone(result)

    @mock.patch('software.base.cfg.get_mgmt_ip', return_value='10.0.0.1')
    @mock.patch('socket.socket')
    def test_setup_socket_ipv4(self, _mock_sock, _mock_ip):
        ps = PatchService()
        ps.port = 5494
        ps.mcast_addr = '239.1.1.3'
        result = ps.setup_socket_ipv4()
        self.assertIsNotNone(result)

    @mock.patch('software.base.cfg.get_mgmt_iface', return_value='ens3')
    @mock.patch('software.base.utils.if_nametoindex', return_value=2)
    @mock.patch('software.base.cfg.get_mgmt_ip', return_value='fd00::1')
    @mock.patch('socket.socket')
    def test_setup_socket_ipv6(self, _mock_sock, _mock_ip, _mock_idx, _mock_iface):
        ps = PatchService()
        ps.port = 5494
        ps.mcast_addr = 'ff02::1'
        result = ps.setup_socket_ipv6()
        self.assertIsNotNone(result)

    @mock.patch('software.base.cfg.get_mgmt_ip', return_value='10.0.0.1')
    @mock.patch('software.base.utils.get_management_version', return_value=4)
    @mock.patch('socket.socket')
    def test_setup_socket_ipv4_path(self, _mock_sock, _mock_ver, _mock_ip):
        ps = PatchService()
        ps.pre_bootstrap = False
        ps.port = 5494
        ps.mcast_addr = None
        result = ps.setup_socket()
        self.assertIsNotNone(result)

    @mock.patch('software.base.cfg.get_mgmt_ip', return_value='10.0.0.1')
    @mock.patch('socket.socket', side_effect=Exception("socket error"))
    def test_setup_socket_failure(self, _mock_sock, _mock_ip):
        ps = PatchService()
        ps.pre_bootstrap = False
        ps.port = 5494
        ps.mcast_addr = None
        result = ps.setup_socket()
        self.assertIsNone(result)
