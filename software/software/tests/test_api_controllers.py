#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from unittest.mock import MagicMock
from unittest.mock import patch
import unittest
import socket

import webob.exc

from software.tests import base  # noqa: F401

from software.api.controllers.v1 import deploy_host
from software.api.controllers.v1.deploy import DeployController
from software.api.controllers.v1.release import ReleaseController
from software.exceptions import SoftwareServiceError
from software.logging_hook import CustomSoftwareApiLogFilter
from software.utilities.update_deploy_state import get_udp_socket
from software.utilities.update_deploy_state import update_deploy_state


class TestGetUdpSocket(unittest.TestCase):

    @patch('software.utilities.update_deploy_state.socket')
    def test_empty_addr(self, mock_sock_mod):
        mock_sock_mod.getaddrinfo.return_value = []
        with self.assertRaises(Exception):  # noqa: H202
            get_udp_socket('bad', 0)


class TestUpdateDeployState(unittest.TestCase):

    @patch('software.utilities.update_deploy_state.get_udp_socket')
    @patch('software.utilities.update_deploy_state.cfg')
    def test_timeout_retry(self, mock_cfg, mock_get_sock):
        mock_cfg.get_mgmt_ip.return_value = ''
        mock_cfg.controller_port = 5000
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = socket.timeout("timeout")
        mock_get_sock.return_value = mock_sock
        with self.assertRaises(Exception):  # noqa: H202
            update_deploy_state('agent1', deploy_state='started')


class TestCustomLogFilter(unittest.TestCase):
    def test_suppress(self):
        f = CustomSoftwareApiLogFilter(suppress_patterns=[r'GET /health'])
        record = MagicMock()
        record.getMessage.return_value = 'GET /health check'
        self.assertFalse(f.filter(record))

    def test_allow(self):
        f = CustomSoftwareApiLogFilter(suppress_patterns=[r'GET /health'])
        record = MagicMock()
        record.getMessage.return_value = 'POST /v1/deploy'
        self.assertTrue(f.filter(record))


class TestReleaseController(unittest.TestCase):
    @patch('software.api.controllers.v1.release.sc')
    @patch('software.api.controllers.v1.release.reload_release_data')
    def test_get_all(self, _mock_reload, mock_sc):
        ctrl = ReleaseController()
        mock_sc.software_release_query_cached.return_value = [{'id': 'r1'}]
        result = ctrl.get_all()
        self.assertEqual(result, [{'id': 'r1'}])

    @patch('software.api.controllers.v1.release.sc')
    @patch('software.api.controllers.v1.release.reload_release_data')
    def test_get_one_found(self, _mock_reload, mock_sc):
        ctrl = ReleaseController()
        mock_sc.software_release_query_specific_cached.return_value = [
            {'id': 'r1'}]
        result = ctrl.get_one('r1')
        self.assertEqual(result, {'id': 'r1'})

    @patch('software.api.controllers.v1.release.sc')
    @patch('software.api.controllers.v1.release.reload_release_data')
    def test_get_one_not_found(self, _mock_reload, mock_sc):
        ctrl = ReleaseController()
        mock_sc.software_release_query_specific_cached.return_value = []
        with self.assertRaises(webob.exc.HTTPNotFound):
            ctrl.get_one('r1')


class TestDeployController(unittest.TestCase):

    @patch('software.api.controllers.v1.deploy.response')
    @patch('software.api.controllers.v1.deploy.sc')
    @patch('software.api.controllers.v1.deploy.reload_release_data')
    def test_precheck_error(self, _mock_reload, mock_sc, mock_resp):
        ctrl = DeployController()
        mock_sc.software_deploy_precheck_api.return_value = {'error': 'bad'}
        ctrl.precheck(force='yes')
        self.assertEqual(mock_resp.status, 406)

    @patch('software.api.controllers.v1.deploy.sc')
    @patch('software.api.controllers.v1.deploy.reload_release_data')
    def test_start_installing(self, _mock_reload, mock_sc):
        ctrl = DeployController()
        mock_sc.any_patch_host_installing.return_value = True
        with self.assertRaises(SoftwareServiceError):
            ctrl.start('r1')

    @patch('software.api.controllers.v1.deploy.sc')
    @patch('software.api.controllers.v1.deploy.reload_release_data')
    def test_software_sync(self, _mock_reload, mock_sc):
        ctrl = DeployController()
        mock_sc.software_sync.return_value = True
        result = ctrl.software_sync()
        self.assertEqual(result, {'result': True})


class TestDeployHostController(unittest.TestCase):

    @patch('software.api.controllers.v1.deploy_host.sc')
    @patch('software.api.controllers.v1.deploy_host.reload_release_data')
    def test_post_no_host(self, _mock_reload, _mock_sc):
        DeployHostController = deploy_host.DeployHostController
        ctrl = DeployHostController()
        result = ctrl.post()
        self.assertIn('error', result)
