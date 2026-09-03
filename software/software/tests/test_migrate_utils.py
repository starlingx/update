#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for uncovered lines in migrate.py and smaller utility files."""

import unittest
from unittest import mock
from unittest.mock import patch
from unittest.mock import MagicMock

from software.tests import base as test_base  # noqa: F401

# migrate.py calls get_postgres_bin() -> pg_config at module scope, so
# subprocess.check_output must be patched before importing it.
mock.patch('subprocess.check_output', return_value=b'/usr/lib/postgresql/14/bin\n').start()

from software.utilities import migrate
from software.utilities.deploy_action import activate
from software.utilities.deploy_action import activate_rollback
from software.utilities.deploy_action import delete
from software.utilities.deploy_set_failed import get_current_deploy_state
from software.utilities.deploy_set_failed import get_current_deploy_host_state
from software.utilities.deploy_set_failed import acknowledge_operation
from software.utilities.deploy_set_failed import get_deploy_host_fail_function
from software.states import DEPLOY_HOST_STATES
from software.sysinv_utils import get_system_info
from software.sysinv_utils import trigger_vim_host_audit
from software.sysinv_utils import get_service_parameter


class TestMigrateGetPostgresBin(unittest.TestCase):
    """Tests for get_postgres_bin."""

    @patch('subprocess.check_output', return_value=b'/usr/lib/postgresql/14/bin\n')
    def test_success(self, _mock_run):
        result = migrate.get_postgres_bin()
        self.assertEqual(result, '/usr/lib/postgresql/14/bin')


class TestActivateEntry(unittest.TestCase):
    """Tests for activate() entry point."""

    @patch('software.utilities.deploy_action.do_action', return_value=True)
    @patch('software.utilities.deploy_action.configure_logging')
    def test_activate_success(self, _mock_log, _mock_do):
        with patch('sys.argv', ['activate', '24.09', '25.03']):
            with self.assertRaises(SystemExit) as ctx:
                activate()
            self.assertEqual(ctx.exception.code, 0)

    @patch('software.utilities.deploy_action.do_action', return_value=False)
    @patch('software.utilities.deploy_action.configure_logging')
    def test_activate_failure(self, _mock_log, _mock_do):
        with patch('sys.argv', ['activate', '24.09', '25.03']):
            with self.assertRaises(SystemExit) as ctx:
                activate()
            self.assertEqual(ctx.exception.code, 1)


class TestActivateRollbackEntry(unittest.TestCase):
    """Tests for activate_rollback() entry point."""

    @patch('software.utilities.deploy_action.do_action',
           return_value=True)
    @patch('software.utilities.deploy_action.configure_logging')
    def test_success(self, _mock_log, _mock_do):
        with patch('sys.argv', ['activate_rollback', '24.09', '25.03']):
            with self.assertRaises(SystemExit) as ctx:
                activate_rollback()
            self.assertEqual(ctx.exception.code, 0)

    @patch('software.utilities.deploy_action.do_action',
           return_value=False)
    @patch('software.utilities.deploy_action.configure_logging')
    def test_failure(self, _mock_log, _mock_do):
        with patch('sys.argv', ['activate_rollback', '24.09', '25.03']):
            with self.assertRaises(SystemExit) as ctx:
                activate_rollback()
            self.assertEqual(ctx.exception.code, 1)


class TestDeployDeleteEntry(unittest.TestCase):
    """Tests for delete() entry point."""

    @patch('software.utilities.deploy_action.do_action')
    @patch('software.utilities.deploy_action.configure_logging')
    def test_deploy_delete(self, _mock_log, mock_do):
        mock_do.return_value = True
        with patch('sys.argv', ['delete', '24.09', '25.03']):
            with self.assertRaises(SystemExit) as ctx:
                delete()
            self.assertEqual(ctx.exception.code, 0)
        mock_do.assert_called_once()


class TestDeploySetFailedGetState(unittest.TestCase):
    """Tests for get_current_deploy_state."""

    @patch('software.utilities.deploy_set_failed.get_instance')
    def test_returns_state(self, mock_db):
        mock_db.return_value.get_current_deploy.return_value = {
            'state': 'host'
        }
        result = get_current_deploy_state()
        self.assertEqual(result, 'host')

    @patch('software.utilities.deploy_set_failed.get_instance')
    def test_no_deploy_exits(self, mock_db):
        mock_db.return_value.get_current_deploy.return_value = None
        with self.assertRaises(SystemExit):
            get_current_deploy_state()


class TestDeploySetFailedGetHostState(unittest.TestCase):
    """Tests for get_current_deploy_host_state."""

    @patch('software.utilities.deploy_set_failed.get_instance')
    def test_returns_state(self, mock_db):
        mock_db.return_value.get_deploy_host.return_value = {'state': 'deploying'}
        result = get_current_deploy_host_state()
        self.assertEqual(result, 'deploying')

    @patch('software.utilities.deploy_set_failed.get_instance')
    def test_no_deploy_exits(self, mock_db):
        mock_db.return_value.get_deploy_host.return_value = None
        with self.assertRaises(SystemExit):
            get_current_deploy_host_state()


class TestAcknowledgeOperation(unittest.TestCase):
    """Tests for acknowledge_operation."""

    @patch('software.utilities.deploy_set_failed.get_current_deploy_state',
           return_value='host')
    @patch('builtins.input', return_value='no')
    def test_user_cancels(self, _mock_input, _mock_state):
        with self.assertRaises(SystemExit):
            acknowledge_operation(False)


class TestGetDeployHostFailFunction(unittest.TestCase):
    """Tests for get_deploy_host_fail_function."""

    def test_deploying_state(self):
        mock_host = MagicMock()
        mock_host.get_deploy_host_state.return_value = DEPLOY_HOST_STATES.DEPLOYING
        result = get_deploy_host_fail_function(mock_host)
        self.assertEqual(result, mock_host.failed)

    def test_rollback_deploying_state(self):
        mock_host = MagicMock()
        mock_host.get_deploy_host_state.return_value = DEPLOY_HOST_STATES.ROLLBACK_DEPLOYING
        result = get_deploy_host_fail_function(mock_host)
        self.assertEqual(result, mock_host.deploy_failed)

    def test_no_state_exits(self):
        mock_host = MagicMock()
        mock_host.get_deploy_host_state.return_value = None
        with self.assertRaises(SystemExit):
            get_deploy_host_fail_function(mock_host)

    def test_unsupported_state_exits(self):
        mock_host = MagicMock()
        mock_host.get_deploy_host_state.return_value = DEPLOY_HOST_STATES.PENDING
        with self.assertRaises(SystemExit):
            get_deploy_host_fail_function(mock_host)


class TestSysinvGetSystemInfo(unittest.TestCase):
    """Tests for get_system_info."""

    @patch('software.sysinv_utils.utils.get_endpoints_token',
           side_effect=Exception("conn fail"))
    def test_failure(self, _mock_token):
        with self.assertRaises(Exception):  # noqa: H202
            get_system_info()


class TestSysinvTriggerVimAudit(unittest.TestCase):
    """Tests for trigger_vim_host_audit."""

    @patch('software.sysinv_utils.utils.get_endpoints_token',
           return_value=('token', 'http://sysinv'))
    @patch('software.sysinv_utils.get_sysinv_client')
    def test_failure(self, mock_client, _mock_token):
        mock_client.return_value.ihost.get.side_effect = Exception("not found")
        with self.assertRaises(Exception):  # noqa: H202
            trigger_vim_host_audit("bad-host")


class TestSysinvGetServiceParameter(unittest.TestCase):
    """Tests for get_service_parameter."""

    @patch('software.sysinv_utils.utils.get_endpoints_token',
           return_value=('token', 'http://sysinv'))
    @patch('software.sysinv_utils.get_sysinv_client')
    def test_filter_by_service(self, mock_client, _mock_token):
        sp = MagicMock()
        sp.service = 'platform'
        sp.section = 'config'
        sp.name = 'param1'
        sp.value = 'val1'
        sp.uuid = 'u1'
        sp.personality = ''
        sp.resource = ''
        mock_client.return_value.service_parameter.list.return_value = [sp]
        result = get_service_parameter(service='platform')
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['name'], 'param1')

    @patch('software.sysinv_utils.utils.get_endpoints_token',
           return_value=('token', 'http://sysinv'))
    @patch('software.sysinv_utils.get_sysinv_client')
    def test_no_filter(self, mock_client, _mock_token):
        mock_client.return_value.service_parameter.list.return_value = []
        result = get_service_parameter()
        self.assertEqual(result, [])
