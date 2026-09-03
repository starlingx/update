#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# pylint: disable=unused-argument,protected-access,arguments-differ

import json
import unittest
from unittest.mock import MagicMock
from unittest.mock import patch

from patch_alarm.tests import base  # noqa: F401 # pylint: disable=unused-import

from patch_alarm.patch_alarm_manager import PatchAlarmDaemon


@patch('patch_alarm.patch_alarm_manager.get_platform_conf', return_value=None)
class TestPatchAlarmDaemonInit(unittest.TestCase):
    @patch('patch_alarm.patch_alarm_manager.fm_api.FaultAPIs')
    @patch('patch_alarm.patch_alarm_manager.cfg')
    def test_init(self, mock_config, mock_fault_apis, mock_plat):
        """Daemon init sets the pidfile path and API address from config."""
        mock_config.api_port = 5493
        daemon = PatchAlarmDaemon()
        self.assertEqual(
            daemon.pidfile_path,
            '/var/run/patch-alarm-manager.pid')
        self.assertIn("5493", daemon.api_addr)


class TestHandlePatchAlarmsDIP(unittest.TestCase):
    """Tests for deploy-in-progress alarm (900.023)."""

    @patch('patch_alarm.patch_alarm_manager.get_platform_conf', return_value=None)
    @patch('patch_alarm.patch_alarm_manager.fm_api.FaultAPIs')
    @patch('patch_alarm.patch_alarm_manager.cfg')
    def setUp(self, mock_config, mock_fault_apis, mock_plat):
        mock_config.api_port = 5493
        self.daemon = PatchAlarmDaemon()
        self.daemon.fm_api = MagicMock()

    @patch('patch_alarm.patch_alarm_manager.requests.get')
    def test_deploying_raises_dip_alarm(self, mock_get):
        """A release in 'deploying' state raises the 900.023 minor alarm."""
        mock_resp = MagicMock(status_code=200)
        mock_resp.text = json.dumps(
            [{"state": "deploying", "release_id": "R1"}])
        mock_get.return_value = mock_resp
        self.daemon.fm_api.get_fault.return_value = None
        self.daemon._handle_patch_alarms()
        fault = self.daemon.fm_api.set_fault.call_args[0][0]
        self.assertEqual(fault.alarm_id, '900.023')
        self.assertEqual(fault.severity, 'minor')
        self.assertEqual(
            fault.reason_text, 'Software release deploy in progress')

    @patch('patch_alarm.patch_alarm_manager.requests.get')
    def test_removing_raises_dip_alarm(self, mock_get):
        """A release in 'removing' state raises the 900.023 minor alarm."""
        mock_resp = MagicMock(status_code=200)
        mock_resp.text = json.dumps(
            [{"state": "removing", "release_id": "R1"}])
        mock_get.return_value = mock_resp
        self.daemon.fm_api.get_fault.return_value = None
        self.daemon._handle_patch_alarms()
        fault = self.daemon.fm_api.set_fault.call_args[0][0]
        self.assertEqual(fault.alarm_id, '900.023')
        self.assertEqual(fault.severity, 'minor')

    @patch('patch_alarm.patch_alarm_manager.requests.get')
    def test_no_deploying_clears_dip_alarm(self, mock_get):
        """When no release is deploying, an existing 900.023 alarm clears."""
        mock_resp = MagicMock(status_code=200)
        mock_resp.text = json.dumps(
            [{"state": "deployed", "release_id": "R1"}])
        mock_get.return_value = mock_resp
        self.daemon.fm_api.get_fault.return_value = MagicMock()
        self.daemon._handle_patch_alarms()
        clear_calls = self.daemon.fm_api.clear_fault.call_args_list
        cleared_ids = [c[0][0] for c in clear_calls]
        self.assertIn('900.023', cleared_ids)

    @patch('patch_alarm.patch_alarm_manager.requests.get')
    def test_non_200_does_not_raise_alarm(self, mock_get):
        """A non-200 response from the software API raises no alarm."""
        mock_resp = MagicMock(status_code=500)
        mock_get.return_value = mock_resp
        self.daemon.fm_api.get_fault.return_value = None
        self.daemon._handle_patch_alarms()
        self.daemon.fm_api.set_fault.assert_not_called()

    @patch('patch_alarm.patch_alarm_manager.requests.get')
    def test_request_exception_does_not_crash(self, mock_get):
        """A request exception is handled gracefully and raises no alarm."""
        mock_get.side_effect = Exception("connection refused")
        self.daemon._handle_patch_alarms()
        self.daemon.fm_api.set_fault.assert_not_called()


class TestHandlePatchAlarmsObsolete(unittest.TestCase):
    """Tests for obsolete-release alarm (900.024)."""

    @patch('patch_alarm.patch_alarm_manager.get_platform_conf', return_value=None)
    @patch('patch_alarm.patch_alarm_manager.fm_api.FaultAPIs')
    @patch('patch_alarm.patch_alarm_manager.cfg')
    def setUp(self, mock_config, mock_fault_apis, mock_plat):
        mock_config.api_port = 5493
        self.daemon = PatchAlarmDaemon()
        self.daemon.fm_api = MagicMock()

    @patch('patch_alarm.patch_alarm_manager.SW_VERSION', '26.03')
    @patch('patch_alarm.patch_alarm_manager.requests.get')
    def test_unavailable_prev_version_raises_obs_alarm(self, mock_get):
        """A leftover unavailable release from a previous major version
        (e.g. right after a platform upgrade) on a non-System-Controller
        should raise the obsolete-release alarm.
        """
        mock_resp = MagicMock(status_code=200)
        mock_resp.text = json.dumps([
            {"state": "unavailable",
             "sw_version": "25.09.1",
             "release_id": "R1"}
        ])
        mock_get.return_value = mock_resp
        self.daemon.fm_api.get_fault.return_value = None
        self.daemon._handle_patch_alarms()
        fault = self.daemon.fm_api.set_fault.call_args[0][0]
        self.assertEqual(fault.alarm_id, '900.024')
        self.assertEqual(fault.severity, 'warning')
        self.assertEqual(fault.reason_text, 'Obsolete release in system')

    @patch('patch_alarm.patch_alarm_manager.SW_VERSION', '26.03')
    @patch('patch_alarm.patch_alarm_manager.requests.get')
    def test_unavailable_prev_version_on_syscontroller_no_obs_alarm(self, mock_get):
        """On a System Controller, an unavailable release from a previous
        major version (n-1/n-2 uploaded for subcloud provisioning) should
        NOT raise the obsolete-release alarm.
        """
        self.daemon._is_system_controller = True
        mock_resp = MagicMock(status_code=200)
        mock_resp.text = json.dumps([
            {"state": "unavailable",
             "sw_version": "25.09.1",
             "release_id": "R1"}
        ])
        mock_get.return_value = mock_resp
        self.daemon.fm_api.get_fault.return_value = None
        self.daemon._handle_patch_alarms()
        for call in self.daemon.fm_api.set_fault.call_args_list:
            fault = call[0][0]
            self.assertNotEqual(fault.alarm_id, '900.024')

    @patch('patch_alarm.patch_alarm_manager.requests.get')
    def test_not_unavailable_clears_obs_alarm(self, mock_get):
        """When no release is unavailable, an existing 900.024 alarm clears."""
        mock_resp = MagicMock(status_code=200)
        mock_resp.text = json.dumps(
            [{"state": "deployed", "release_id": "R1"}])
        mock_get.return_value = mock_resp
        self.daemon.fm_api.get_fault.return_value = MagicMock()
        self.daemon._handle_patch_alarms()
        clear_calls = self.daemon.fm_api.clear_fault.call_args_list
        cleared_ids = [c[0][0] for c in clear_calls]
        self.assertIn('900.024', cleared_ids)


class TestHandlePatchAlarmsDevCert(unittest.TestCase):
    """Tests for dev certificate alarm (500.101)."""

    @patch('patch_alarm.patch_alarm_manager.get_platform_conf', return_value=None)
    @patch('patch_alarm.patch_alarm_manager.fm_api.FaultAPIs')
    @patch('patch_alarm.patch_alarm_manager.cfg')
    def setUp(self, mock_config, mock_fault_apis, mock_plat):
        mock_config.api_port = 5493
        self.daemon = PatchAlarmDaemon()
        self.daemon.fm_api = MagicMock()

    @patch(
        'patch_alarm.patch_alarm_manager.'
        'ENABLE_DEV_CERTIFICATE_PATCH_IDENTIFIER',
        'DEV_CERT')
    @patch('patch_alarm.patch_alarm_manager.requests.get')
    def test_dev_cert_raises_critical_alarm(self, mock_get):
        """A release signed with a dev certificate raises the 500.101
        critical alarm.
        """
        mock_resp = MagicMock(status_code=200)
        mock_resp.text = json.dumps([
            {"state": "deployed", "release_id": "DEV_CERT_001"}
        ])
        mock_get.return_value = mock_resp
        self.daemon.fm_api.get_fault.return_value = None
        self.daemon._handle_patch_alarms()
        fault = self.daemon.fm_api.set_fault.call_args[0][0]
        self.assertEqual(fault.alarm_id, '500.101')
        self.assertEqual(fault.severity, 'critical')
        self.assertIn('certificate', fault.reason_text.lower())


class TestGetHandleFailedHosts(unittest.TestCase):
    """Tests for host failure alarm (900.021)."""

    @patch('patch_alarm.patch_alarm_manager.get_platform_conf', return_value=None)
    @patch('patch_alarm.patch_alarm_manager.fm_api.FaultAPIs')
    @patch('patch_alarm.patch_alarm_manager.cfg')
    def setUp(self, mock_config, mock_fault_apis, mock_plat):
        mock_config.api_port = 5493
        self.daemon = PatchAlarmDaemon()
        self.daemon.fm_api = MagicMock()

    @patch('patch_alarm.patch_alarm_manager.requests.get')
    def test_failed_host_raises_alarm_with_hostname(self, mock_get):
        """A host in 'failed' state raises the 900.021 major alarm naming
        that host.
        """
        mock_resp = MagicMock(status_code=200)
        mock_resp.text = json.dumps([
            {"hostname": "worker-0", "host_state": "failed"}
        ])
        mock_get.return_value = mock_resp
        self.daemon.fm_api.get_fault.return_value = None
        self.daemon._get_handle_failed_hosts()
        fault = self.daemon.fm_api.set_fault.call_args[0][0]
        self.assertEqual(fault.alarm_id, '900.021')
        self.assertEqual(fault.severity, 'major')
        self.assertIn('worker-0', fault.reason_text)

    @patch('patch_alarm.patch_alarm_manager.requests.get')
    def test_rollback_failed_raises_alarm(self, mock_get):
        """A host in 'rollback-failed' state raises the 900.021 alarm naming
        that host.
        """
        mock_resp = MagicMock(status_code=200)
        mock_resp.text = json.dumps([
            {"hostname": "ctrl-1", "host_state": "rollback-failed"}
        ])
        mock_get.return_value = mock_resp
        self.daemon.fm_api.get_fault.return_value = None
        self.daemon._get_handle_failed_hosts()
        fault = self.daemon.fm_api.set_fault.call_args[0][0]
        self.assertEqual(fault.alarm_id, '900.021')
        self.assertIn('ctrl-1', fault.reason_text)

    @patch('patch_alarm.patch_alarm_manager.requests.get')
    def test_multiple_failed_hosts_sorted_in_text(self, mock_get):
        """Multiple failed hosts appear in the alarm text in sorted order."""
        mock_resp = MagicMock(status_code=200)
        mock_resp.text = json.dumps([
            {"hostname": "worker-1", "host_state": "failed"},
            {"hostname": "worker-0", "host_state": "failed"}
        ])
        mock_get.return_value = mock_resp
        self.daemon.fm_api.get_fault.return_value = None
        self.daemon._get_handle_failed_hosts()
        fault = self.daemon.fm_api.set_fault.call_args[0][0]
        self.assertIn('worker-0', fault.reason_text)
        self.assertIn('worker-1', fault.reason_text)
        self.assertLess(
            fault.reason_text.index('worker-0'),
            fault.reason_text.index('worker-1'))

    @patch('patch_alarm.patch_alarm_manager.requests.get')
    def test_no_failed_hosts_clears_alarm(self, mock_get):
        """When no host has failed, an existing 900.021 alarm clears."""
        mock_resp = MagicMock(status_code=200)
        mock_resp.text = json.dumps([
            {"hostname": "worker-0", "host_state": "deployed"}
        ])
        mock_get.return_value = mock_resp
        self.daemon.fm_api.get_fault.return_value = MagicMock()
        self.daemon._get_handle_failed_hosts()
        clear_args = self.daemon.fm_api.clear_fault.call_args[0]
        self.assertEqual(clear_args[0], '900.021')

    @patch('patch_alarm.patch_alarm_manager.requests.get')
    def test_no_failed_no_existing_alarm_does_nothing(self, mock_get):
        """With no failed hosts and no existing alarm, nothing is set or
        cleared.
        """
        mock_resp = MagicMock(status_code=200)
        mock_resp.text = json.dumps([
            {"hostname": "worker-0", "host_state": "deployed"}
        ])
        mock_get.return_value = mock_resp
        self.daemon.fm_api.get_fault.return_value = None
        self.daemon._get_handle_failed_hosts()
        self.daemon.fm_api.set_fault.assert_not_called()
        self.daemon.fm_api.clear_fault.assert_not_called()

    @patch('patch_alarm.patch_alarm_manager.requests.get')
    def test_changed_failed_hosts_updates_alarm(self, mock_get):
        """When the set of failed hosts differs from the existing alarm,
        the alarm is re-raised with the updated host list.
        """
        mock_resp = MagicMock(status_code=200)
        mock_resp.text = json.dumps([
            {"hostname": "worker-0", "host_state": "failed"},
            {"hostname": "worker-1", "host_state": "failed"}
        ])
        mock_get.return_value = mock_resp
        existing_alarm = MagicMock()
        existing_alarm.reason_text = "old text"
        self.daemon.fm_api.get_fault.return_value = existing_alarm
        self.daemon._get_handle_failed_hosts()
        fault = self.daemon.fm_api.set_fault.call_args[0][0]
        self.assertIn('worker-0', fault.reason_text)
        self.assertIn('worker-1', fault.reason_text)

    @patch('patch_alarm.patch_alarm_manager.requests.get')
    def test_same_alarm_text_no_update(self, mock_get):
        """When the failed-host set is unchanged, the alarm is not re-raised."""
        mock_resp = MagicMock(status_code=200)
        mock_resp.text = json.dumps([
            {"hostname": "worker-0", "host_state": "failed"}
        ])
        mock_get.return_value = mock_resp
        existing_alarm = MagicMock()
        existing_alarm.reason_text = \
            "Release installation failed on the following hosts: worker-0"
        self.daemon.fm_api.get_fault.return_value = existing_alarm
        self.daemon._get_handle_failed_hosts()
        self.daemon.fm_api.set_fault.assert_not_called()

    @patch('patch_alarm.patch_alarm_manager.requests.get')
    def test_request_exception_does_not_crash(self, mock_get):
        """A request exception is handled gracefully and raises no alarm."""
        mock_get.side_effect = Exception("connection refused")
        self.daemon._get_handle_failed_hosts()
        self.daemon.fm_api.set_fault.assert_not_called()

    @patch('patch_alarm.patch_alarm_manager.requests.get')
    def test_non_200_does_not_raise_alarm(self, mock_get):
        """A non-200 response from the software API raises no alarm."""
        mock_resp = MagicMock(status_code=500)
        mock_get.return_value = mock_resp
        self.daemon.fm_api.get_fault.return_value = None
        self.daemon._get_handle_failed_hosts()
        self.daemon.fm_api.set_fault.assert_not_called()
