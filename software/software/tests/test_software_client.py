#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2023 Wind River Systems, Inc.
#

import json
import os
import sys
import testtools
from unittest import mock

from software import software_client


API_PORT = "5493"
URL_PREFIX = "http://127.0.0.1:" + API_PORT + "/software"

FAKE_SW_VERSION = "1.2.3"
PATCH_FLAG_NO = "N"
PATCH_FLAG_YES = "Y"
STATE_APPLIED = "Applied"
STATE_AVAILABLE = "Available"
STATE_NA = "n/a"
STATUS_DEV = "DEV"

FAKE_PATCH_ID_1 = "PATCH_1"
FAKE_PATCH_1_META = {
    "apply_active_release_only": "",
    "description": "Patch 1 description",
    "install_instructions": "Patch 1 instructions",
    "state": STATE_NA,
    "reboot_required": PATCH_FLAG_YES,
    "deploy_state": STATE_APPLIED,
    "requires": [],
    "status": STATUS_DEV,
    "summary": "Patch 1 summary",
    "sw_version": FAKE_SW_VERSION,
    "unremovable": PATCH_FLAG_NO,
    "warnings": "Patch 1 warnings",
}

FAKE_PATCH_ID_2 = "PATCH_2"
FAKE_PATCH_2_META = {
    "apply_active_release_only": "",
    "description": "Patch 2 description",
    "install_instructions": "Patch 2 instructions",
    "state": STATE_AVAILABLE,
    "reboot_required": PATCH_FLAG_NO,
    "deploy_state": STATE_AVAILABLE,
    "requires": [FAKE_PATCH_ID_1],
    "status": STATUS_DEV,
    "summary": "Patch 2 summary",
    "sw_version": FAKE_SW_VERSION,
    "unremovable": PATCH_FLAG_NO,
    "warnings": "Patch 2 warnings",
}


class FakeResponse(object):
    """This is used to mock a requests.get result"""
    def __init__(self, json_data, status_code):
        self.json_data = json_data
        self.status_code = status_code
        self.text = json.dumps(json_data)

    def json(self):
        return self.json_data


class SoftwareClientTestCase(testtools.TestCase):
    PROG = "software"

    MOCK_ENV = {
        'OS_AUTH_URL': 'FAKE_OS_AUTH_URL',
        'OS_PROJECT_NAME': 'FAKE_OS_PROJECT_NAME',
        'OS_PROJECT_DOMAIN_NAME': 'FAKE_OS_PROJECT_DOMAIN_NAME',
        'OS_USERNAME': 'FAKE_OS_USERNAME',
        'OS_PASSWORD': 'FAKE_OS_PASSWORD',
        'OS_USER_DOMAIN_NAME': 'FAKE_OS_USER_DOMAIN_NAME',
        'OS_REGION_NAME': 'FAKE_OS_REGION_NAME',
        'OS_INTERFACE': 'FAKE_OS_INTERFACE'
    }

    # mock_map is populated by the setUp method
    mock_map = {}

    def setUp(self):
        super(SoftwareClientTestCase, self).setUp()

        def _mock_requests_get(*args, **kwargs):
            key = args[0]
            _ = kwargs  # kwargs is unused
            # if the key is not found in the mock_map
            # we return a 404 (not found)
            return self.mock_map.get(key,
                                     FakeResponse(None, 404))

        patcher = mock.patch(
            'requests.get',
            side_effect=_mock_requests_get)
        self.mock_requests_get = patcher.start()
        self.addCleanup(patcher.stop)


class SoftwareClientNonRootMixin(object):
    """
    This Mixin Requires self.MOCK_ENV

    Disable printing to stdout

    Every client call invokes exit which raises SystemExit
    This asserts that happens.
    """

    def _test_method(self, shell_args=None):
        with mock.patch.dict(os.environ, self.MOCK_ENV):
            with mock.patch.object(sys, 'argv', shell_args):
                # mock 'print' so running unit tests will
                # not print to the tox output
                with mock.patch('builtins.print'):
                    # Every client invocation invokes exit
                    # which raises SystemExit
                    self.assertRaises(SystemExit,
                                      software_client.main)


class SoftwareClientHelpTestCase(SoftwareClientTestCase, SoftwareClientNonRootMixin):
    """Test the sw-patch CLI calls that invoke 'help'

    'check_for_os_region_name' is the first method called
    after args are parsed
    print_help is invoked when there is a failure.
    """

    @mock.patch('software.software_client.check_for_os_region_name')
    @mock.patch('argparse.ArgumentParser.print_help')
    @mock.patch('argparse.ArgumentParser.print_usage')
    def test_main_no_args(self, mock_usage, mock_help, mock_check):
        """When no arguments are called, it should call print_usage"""
        shell_args = [self.PROG, ]
        self._test_method(shell_args=shell_args)
        mock_usage.assert_called()
        mock_help.assert_not_called()
        mock_check.assert_not_called()

    @mock.patch('software.software_client.check_for_os_region_name')
    @mock.patch('argparse.ArgumentParser.print_help')
    @mock.patch('argparse.ArgumentParser.print_usage')
    def test_main_help(self, mock_usage, mock_help, mock_check):
        """When -h is passed in, this should invoke print_help"""
        shell_args = [self.PROG, "-h"]
        self._test_method(shell_args=shell_args)
        mock_usage.assert_not_called()
        mock_help.assert_called()
        mock_check.assert_not_called()

    @mock.patch('software.software_client.check_for_os_region_name')
    @mock.patch('argparse.ArgumentParser.print_help')
    @mock.patch('argparse.ArgumentParser.print_usage')
    def test_main_invalid_action_calls_help(self, mock_usage, mock_help, mock_check):
        """invalid args should invoke print_usage"""
        shell_args = [self.PROG, "invalid_arg"]
        self._test_method(shell_args=shell_args)
        mock_usage.assert_called()
        mock_help.assert_not_called()
        mock_check.assert_not_called()
