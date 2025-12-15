#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2019-2022 Wind River Systems, Inc.
#

import json
import mock
import os
import sys
import testtools

from cgcs_patch import patch_client


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
    "patchstate": STATE_NA,
    "reboot_required": PATCH_FLAG_YES,
    "repostate": STATE_APPLIED,
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
    "patchstate": STATE_AVAILABLE,
    "reboot_required": PATCH_FLAG_NO,
    "repostate": STATE_AVAILABLE,
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


class PatchClientTestCase(testtools.TestCase):
    PROG = "sw-patch"

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
        super(PatchClientTestCase, self).setUp()

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


class PatchClientNonRootMixin(object):
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
                                      patch_client.main)


class PatchClientHelpTestCase(PatchClientTestCase, PatchClientNonRootMixin):
    """Test the sw-patch CLI calls that invoke 'help'

    'check_for_os_region_name' is mocked to help determine
    which code path is used since many code paths can short
    circuit and invoke 'help' in failure cases.
    """

    @mock.patch('cgcs_patch.patch_client.check_for_os_region_name')
    def test_main_no_args_calls_help(self, mock_check):
        """When no arguments are called, this should invoke print_help"""
        shell_args = [self.PROG, ]
        self._test_method(shell_args=shell_args)
        mock_check.assert_not_called()

    @mock.patch('cgcs_patch.patch_client.check_for_os_region_name')
    def test_main_help(self, mock_check):
        """When no arguments are called, this should invoke print_help"""
        shell_args = [self.PROG, "--help"]
        self._test_method(shell_args=shell_args)
        mock_check.assert_called()

    @mock.patch('cgcs_patch.patch_client.check_for_os_region_name')
    def test_main_invalid_action_calls_help(self, mock_check):
        """invalid args should invoke print_help"""
        shell_args = [self.PROG, "invalid_arg"]
        self._test_method(shell_args=shell_args)
        mock_check.assert_called()


class PatchClientQueryTestCase(PatchClientTestCase, PatchClientNonRootMixin):
    """Test the sw-patch CLI calls that invoke 'query'"""

    TEST_URL_ALL = "http://127.0.0.1:5487/patch/query?show=all"
    TEST_PATCH_DATA_SHOW_ALL = {
        "pd": {
            FAKE_PATCH_ID_1: FAKE_PATCH_1_META,
            FAKE_PATCH_ID_2: FAKE_PATCH_2_META,
        }
    }

    TEST_URL_APPLIED = "http://127.0.0.1:5487/patch/query?show=applied"
    TEST_PATCH_DATA_SHOW_APPLIED = {
        "pd": {
            FAKE_PATCH_ID_1: FAKE_PATCH_1_META,
        }
    }

    def setUp(self):
        super(PatchClientQueryTestCase, self).setUp()
        # update the mock_map with a query result
        self.mock_map[self.TEST_URL_ALL] = FakeResponse(
            self.TEST_PATCH_DATA_SHOW_ALL, 200)
        self.mock_map[self.TEST_URL_APPLIED] = FakeResponse(
            self.TEST_PATCH_DATA_SHOW_APPLIED, 200)

    def test_query(self):
        shell_args = [self.PROG, "query"]
        self._test_method(shell_args=shell_args)
        self.mock_requests_get.assert_called_with(
            self.TEST_URL_ALL,
            headers=mock.ANY)

    def test_query_patch(self):
        shell_args = [self.PROG, "query", "applied"]
        self._test_method(shell_args=shell_args)
        self.mock_requests_get.assert_called_with(
            self.TEST_URL_APPLIED,
            headers=mock.ANY)


class PatchClientWhatRequiresTestCase(PatchClientTestCase, PatchClientNonRootMixin):

    TEST_URL_VALID = "http://127.0.0.1:5487/patch/what_requires/" + FAKE_PATCH_ID_1
    TEST_WHAT_REQUIRES_VALID = {
        "error": "",
        "info": FAKE_PATCH_ID_1 + " is not required by any patches.\n",
        "warning": ""
    }

    TEST_URL_INVALID = "http://127.0.0.1:5487/patch/what_requires/" + FAKE_PATCH_ID_2
    TEST_WHAT_REQUIRES_INVALID = {
        "error": "Patch " + FAKE_PATCH_ID_2 + " does not exist\n",
        "info": "",
        "warning": ""
    }

    def setUp(self):
        super(PatchClientWhatRequiresTestCase, self).setUp()
        # update the mock_map with a query result
        self.mock_map[self.TEST_URL_VALID] = FakeResponse(
            self.TEST_WHAT_REQUIRES_VALID, 200)
        self.mock_map[self.TEST_URL_INVALID] = FakeResponse(
            self.TEST_WHAT_REQUIRES_INVALID, 200)

    def test_what_requires(self):
        shell_args = [self.PROG, "what-requires", FAKE_PATCH_ID_1]
        self._test_method(shell_args=shell_args)
        self.mock_requests_get.assert_called_with(
            self.TEST_URL_VALID,
            headers=mock.ANY)

    def test_what_requires_debug(self):
        shell_args = [self.PROG, "--debug", "what-requires", FAKE_PATCH_ID_1]
        self._test_method(shell_args=shell_args)
        self.mock_requests_get.assert_called_with(
            self.TEST_URL_VALID,
            headers=mock.ANY)

    def test_what_requires_not_found(self):
        shell_args = [self.PROG, "what-requires", FAKE_PATCH_ID_2]
        self._test_method(shell_args=shell_args)
        self.mock_requests_get.assert_called_with(
            self.TEST_URL_INVALID,
            headers=mock.ANY)


class PatchClientQueryHostsTestCase(PatchClientTestCase, PatchClientNonRootMixin):

    TEST_URL = "http://127.0.0.1:5487/patch/query_hosts"
    TEST_RESULTS = {'data': [
        {
            "allow_insvc_patching": 'true',
            "hostname": "controller-0",
            "interim_state": 'false',
            "ip": "192.168.204.3",
            "latest_sysroot_commit": "4b26afcf716f1804e70222a5564c2174340c2c6aabae9bcabe3468b2ce309d87",
            "nodetype": "controller",
            "patch_current": 'true',
            "patch_failed": 'false',
            "requires_reboot": 'false',
            "secs_since_ack": 17,
            "stale_details": 'false',
            "state": "idle",
            "subfunctions": [
                "controller",
                "worker"
            ],
            "sw_version": "12.34"
        },
        {
            "allow_insvc_patching": 'true',
            "hostname": "controller-1",
            "interim_state": 'false',
            "ip": "192.168.204.4",
            "latest_sysroot_commit": "4b26afcf716f1804e70222a5564c2174340c2c6aabae9bcabe3468b2ce309d87",
            "nodetype": "controller",
            "patch_current": 'true',
            "patch_failed": 'false',
            "requires_reboot": 'false',
            "secs_since_ack": 17,
            "stale_details": 'false',
            "state": "idle",
            "subfunctions": [
                "controller",
                "worker"
            ],
            "sw_version": "12.34"
        }
    ]}

    def setUp(self):
        super(PatchClientQueryHostsTestCase, self).setUp()
        # update the mock_map with a query result
        self.mock_map[self.TEST_URL] = FakeResponse(
            self.TEST_RESULTS, 200)

    def test_query_hosts(self):
        shell_args = [self.PROG, "query-hosts"]
        self._test_method(shell_args=shell_args)
        # for some reason, this does not pass a HEADER
        self.mock_requests_get.assert_called_with(
            self.TEST_URL)
