#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2019-2022 Wind River Systems, Inc.
#

import mock
import socket
import testtools

import cgcs_patch.constants
import cgcs_patch.patch_functions
import cgcs_patch.utils


class CgcsPatchUtilsTestCase(testtools.TestCase):

    def test_if_nametoindex_loopback(self):
        result = cgcs_patch.utils.if_nametoindex('lo')
        self.assertGreater(result, 0)

    def test_if_nametoindex_failure(self):
        result = cgcs_patch.utils.if_nametoindex('xfakeifx')
        self.assertEqual(result, 0)

    def test_gethostbyname(self):
        result = cgcs_patch.utils.gethostbyname('localhost')
        self.assertIn(result, ['127.0.0.1', '::1'])

    def test_gethostbyname_failure(self):
        result = cgcs_patch.utils.gethostbyname('xfakehostx')
        self.assertIsNone(result)

    @mock.patch('cgcs_patch.utils.gethostbyname')
    def test_get_management_version_ipv4(self, mock_gethostbyname):
        mock_gethostbyname.return_value = '192.168.204.2'
        expected_result = cgcs_patch.constants.ADDRESS_VERSION_IPV4

        result = cgcs_patch.utils.get_management_version()
        self.assertEqual(expected_result, result)

    @mock.patch('cgcs_patch.utils.gethostbyname')
    def test_get_management_version_ipv6(self, mock_gethostbyname):
        mock_gethostbyname.return_value = 'fe80::2e44:fdff:fe84:5479'
        expected_result = cgcs_patch.constants.ADDRESS_VERSION_IPV6

        result = cgcs_patch.utils.get_management_version()
        self.assertEqual(expected_result, result)

    @mock.patch('cgcs_patch.utils.gethostbyname')
    def test_get_management_version_ipv4_default(self, mock_gethostbyname):
        mock_gethostbyname.return_value = None
        expected_result = cgcs_patch.constants.ADDRESS_VERSION_IPV4

        result = cgcs_patch.utils.get_management_version()
        self.assertEqual(expected_result, result)

    @mock.patch('cgcs_patch.utils.gethostbyname')
    def test_get_management_family_ipv4(self, mock_gethostbyname):
        mock_gethostbyname.return_value = '192.168.204.2'
        expected_result = socket.AF_INET

        result = cgcs_patch.utils.get_management_family()
        self.assertEqual(expected_result, result)

    @mock.patch('cgcs_patch.utils.gethostbyname')
    def test_get_management_family_ipv6(self, mock_gethostbyname):
        mock_gethostbyname.return_value = 'fe80::2e44:fdff:fe84:5479'
        expected_result = socket.AF_INET6

        result = cgcs_patch.utils.get_management_family()
        self.assertEqual(expected_result, result)

    @mock.patch('cgcs_patch.utils.gethostbyname')
    def test_get_management_version_ipv4_int(self, mock_gethostbyname):
        mock_gethostbyname.return_value = 0xc0a8cc02
        expected_result = socket.AF_INET

        result = cgcs_patch.utils.get_management_family()
        self.assertEqual(expected_result, result)

    @mock.patch('cgcs_patch.utils.gethostbyname')
    def test_get_versioned_address_all_ipv4(self, mock_gethostbyname):
        mock_gethostbyname.return_value = '192.168.204.2'
        expected_result = '0.0.0.0'

        result = cgcs_patch.utils.get_versioned_address_all()
        self.assertEqual(expected_result, result)

    @mock.patch('cgcs_patch.utils.gethostbyname')
    def test_get_versioned_address_all_ipv6(self, mock_gethostbyname):
        mock_gethostbyname.return_value = 'fe80::2e44:fdff:fe84:5479'
        expected_result = '::'

        result = cgcs_patch.utils.get_versioned_address_all()
        self.assertEqual(expected_result, result)

    def test_ip_to_url_ipv4(self):
        ip = '192.168.204.2'
        expected_result = ip

        result = cgcs_patch.utils.ip_to_url(ip)
        self.assertEqual(expected_result, result)

    def test_ip_to_url_ipv6(self):
        ip = 'fe80::2e44:fdff:fe84:5479'
        expected_result = '[%s]' % ip

        result = cgcs_patch.utils.ip_to_url(ip)
        self.assertEqual(expected_result, result)

    def test_ip_to_url_invalid(self):
        ip = 'not-an-ip'
        expected_result = ip

        result = cgcs_patch.utils.ip_to_url(ip)
        self.assertEqual(expected_result, result)

    def test_ip_to_versioned_localhost_ipv4(self):
        ip = '192.168.204.2'
        expected_result = 'localhost'

        result = cgcs_patch.utils.ip_to_versioned_localhost(ip)
        self.assertEqual(expected_result, result)

    def test_ip_to_versioned_localhost_ipv6(self):
        ip = 'fe80::2e44:fdff:fe84:5479'
        expected_result = '::1'

        result = cgcs_patch.utils.ip_to_versioned_localhost(ip)
        self.assertEqual(expected_result, result)
