#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for software.utils module - extended coverage."""

import socket
import unittest
from unittest import mock

from software.tests import base  # noqa: F401
from software.utils import check_instances
from software.utils import check_state
from software.utils import compare_release_version
from software.utils import get_all_files
from software.utils import get_component_and_versions
from software.utils import get_feed_path
from software.utils import get_major_release_version
from software.utils import get_management_version
from software.utils import get_software_filesystem_data
from software.utils import get_synced_software_filesystem_data
from software.utils import get_versioned_address_all
from software.utils import gethostbyname
from software.utils import if_nametoindex
from software.utils import ip_to_url
from software.utils import ip_to_versioned_localhost
from software.utils import is_upgrade_deploy
from software.utils import load_from_json_file
from software.utils import safe_rstrip
from software.utils import validate_versions
from software.utils import get_iface_ip
from software.utils import get_management_family
from software.exceptions import StateValidationFailure
from enum import Enum


class TestGetMajorReleaseVersion(unittest.TestCase):
    """Tests for get_major_release_version."""

    def test_valid_version(self):
        """Test valid version string."""
        self.assertEqual(get_major_release_version("24.09.1"), "24.09")

    def test_two_part_version(self):
        """Test two-part version string."""
        self.assertEqual(get_major_release_version("24.09"), "24.09")

    def test_empty_string(self):
        """Test empty string returns None."""
        self.assertIsNone(get_major_release_version(""))

    def test_none_input(self):
        """Test None input returns None."""
        self.assertIsNone(get_major_release_version(None))

    def test_single_number(self):
        """Test single number returns None."""
        self.assertIsNone(get_major_release_version("24"))


class TestCompareReleaseVersion(unittest.TestCase):
    """Tests for compare_release_version."""

    def test_first_higher(self):
        """Test first version higher."""
        self.assertTrue(compare_release_version("24.09.1", "24.09.0"))

    def test_second_higher(self):
        """Test second version higher."""
        self.assertFalse(compare_release_version("24.09.0", "24.09.1"))

    def test_equal_versions(self):
        """Test equal versions."""
        self.assertFalse(compare_release_version("24.09.0", "24.09.0"))

    def test_none_first(self):
        """Test None first argument."""
        self.assertIsNone(compare_release_version(None, "24.09.0"))

    def test_none_second(self):
        """Test None second argument."""
        self.assertIsNone(compare_release_version("24.09.0", None))

    def test_invalid_version(self):
        """Test invalid version string."""
        self.assertIsNone(compare_release_version("invalid", "24.09.0"))


class TestGethostbyname(unittest.TestCase):
    """Tests for gethostbyname."""

    @mock.patch('socket.getaddrinfo')
    def test_valid_hostname(self, mock_getaddrinfo):
        """Test valid hostname resolution."""
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, 0, 0, '', ('192.168.1.1', 0))
        ]
        self.assertEqual(gethostbyname("controller"), "192.168.1.1")

    @mock.patch('socket.getaddrinfo', side_effect=Exception("DNS fail"))
    def test_invalid_hostname(self, _mock):
        """Test invalid hostname returns None."""
        self.assertIsNone(gethostbyname("invalid-host"))


class TestIfNametoindex(unittest.TestCase):
    """Tests for if_nametoindex."""

    @mock.patch('socket.if_nametoindex', return_value=2)
    def test_valid_interface(self, _mock):
        """Test valid interface name."""
        self.assertEqual(if_nametoindex("eth0"), 2)

    @mock.patch('socket.if_nametoindex', side_effect=Exception("no iface"))
    def test_invalid_interface(self, _mock):
        """Test invalid interface returns 0."""
        self.assertEqual(if_nametoindex("invalid"), 0)


class TestGetManagementVersion(unittest.TestCase):
    """Tests for get_management_version."""

    @mock.patch('software.utils.gethostbyname', return_value='192.168.1.1')
    def test_ipv4(self, _mock):
        """Test IPv4 management."""
        self.assertEqual(get_management_version(), 4)

    @mock.patch('software.utils.gethostbyname', return_value='::1')
    def test_ipv6(self, _mock):
        """Test IPv6 management."""
        self.assertEqual(get_management_version(), 6)

    @mock.patch('software.utils.gethostbyname', return_value=None)
    def test_no_resolution(self, _mock):
        """Test no resolution defaults to IPv4."""
        self.assertEqual(get_management_version(), 4)


class TestGetManagementFamily(unittest.TestCase):
    """Tests for get_management_family."""

    @mock.patch('software.utils.get_management_version', return_value=4)
    def test_ipv4_family(self, _mock):
        """Test IPv4 returns AF_INET."""
        self.assertEqual(get_management_family(), socket.AF_INET)

    @mock.patch('software.utils.get_management_version', return_value=6)
    def test_ipv6_family(self, _mock):
        """Test IPv6 returns AF_INET6."""
        self.assertEqual(get_management_family(), socket.AF_INET6)


class TestGetVersionedAddressAll(unittest.TestCase):
    """Tests for get_versioned_address_all."""

    @mock.patch('software.utils.get_management_version', return_value=4)
    def test_ipv4_all(self, _mock):
        """Test IPv4 all address."""
        self.assertEqual(get_versioned_address_all(), "0.0.0.0")

    @mock.patch('software.utils.get_management_version', return_value=6)
    def test_ipv6_all(self, _mock):
        """Test IPv6 all address."""
        self.assertEqual(get_versioned_address_all(), "::")


class TestIpToUrl(unittest.TestCase):
    """Tests for ip_to_url."""

    def test_ipv4(self):
        """Test IPv4 address unchanged."""
        self.assertEqual(ip_to_url("192.168.1.1"), "192.168.1.1")

    def test_ipv6(self):
        """Test IPv6 address gets brackets."""
        self.assertEqual(ip_to_url("::1"), "[::1]")

    def test_invalid_ip(self):
        """Test invalid IP returns as-is."""
        self.assertEqual(ip_to_url("not-an-ip"), "not-an-ip")


class TestIpToVersionedLocalhost(unittest.TestCase):
    """Tests for ip_to_versioned_localhost."""

    def test_ipv4(self):
        """Test IPv4 returns localhost."""
        self.assertEqual(ip_to_versioned_localhost("192.168.1.1"),
                         "localhost")

    def test_ipv6(self):
        """Test IPv6 returns ::1."""
        self.assertEqual(ip_to_versioned_localhost("::1"), "::1")


class TestSafeRstrip(unittest.TestCase):
    """Tests for safe_rstrip."""

    def test_normal_strip(self):
        """Test normal rstrip."""
        self.assertEqual(safe_rstrip("hello   "), "hello")

    def test_strip_specific_chars(self):
        """Test strip specific characters."""
        self.assertEqual(safe_rstrip("hello///", "/"), "hello")

    def test_would_make_empty(self):
        """Test strip that would make string empty returns original."""
        self.assertEqual(safe_rstrip("///", "/"), "///")

    def test_non_string_input(self):
        """Test non-string input returns original."""
        self.assertEqual(safe_rstrip(123), 123)


class TestGetComponentAndVersionsExtended(unittest.TestCase):
    """Extended tests for get_component_and_versions."""

    def test_component_with_three_part_version(self):
        """Test component with full version."""
        result = get_component_and_versions("starlingx-24.09.1")
        self.assertEqual(result, ("starlingx", "24.09.1", "24.09", "1"))

    def test_no_component_two_part(self):
        """Test version without component, two parts."""
        result = get_component_and_versions("24.09")
        self.assertEqual(result, (None, "24.09.0", "24.09", "0"))

    def test_completely_invalid(self):
        """Test completely invalid string."""
        result = get_component_and_versions("abc")
        self.assertEqual(result, (None, None, None, None))


class TestGetFeedPath(unittest.TestCase):
    """Tests for get_feed_path."""

    def test_feed_path(self):
        """Test feed path generation."""
        path = get_feed_path("24.09.1")
        self.assertIn("rel-24.09", path)


class TestIsUpgradeDeploy(unittest.TestCase):
    """Tests for is_upgrade_deploy."""

    def test_same_major_minor(self):
        """Test same major.minor is not upgrade."""
        self.assertFalse(is_upgrade_deploy("24.09.0", "24.09.1"))

    def test_different_minor(self):
        """Test different minor is upgrade."""
        self.assertTrue(is_upgrade_deploy("24.03.0", "24.09.0"))

    def test_different_major(self):
        """Test different major is upgrade."""
        self.assertTrue(is_upgrade_deploy("23.09.0", "24.09.0"))


class TestSaveLoadJsonFile(unittest.TestCase):
    """Tests for save_to_json_file and load_from_json_file."""

    @mock.patch('builtins.open', mock.mock_open(read_data='{"key": "val"}'))
    @mock.patch('os.path.exists', return_value=True)
    def test_load_from_json(self, _mock_exists):
        """Test loading data from JSON file."""
        # load_from_json_file opens the file directly
        result = load_from_json_file("/tmp/test.json")
        self.assertEqual(result, {"key": "val"})

    @mock.patch('os.path.exists', return_value=False)
    def test_load_file_not_found(self, _mock):
        """Test loading non-existent file."""
        result = load_from_json_file("/tmp/nonexistent.json")
        self.assertIsNone(result)


class TestCheckState(unittest.TestCase):
    """Tests for check_state."""

    def test_invalid_state(self):
        """Test invalid state raises."""
        States = Enum('States', 'active deploying inactive')
        with self.assertRaises(StateValidationFailure):
            check_state('unknown', States)


class TestCheckInstances(unittest.TestCase):
    """Tests for check_instances."""

    def test_invalid_instances(self):
        """Test invalid instances raise ValueError."""
        with self.assertRaises(ValueError):
            check_instances([1, "b"], str)


class TestValidateVersions(unittest.TestCase):
    """Tests for validate_versions."""

    def test_invalid_version(self):
        """Test invalid version raises ValueError."""
        with self.assertRaises(ValueError):
            validate_versions(["invalid"])


class TestGetSoftwareFilesystemData(unittest.TestCase):
    """Tests for get_software_filesystem_data."""

    @mock.patch('os.path.exists', return_value=False)
    def test_no_file(self, _mock):
        """Test returns empty dict when file missing."""
        result = get_software_filesystem_data()
        self.assertEqual(result, {})

    @mock.patch('os.path.exists', return_value=True)
    @mock.patch('software.utils.load_from_json_file',
                return_value={"key": "val"})
    def test_with_file(self, _mock_load, _mock_exists):
        """Test returns data when file exists."""
        result = get_software_filesystem_data()
        self.assertEqual(result, {"key": "val"})


class TestGetSyncedSoftwareFilesystemData(unittest.TestCase):
    """Tests for get_synced_software_filesystem_data."""

    @mock.patch('os.path.exists', return_value=False)
    def test_no_file(self, _mock):
        """Test returns empty dict when file missing."""
        result = get_synced_software_filesystem_data()
        self.assertEqual(result, {})


class TestGetAllFiles(unittest.TestCase):
    """Tests for get_all_files."""

    @mock.patch('os.listdir', return_value=['a.txt', 'b.txt'])
    def test_get_files(self, _mock):
        """Test getting all files."""
        result = get_all_files("/tmp/test")
        self.assertEqual(len(result), 2)

    @mock.patch('os.listdir', side_effect=Exception("fail"))
    def test_get_files_error(self, _mock):
        """Test error returns empty list."""
        result = get_all_files("/tmp/nonexistent")
        self.assertEqual(result, [])


class TestGetIfaceIp(unittest.TestCase):
    """Tests for get_iface_ip."""

    def test_invalid_iface_name_empty(self):
        """Test empty interface name raises ValueError."""
        with self.assertRaises(ValueError):
            get_iface_ip("")

    def test_invalid_iface_name_none(self):
        """Test None interface name raises ValueError."""
        with self.assertRaises(ValueError):
            get_iface_ip(None)

    def test_invalid_family(self):
        """Test invalid address family raises TypeError."""
        with self.assertRaises(TypeError):
            get_iface_ip("eth0", ip_family=99)

    @mock.patch('psutil.net_if_addrs', return_value={})
    def test_interface_not_found(self, _mock):
        """Test interface not found returns empty list."""
        result = get_iface_ip("nonexistent")
        self.assertEqual(result, [])
