#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for software.utils — pure logic functions.

Tests actual return values, edge cases, error handling.
No mock-only tests.
"""

import os
import unittest

from software.tests import base  # noqa: F401
from software.exceptions import StateValidationFailure
from software.states import DEPLOY_STATES
from software.utils import check_state
from software.utils import check_instances
from software.utils import get_feed_path
from software.utils import get_patch_level_version
from software.utils import get_precheck_script
from software.utils import ip_to_url
from software.utils import ip_to_versioned_localhost
from software.utils import is_upgrade_deploy
from software.utils import parse_release_version
from software.utils import safe_rstrip
from software.utils import validate_versions
from software import constants


class TestGetPatchLevelVersion(unittest.TestCase):
    """Tests for get_patch_level_version."""

    def test_major_only_appends_zero(self):
        """MM.mm format gets .0 appended."""
        self.assertEqual(get_patch_level_version("24.09"), "24.09.0")

    def test_full_version_unchanged(self):
        """MM.mm.pp format returned unchanged."""
        self.assertEqual(get_patch_level_version("24.09.1"), "24.09.1")

    def test_empty_returns_empty(self):
        """Empty string returns empty."""
        self.assertEqual(get_patch_level_version(""), "")

    def test_none_returns_none(self):
        """None returns None."""
        self.assertIsNone(get_patch_level_version(None))

    def test_non_version_string_unchanged(self):
        """Non-matching string returned unchanged."""
        self.assertEqual(get_patch_level_version("abc"), "abc")


class TestIsUpgradeDeploy(unittest.TestCase):
    """Tests for is_upgrade_deploy — determines if deployment is
    a major upgrade vs patch.
    """

    def test_same_major_minor_is_patch(self):
        """Same MM.mm means patch (not upgrade)."""
        self.assertFalse(is_upgrade_deploy("24.09.0", "24.09.1"))

    def test_different_minor_is_upgrade(self):
        """Different minor version is upgrade."""
        self.assertTrue(is_upgrade_deploy("24.09.0", "24.12.0"))

    def test_different_major_is_upgrade(self):
        """Different major version is upgrade."""
        self.assertTrue(is_upgrade_deploy("24.09.0", "25.03.0"))

    def test_same_version_is_not_upgrade(self):
        """Identical versions is not upgrade."""
        self.assertFalse(is_upgrade_deploy("24.09.0", "24.09.0"))


class TestValidateVersions(unittest.TestCase):
    """Tests for validate_versions — input validation."""

    def test_valid_versions(self):
        """Valid version list does not raise."""
        validate_versions(["24.09", "24.09.1", "25.03.0"])

    def test_invalid_version_raises(self):
        """Non-numeric version raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            validate_versions(["24.09", "invalid"])
        self.assertIn("Invalid version", str(ctx.exception))

    def test_empty_list_passes(self):
        """Empty list does not raise."""
        validate_versions([])

    def test_letters_in_version_raises(self):
        """Letters mixed with numbers raises."""
        with self.assertRaises(ValueError):
            validate_versions(["24.0a.1"])

    def test_single_number_raises(self):
        """Single number without dot raises."""
        with self.assertRaises(ValueError):
            validate_versions(["24"])


class TestCheckState(unittest.TestCase):
    """Tests for check_state — enum validation."""

    def test_valid_state(self):
        """Valid state does not raise."""
        check_state("START", DEPLOY_STATES)

    def test_invalid_state_raises(self):
        """Invalid state raises StateValidationFailure."""
        with self.assertRaises(StateValidationFailure) as ctx:
            check_state("nonexistent", DEPLOY_STATES)
        self.assertIn("not in valid states", str(ctx.exception))


class TestCheckInstances(unittest.TestCase):
    """Tests for check_instances — type validation."""

    def test_valid_instances(self):
        """All matching types does not raise."""
        check_instances(["a", "b", "c"], str)

    def test_invalid_instance_raises(self):
        """Non-matching type raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            check_instances(["a", 123, "c"], str)
        self.assertIn("must be type", str(ctx.exception))


class TestSafeRstrip(unittest.TestCase):
    """Tests for safe_rstrip — strip that won't empty the string."""

    def test_normal_strip(self):
        """Strips trailing chars normally."""
        self.assertEqual(safe_rstrip("hello///", "/"), "hello")

    def test_does_not_empty(self):
        """Won't strip to empty — returns original."""
        self.assertEqual(safe_rstrip("///", "/"), "///")

    def test_non_string_returns_original(self):
        """Non-string input returned unchanged."""
        self.assertEqual(safe_rstrip(123), 123)

    def test_no_chars_strips_whitespace(self):
        """No chars argument strips whitespace."""
        self.assertEqual(safe_rstrip("hello   "), "hello")


class TestIpToUrl(unittest.TestCase):
    """Tests for ip_to_url — IPv6 bracket handling."""

    def test_ipv4_unchanged(self):
        """IPv4 address returned unchanged."""
        self.assertEqual(ip_to_url("192.168.1.1"), "192.168.1.1")

    def test_ipv6_gets_brackets(self):
        """IPv6 address gets brackets."""
        self.assertEqual(ip_to_url("fd00::1"), "[fd00::1]")

    def test_loopback_v6(self):
        """IPv6 loopback gets brackets."""
        self.assertEqual(ip_to_url("::1"), "[::1]")

    def test_invalid_returns_as_is(self):
        """Invalid IP string returned as-is (no crash)."""
        self.assertEqual(ip_to_url("not_an_ip"), "not_an_ip")


class TestIpToVersionedLocalhost(unittest.TestCase):
    """Tests for ip_to_versioned_localhost."""

    def test_ipv4_returns_localhost(self):
        """IPv4 returns 'localhost'."""
        self.assertEqual(ip_to_versioned_localhost("192.168.1.1"), "localhost")

    def test_ipv6_returns_loopback(self):
        """IPv6 returns '::1'."""
        self.assertEqual(ip_to_versioned_localhost("fd00::1"), "::1")


class TestParseReleaseVersion(unittest.TestCase):
    """Tests for parse_release_version — strips component prefix."""

    def test_plain_version(self):
        """Plain version string parsed."""
        v = parse_release_version("24.09.0")
        self.assertEqual(str(v), "24.9.0")

    def test_with_component_prefix(self):
        """Component prefix stripped before parsing."""
        v = parse_release_version("starlingx-24.09.1")
        self.assertEqual(str(v), "24.9.1")

    def test_comparison_works(self):
        """Parsed versions support comparison."""
        v1 = parse_release_version("starlingx-24.09.0")
        v2 = parse_release_version("starlingx-25.03.0")
        self.assertLess(v1, v2)


class TestGetFeedPath(unittest.TestCase):
    """Tests for get_feed_path — path construction."""

    def test_constructs_correct_path(self):
        """Builds correct feed path from version."""
        path = get_feed_path("24.09.1")
        expected = os.path.join(constants.UPGRADE_FEED_DIR, "rel-24.09")
        self.assertEqual(path, expected)

    def test_major_version_only(self):
        """Works with major version input."""
        path = get_feed_path("24.09")
        expected = os.path.join(constants.UPGRADE_FEED_DIR, "rel-24.09")
        self.assertEqual(path, expected)


class TestGetPrecheckScript(unittest.TestCase):
    """Tests for get_precheck_script — path construction."""

    def test_without_metapackage(self):
        """Without metapackage, uses legacy bin path."""
        path = get_precheck_script("24.09")
        self.assertIn("rel-24.09/bin", path)
        self.assertTrue(path.endswith(constants.DEPLOY_PRECHECK_SCRIPT))

    def test_with_metapackage(self):
        """With metapackage, uses component path."""
        path = get_precheck_script("24.09.0", metapackage="platform")
        self.assertIn("24.09.0/platform", path)
        self.assertIn(constants.SUPPORT_SCRIPTS_DIR, path)
        self.assertTrue(path.endswith(constants.DEPLOY_PRECHECK_SCRIPT))
