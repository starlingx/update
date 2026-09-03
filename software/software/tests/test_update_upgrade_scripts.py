#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for upgrade-scripts directory."""

import os
import unittest

from software.tests import base as test_base  # noqa: F401

UPGRADE_SCRIPTS_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..', 'upgrade-scripts')
)


class TestUpgradeScripts(unittest.TestCase):
    """Validate upgrade-scripts exist, are executable,
    and have shebangs.
    """

    scripts = []

    @classmethod
    def setUpClass(cls):
        cls.scripts = sorted(
            f for f in os.listdir(UPGRADE_SCRIPTS_DIR)
            if os.path.isfile(os.path.join(UPGRADE_SCRIPTS_DIR, f))
            and os.access(os.path.join(UPGRADE_SCRIPTS_DIR, f), os.X_OK)
            and not f.startswith("__")
        )

    def test_scripts_directory_exists(self):
        """Test that the upgrade-scripts directory exists."""
        self.assertTrue(
            os.path.isdir(UPGRADE_SCRIPTS_DIR),
            f"Directory not found: {UPGRADE_SCRIPTS_DIR}"
        )

    def test_scripts_found(self):
        """Test that at least one upgrade script is present."""
        self.assertGreater(
            len(self.scripts), 0,
            "No scripts found in upgrade-scripts directory"
        )

    def test_each_script_has_valid_shebang(self):
        """Test that each script starts with a valid shebang line."""
        for script in self.scripts:
            path = os.path.join(UPGRADE_SCRIPTS_DIR, script)
            with open(path, 'r', encoding='utf-8') as f:
                first_line = f.readline().strip()
            self.assertTrue(
                first_line.startswith('#!'),
                f"Missing or invalid shebang in {script}: {first_line}"
            )
