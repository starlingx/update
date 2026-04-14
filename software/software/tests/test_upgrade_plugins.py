#!/usr/bin/env python
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import importlib.util
import os
import unittest

# upgrade-scripts directory is not a standard Python package,
# so we load its __init__.py directly via importlib.
UPGRADE_SCRIPTS_DIR = os.path.normpath(os.path.join(
    os.path.dirname(__file__), "..", "..", "upgrade-scripts"
))

_spec = importlib.util.spec_from_file_location(
    "upgrade_scripts",
    os.path.join(UPGRADE_SCRIPTS_DIR, "__init__.py"),
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

PLUGINS = _mod.PLUGINS


class TestPluginsConsistency(unittest.TestCase):

    def _get_files_on_disk(self):
        """Return set of .py/.sh filenames in upgrade-scripts,
           excluding __init__.py and the n-1/ subdirectory.
        """
        return {
            f for f in os.listdir(UPGRADE_SCRIPTS_DIR)
            if os.path.isfile(os.path.join(UPGRADE_SCRIPTS_DIR, f))
            and (f.endswith(".py") or f.endswith(".sh"))
            and f != "__init__.py"
        }

    def _get_files_in_plugins(self):
        """Return set of filenames referenced in PLUGINS,
           excluding n-1/ prefixed entries.
        """
        referenced = set()
        for action_dict in PLUGINS.values():
            for file_list in action_dict.values():
                for entry in file_list:
                    if not entry.startswith("n-1/"):
                        referenced.add(entry)
        return referenced

    def test_all_scripts_are_in_plugins(self):
        """Every .py/.sh file on disk must appear in at least one PLUGINS list."""
        files_on_disk = self._get_files_on_disk()
        files_in_plugins = self._get_files_in_plugins()
        missing = files_on_disk - files_in_plugins
        self.assertEqual(
            missing, set(),
            f"Scripts on disk but not in any PLUGINS list: {sorted(missing)}"
        )

    def test_all_plugins_are_scripts_on_disk(self):
        """Every entry in PLUGINS lists must be a .py/.sh file on disk."""
        files_on_disk = self._get_files_on_disk()
        files_in_plugins = self._get_files_in_plugins()
        extra = files_in_plugins - files_on_disk
        self.assertEqual(
            extra, set(),
            f"Entries in PLUGINS but not on disk: {sorted(extra)}"
        )
