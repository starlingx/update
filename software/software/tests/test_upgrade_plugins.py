#!/usr/bin/env python
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import importlib.util
import os
import sys
import unittest
from unittest.mock import MagicMock

from software.utilities.plugin_runner import APlugin
from software.utilities.plugin_runner import CPlugin
from software.utilities.plugin_runner import ScriptPlugin

# Mock external modules not available in the test environment
for mod_name in [
    "cgtsclient", "cgtsclient.client",
    "controllerconfig", "controllerconfig.common",
    "controllerconfig.common.constants", "controllerconfig.utils",
    "sysinv", "sysinv.common", "sysinv.common.kubernetes",
    "sysinv.common.kube_utils",
    "sysinv.common.retrying",
    "psycopg2", "psycopg2.extras",
    "oslo_config", "oslo_config.cfg",
    "six", "six.moves", "six.moves.configparser",
]:
    if mod_name not in sys.modules:
        sys.modules[mod_name] = MagicMock()

# upgrade-scripts directory is not a standard Python package,
# so we load its __init__.py directly via importlib.
UPGRADE_SCRIPTS_DIR = os.path.normpath(os.path.join(
    os.path.dirname(__file__), "..", "..", "upgrade-scripts"
))

_spec = importlib.util.spec_from_file_location(
    "upgrade_scripts",
    os.path.join(UPGRADE_SCRIPTS_DIR, "__init__.py"),
    submodule_search_locations=[UPGRADE_SCRIPTS_DIR]
)
_mod = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _mod
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
        """Return set of filenames referenced in PLUGINS.

        For ScriptPlugin instances, extract the basename of the script path.
        For CPlugin subclasses, find the .py file that defines the class.
        """
        referenced = set()
        for action_dict in PLUGINS.values():
            for plugin_list in action_dict.values():
                for plugin in plugin_list:
                    if isinstance(plugin, ScriptPlugin):
                        referenced.add(os.path.basename(plugin.name))
                    elif isinstance(plugin, CPlugin):
                        module = type(plugin).__module__
                        mod_name = module.rsplit('.', 1)[-1]
                        referenced.add(mod_name + ".py")
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
        """Every entry in PLUGINS lists must correspond to a file on disk."""
        files_on_disk = self._get_files_on_disk()
        files_in_plugins = self._get_files_in_plugins()
        extra = files_in_plugins - files_on_disk
        self.assertEqual(
            extra, set(),
            f"Entries in PLUGINS but not on disk: {sorted(extra)}"
        )

    def test_all_plugins_are_aplugin_instances(self):
        """Every entry in PLUGINS must be an APlugin instance."""
        for action, action_dict in PLUGINS.items():
            for stage, plugin_list in action_dict.items():
                for plugin in plugin_list:
                    self.assertIsInstance(
                        plugin, APlugin,
                        f"PLUGINS[{action}][{stage}] contains non-APlugin: {plugin}"
                    )
