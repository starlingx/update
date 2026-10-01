#!/usr/bin/env python
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""Behavior tests for the delete-action LUKS passphrase-type rollback plugin."""

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock

# Mock external modules not available in the test environment.
for mod_name in [
    "cgtsclient", "cgtsclient.client",
    "sysinv", "sysinv.common", "sysinv.common.kubernetes",
    "sysinv.common.retrying",
]:
    if mod_name not in sys.modules:
        sys.modules[mod_name] = MagicMock()

UPGRADE_SCRIPTS_DIR = os.path.normpath(os.path.join(
    os.path.dirname(__file__), "..", "..", "upgrade-scripts"
))

# plugin_runner.py is installed into upgrade-scripts/ at build time; in the
# source tree symlink it so _loader.py can resolve it.
_plugin_runner_link = os.path.join(UPGRADE_SCRIPTS_DIR, "plugin_runner.py")
_plugin_runner_src = os.path.normpath(os.path.join(
    os.path.dirname(__file__), "..", "utilities", "plugin_runner.py"
))
if not os.path.exists(_plugin_runner_link):
    os.symlink(_plugin_runner_src, _plugin_runner_link)

if UPGRADE_SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, UPGRADE_SCRIPTS_DIR)


def _load_script(filename):
    """Load a numbered upgrade script by filename via importlib."""
    mod_name = filename[:-3].replace("-", "_")
    spec = importlib.util.spec_from_file_location(
        mod_name, os.path.join(UPGRADE_SCRIPTS_DIR, filename)
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


_plugin_mod = _load_script("27-rollback-luks-passphrase-type.py")


class TestRollbackLuksPassphraseType(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._json = os.path.join(self._tmp, "created_luks.json")
        # Point the plugin at a throwaway file.
        self._orig_path = _plugin_mod.CREATED_LUKS_JSON
        _plugin_mod.CREATED_LUKS_JSON = self._json
        self.plugin = _plugin_mod.RollbackLuksPassphraseType()

    def tearDown(self):
        _plugin_mod.CREATED_LUKS_JSON = self._orig_path

    def _write(self, volume):
        with open(self._json, "w") as fp:
            json.dump({"luksvolumes": [volume]}, fp)

    def _read_volume(self):
        with open(self._json) as fp:
            return json.load(fp)["luksvolumes"][0]

    # --- rollback discriminator -------------------------------------------

    def test_is_rollback_true_when_target_older(self):
        self.assertTrue(_plugin_mod._is_rollback("26.10", "26.03"))
        self.assertTrue(_plugin_mod._is_rollback("26.10.0", "25.09.400"))

    def test_is_rollback_false_on_forward_upgrade(self):
        self.assertFalse(_plugin_mod._is_rollback("26.03", "26.10"))
        self.assertFalse(_plugin_mod._is_rollback("25.09.400", "26.10.0"))

    # --- skip when target ships HWID_V2 natively (>= 26.10) ----------------

    def test_skip_for_target_at_or_above_26_10(self):
        self.assertTrue(_plugin_mod._skip_for_native_hwid_v2_target("26.10"))
        self.assertTrue(_plugin_mod._skip_for_native_hwid_v2_target("26.10.0"))
        self.assertTrue(_plugin_mod._skip_for_native_hwid_v2_target("27.03"))
        self.assertTrue(_plugin_mod._skip_for_native_hwid_v2_target("27.03.0"))

    def test_no_skip_for_older_targets(self):
        self.assertFalse(_plugin_mod._skip_for_native_hwid_v2_target("26.03"))
        self.assertFalse(_plugin_mod._skip_for_native_hwid_v2_target("25.09.400"))
        self.assertFalse(_plugin_mod._skip_for_native_hwid_v2_target(None))

    # --- delete-action behavior -------------------------------------------

    def test_rollback_resets_hwid_v2_to_hwid(self):
        self._write({
            "PASSPHRASE_TYPE": "HWID_V2",
            "LEGACY_KEYSLOT_REMOVED": True,
            "VAULT_FILE": "/var/luks/stx/luks_volume.img",
            "VOL_NAME": "luks_encrypted_vault",
        })
        self.plugin._run("26.10", "26.03", "delete", None)
        vol = self._read_volume()
        self.assertEqual(vol["PASSPHRASE_TYPE"], "HWID")
        self.assertNotIn("LEGACY_KEYSLOT_REMOVED", vol)
        # Unrelated fields preserved.
        self.assertEqual(vol["VAULT_FILE"], "/var/luks/stx/luks_volume.img")
        self.assertEqual(vol["VOL_NAME"], "luks_encrypted_vault")

    def test_forward_upgrade_delete_is_noop(self):
        # The delete that finalizes a forward upgrade must not touch the file.
        self._write({
            "PASSPHRASE_TYPE": "HWID_V2",
            "LEGACY_KEYSLOT_REMOVED": True,
        })
        self.plugin._run("26.03", "26.10", "delete", None)
        vol = self._read_volume()
        self.assertEqual(vol["PASSPHRASE_TYPE"], "HWID_V2")
        self.assertIn("LEGACY_KEYSLOT_REMOVED", vol)

    def test_rollback_to_26_10_target_is_noop(self):
        # Framework path: a rollback whose target is 26.10 (native HWID_V2)
        # must not reset the metadata to HWID.
        self._write({
            "PASSPHRASE_TYPE": "HWID_V2",
            "LEGACY_KEYSLOT_REMOVED": True,
        })
        self.plugin._run("27.03.0", "26.10.0", "delete", None)
        vol = self._read_volume()
        self.assertEqual(vol["PASSPHRASE_TYPE"], "HWID_V2")
        self.assertIn("LEGACY_KEYSLOT_REMOVED", vol)

    def test_idempotent_on_already_hwid(self):
        self._write({"PASSPHRASE_TYPE": "HWID"})
        self.plugin._run("26.10", "26.03", "delete", None)
        self.assertEqual(self._read_volume()["PASSPHRASE_TYPE"], "HWID")

    def test_missing_file_is_noop(self):
        # No file present -> must not raise.
        self.assertFalse(os.path.exists(self._json))
        self.plugin._run("26.10", "26.03", "delete", None)
        self.assertFalse(os.path.exists(self._json))

    def test_malformed_json_left_unchanged(self):
        with open(self._json, "w") as fp:
            fp.write("{ not valid json")
        self.plugin._run("26.10", "26.03", "delete", None)
        with open(self._json) as fp:
            self.assertEqual(fp.read(), "{ not valid json")

    def test_missing_luksvolumes_array_left_unchanged(self):
        with open(self._json, "w") as fp:
            json.dump({"something_else": 1}, fp)
        self.plugin._run("26.10", "26.03", "delete", None)
        with open(self._json) as fp:
            self.assertEqual(json.load(fp), {"something_else": 1})

    # --- registration ------------------------------------------------------

    def test_matching_action_is_delete_only(self):
        self.assertTrue(self.plugin.should_run("delete"))
        self.assertFalse(self.plugin.should_run("activate-rollback"))
        self.assertFalse(self.plugin.should_run("migrate"))
        self.assertFalse(self.plugin.should_run("activate"))


if __name__ == "__main__":
    unittest.main()
