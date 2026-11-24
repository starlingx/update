#!/usr/bin/env python
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""Tests for the move-release-metadata-file delete-action upgrade script."""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# The script lives in n-1/, the stx12 -> stx14 (N-2) upgrade path
UPGRADE_SCRIPTS_DIR = os.path.normpath(os.path.join(
    os.path.dirname(__file__), "..", "..", "upgrade-scripts", "n-1"
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


_mod = _load_script("99-move-release-metadata-file.py")


class TestMoveReleaseMetadataFile(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.old_dir = root / "metadata"
        self.new_dir = root / "releases" / "metadata"
        for state in ("available", "unavailable", "deploying"):
            (self.old_dir / state).mkdir(parents=True)
        patcher_old = patch.object(_mod, "OLD_METADATA_DIR", self.old_dir)
        patcher_new = patch.object(_mod, "NEW_METADATA_DIR", self.new_dir)
        patcher_old.start()
        patcher_new.start()
        self.addCleanup(patcher_old.stop)
        self.addCleanup(patcher_new.stop)
        self.addCleanup(self._tmp.cleanup)

    def _add(self, state, name):
        path = self.old_dir / state / name
        path.write_text("<product/>")
        return path

    def test_moves_ga_release_metadata(self):
        src = self._add("available", "starlingx-26.10.0-metadata.xml")
        _mod.do_delete("26.10")
        self.assertFalse(src.exists())
        self.assertTrue((self.new_dir / src.name).exists())

    def test_moves_prepatched_release_metadata(self):
        src = self._add("available", "starlingx-26.10.100-metadata.xml")
        _mod.do_delete("26.10")
        self.assertFalse(src.exists())
        self.assertTrue((self.new_dir / src.name).exists())

    def test_keeps_other_release_metadata(self):
        self._add("available", "starlingx-26.10.100-metadata.xml")
        older = self._add("unavailable", "starlingx-26.03.200-metadata.xml")
        similar = self._add("available", "starlingx-26.100.0-metadata.xml")
        _mod.do_delete("26.10")
        self.assertTrue(older.exists())
        self.assertTrue(similar.exists())
        self.assertEqual(sorted(p.name for p in self.new_dir.iterdir()),
                         ["starlingx-26.10.100-metadata.xml"])

    def test_continues_when_one_move_fails(self):
        first = self._add("available", "starlingx-26.10.100-metadata.xml")
        second = self._add("deploying", "wrcp-26.10.100-metadata.xml")
        real_move = _mod.shutil.move

        def flaky_move(src, dst):
            if src == str(first):
                raise OSError("simulated failure")
            return real_move(src, dst)

        with patch.object(_mod.shutil, "move", side_effect=flaky_move):
            self.assertRaises(RuntimeError, _mod.do_delete, "26.10")
        self.assertTrue(first.exists())
        self.assertFalse(second.exists())
        self.assertTrue((self.new_dir / second.name).exists())

    def test_raises_when_no_metadata_found(self):
        self._add("unavailable", "starlingx-26.03.200-metadata.xml")
        self.assertRaises(FileNotFoundError, _mod.do_delete, "26.10")


if __name__ == "__main__":
    unittest.main()
