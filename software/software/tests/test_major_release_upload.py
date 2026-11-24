#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2026 Wind River Systems, Inc.
#

import contextlib
import importlib.machinery
import importlib.util
import io
import os
import sys
import unittest
from unittest import mock

SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                           "..", "..", "scripts"))


def _load_module(name, filename):
    """Load a script from the scripts dir, which may have no .py extension"""
    path = os.path.join(SCRIPTS_DIR, filename)
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


def load_modules():
    sys.path.insert(0, SCRIPTS_DIR)
    try:
        upgrade_utils = _load_module("upgrade_utils", "upgrade_utils.py")
        # The script creates directories under /opt/software at import time
        with mock.patch("pathlib.Path.mkdir"):
            script = _load_module("major_release_upload", "major-release-upload")
    finally:
        sys.path.remove(SCRIPTS_DIR)
    return upgrade_utils, script


upgrade_utils, major_release_upload = load_modules()


class TestPrintMetapackageOutput(unittest.TestCase):

    def _print(self, common_ids, pud_ids):
        """Run print_metapackage_output; return printed lines and logged messages"""
        stdout = io.StringIO()
        with mock.patch.object(major_release_upload, "LOG") as mock_log, \
                contextlib.redirect_stdout(stdout):
            major_release_upload.print_metapackage_output(common_ids, pud_ids)
        logged = [c.args[0] for c in mock_log.info.call_args_list]
        return stdout.getvalue().splitlines(), logged

    def _assert_no_per_metapackage_line(self, lines):
        for line in lines:
            self.assertNotRegex(line, r"^Uploaded \S+ metapackage release$")
            self.assertNotRegex(
                line, r"^Uploading \S+ pre-upgrade-deploy metapackage release$")

    def test_common_and_pud_prints_both_summaries_common_first(self):
        common = [f"mp{i:02d}" for i in range(25)]
        pud = [f"pud{i:02d}" for i in range(7)]
        lines, logged = self._print(common, pud)

        self.assertEqual([
            "Uploaded 25 metapackage releases",
            "Uploaded 7 pre-upgrade-deploy metapackage releases",
        ], lines)
        self._assert_no_per_metapackage_line(lines)
        self.assertEqual(32, len(logged))
        for mp_id in common:
            self.assertIn(f"Uploaded {mp_id} metapackage release", logged)
        for mp_id in pud:
            self.assertIn(
                f"Uploading {mp_id} pre-upgrade-deploy metapackage release",
                logged)

    def test_common_only_prints_single_summary_without_pud_text(self):
        common = ["mp1", "mp2", "mp3"]
        lines, logged = self._print(common, [])

        self.assertEqual(["Uploaded 3 metapackage releases"], lines)
        self.assertFalse(any("pre-upgrade-deploy" in line for line in lines))
        self._assert_no_per_metapackage_line(lines)
        self.assertEqual(3, len(logged))

    def test_no_ids_prints_nothing_and_logs_nothing(self):
        lines, logged = self._print([], [])

        self.assertEqual([], lines)
        self.assertEqual([], logged)

    def test_pud_only_prints_only_pud_summary(self):
        lines, logged = self._print([], ["pud1", "pud2"])

        self.assertEqual(
            ["Uploaded 2 pre-upgrade-deploy metapackage releases"], lines)
        self.assertEqual(2, len(logged))

    def test_every_metapackage_logged_in_numeric_sort_order(self):
        lines, logged = self._print(
            ["k8s-1.32.13", "k8s-1.32.2"], ["pud-1.10", "pud-1.9"])

        self.assertEqual([
            "Uploaded k8s-1.32.2 metapackage release",
            "Uploaded k8s-1.32.13 metapackage release",
            "Uploading pud-1.9 pre-upgrade-deploy metapackage release",
            "Uploading pud-1.10 pre-upgrade-deploy metapackage release",
        ], logged)
        self._assert_no_per_metapackage_line(lines)
