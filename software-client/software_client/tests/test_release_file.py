#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import contextlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

from software_client import release_file
from software_client import software_release_id
from software_client.exc import ReleaseFileError

PREPATCHED_ISO_XML = b"""<product>
  <id>starlingx-26.10.100</id>
  <sw_version>26.10.100</sw_version>
  <prepatched_iso>Y</prepatched_iso>
</product>"""

GA_ISO_XML = b"""<product>
  <id>starlingx-27.03.0</id>
  <sw_version>27.03.0</sw_version>
  <prepatched_iso>N</prepatched_iso>
</product>"""

LEGACY_ISO_XML = b"""<patch>
  <id>starlingx-26.03.200</id>
  <sw_version>26.03.200</sw_version>
  <prepatched_iso>Y</prepatched_iso></patch>"""

BUILD_XML = b"<build><version>26.10</version></build>"

PATCH_XML = b"""<product>
  <id>starlingx-26.10.100</id>
  <sw_version>26.10.100</sw_version>
</product>"""


def make_patch(path, metadata_xml=PATCH_XML, extra=b""):
    """Build a patch in the real layout: gzip tar with metadata.tar inside"""
    def add(tar, name, data):
        info = tarfile.TarInfo(name)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))

    metadata = io.BytesIO()
    with tarfile.open(fileobj=metadata, mode="w") as tar:
        if metadata_xml is not None:
            add(tar, "metadata.xml", metadata_xml)
    with tarfile.open(path, "w:gz") as tar:
        add(tar, "software.tar", b"")
        add(tar, "metadata.tar", metadata.getvalue())
        if extra:
            add(tar, "extra.tar", extra)


class TestReleaseFile(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir)

    def _file(self, name, content=b""):
        path = os.path.join(self.tmpdir, name)
        with open(path, "wb") as f:
            f.write(content)
        return path

    def _patch(self, name="starlingx-26.10.100.patch", **kwargs):
        path = os.path.join(self.tmpdir, name)
        make_patch(path, **kwargs)
        return path

    def _iso(self, files):
        """An ISO file whose isoinfo output is mocked from {path: content}"""
        def isoinfo(_iso_path, *args):
            if "-f" in args:
                return "\n".join(files).encode()
            return files[args[args.index("-x") + 1]]
        patcher = mock.patch.object(release_file, "_isoinfo", side_effect=isoinfo)
        patcher.start()
        self.addCleanup(patcher.stop)
        return self._file("test.iso")

    # ISO

    def test_prepatched_iso(self):
        iso = self._iso({"/upgrades/starlingx-26.10.100-metadata.xml": PREPATCHED_ISO_XML,
                         "/upgrades/metadata.xml": BUILD_XML})
        self.assertEqual({"file": iso, "type": "iso", "release_id": "starlingx-26.10.100",
                          "sw_version": "26.10.100", "prepatched_iso": True},
                         release_file.get_release_info(iso))

    def test_ga_iso(self):
        iso = self._iso({"/upgrades/starlingx-27.03.0-metadata.xml": GA_ISO_XML})
        self.assertIs(False, release_file.get_release_info(iso)["prepatched_iso"])

    def test_legacy_iso(self):
        iso = self._iso({"/upgrades/starlingx-26.03.200-metadata.xml": LEGACY_ISO_XML})
        info = release_file.get_release_info(iso)
        self.assertEqual(("starlingx-26.03.200", True), (info["release_id"], info["prepatched_iso"]))

    def test_iso_without_prepatched_tag(self):
        iso = self._iso({"/upgrades/starlingx-27.03.0-metadata.xml":
                         b"<product><id>starlingx-27.03.0</id></product>"})
        self.assertIs(False, release_file.get_release_info(iso)["prepatched_iso"])

    def test_iso_with_several_product_files(self):
        # The highest sw_version is used
        iso = self._iso({"/upgrades/starlingx-26.10.0-metadata.xml":
                         b"<product><id>starlingx-26.10.0</id><sw_version>26.10.0</sw_version></product>",
                         "/upgrades/starlingx-26.10.100-metadata.xml": PREPATCHED_ISO_XML,
                         "/upgrades/starlingx-26.10.20-metadata.xml":
                         b"<product><id>starlingx-26.10.20</id><sw_version>26.10.20</sw_version></product>"})
        self.assertEqual("starlingx-26.10.100", release_file.get_release_info(iso)["release_id"])

    def test_pre_usm_iso(self):
        iso = self._iso({"/upgrades/metadata.xml": BUILD_XML})
        self.assertEqual({"file": iso, "type": "iso", "release_id": "starlingx-26.10.0",
                          "sw_version": "26.10.0", "prepatched_iso": None},
                         release_file.get_release_info(iso))

    def test_iso_without_release_metadata(self):
        # A metapackage metadata file is not a product metadata file
        iso = self._iso({"/upgrades/infra_27.03.0-metadata.xml": GA_ISO_XML})
        self.assertRaisesRegex(ReleaseFileError, "No release metadata",
                               release_file.get_release_info, iso)

    def test_isoinfo_errors(self):
        iso = self._file("test.iso")
        for error, message in ((FileNotFoundError, "isoinfo command not found"),
                               (subprocess.CalledProcessError(1, "isoinfo", stderr=b"bad iso"), "bad iso"),
                               (subprocess.TimeoutExpired("isoinfo", 1), "timed out")):
            with self.subTest(message=message), \
                    mock.patch.object(release_file.subprocess, "check_output", side_effect=error):
                self.assertRaisesRegex(ReleaseFileError, message, release_file.get_release_info, iso)

    # Patch

    def test_patch(self):
        patch = self._patch()
        self.assertEqual({"file": patch, "type": "patch", "release_id": "starlingx-26.10.100",
                          "sw_version": "26.10.100", "prepatched_iso": None},
                         release_file.get_release_info(patch))

    def test_patch_read_stops_at_metadata_tar(self):
        # A patch cut off inside extra.tar is still read
        patch = self._patch(extra=os.urandom(2 * 1024 * 1024))
        with open(patch, "r+b") as f:
            f.truncate(os.path.getsize(patch) // 2)
        self.assertEqual("starlingx-26.10.100", release_file.get_release_info(patch)["release_id"])

    def test_patch_without_metadata_xml(self):
        self.assertRaisesRegex(ReleaseFileError, "metadata.xml not found",
                               release_file.get_release_info, self._patch(metadata_xml=None))

    @unittest.skipIf(os.geteuid() == 0, "root can read files with mode 000")
    def test_patch_unreadable(self):
        patch = self._patch("unreadable.patch")
        os.chmod(patch, 0)
        self.addCleanup(os.chmod, patch, 0o644)
        results = release_file.get_release_info_list([patch, self._patch()])
        self.assertIn("Cannot read patch file", results[0]["error"])
        self.assertEqual("starlingx-26.10.100", results[1]["release_id"])

    def test_patch_not_a_tar(self):
        self.assertRaisesRegex(ReleaseFileError, "Invalid patch file",
                               release_file.get_release_info, self._file("x.patch", b"not a tar"))

    # Invalid input

    def test_invalid_metadata(self):
        for xml, message in ((b"<product><id>", "Invalid release metadata"),
                             (b"<product></product>", "No release id")):
            with self.subTest(message=message):
                self.assertRaisesRegex(ReleaseFileError, message,
                                       release_file.get_release_info, self._patch(metadata_xml=xml))

    def test_invalid_file(self):
        for path, message in ((os.path.join(self.tmpdir, "missing.iso"), "File not found"),
                              (self._file("x.txt"), "Unsupported file type")):
            with self.subTest(message=message):
                self.assertRaisesRegex(ReleaseFileError, message, release_file.get_release_info, path)

    # Several files and CLI

    def test_release_info_list(self):
        missing = os.path.join(self.tmpdir, "missing.iso")
        results = release_file.get_release_info_list([missing, self._file("x.sig"), self._patch()])
        self.assertEqual(2, len(results))
        self.assertIn("File not found", results[0]["error"])
        self.assertEqual("starlingx-26.10.100", results[1]["release_id"])

    def test_cli(self):
        for files, rc in (([self._patch()], 0),
                          ([os.path.join(self.tmpdir, "missing.patch"), self._patch()], 1)):
            with self.subTest(rc=rc):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    self.assertEqual(rc, software_release_id.main(files))
                self.assertEqual(release_file.get_release_info_list(files), json.loads(out.getvalue()))
