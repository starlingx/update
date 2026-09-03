#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for software_functions.py -
PatchFile methods and patch_build.
"""

import os
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from unittest.mock import MagicMock

from software.tests import base  # noqa: F401
from software.software_functions import PatchFile
from software.software_functions import PatchMetadata
from software.software_functions import get_md5
import subprocess
from software.software_functions import ReleaseValidationFailure
from software.software_functions import OSTreeTarFail
import sys
from software.software_functions import patch_build
from software.software_functions import MetadataFail


class TestWritePatch(unittest.TestCase):
    """Test PatchFile.write_patch"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.orig_wd = os.getcwd()
        os.chdir(self.tmpdir)
        # Create required files
        with open("metadata.xml", "w") as f:
            f.write("<patch><id>P1</id></patch>")
        # Create metadata.tar
        with tarfile.open("metadata.tar", "w") as t:
            t.add("metadata.xml")
        # Create software.tar
        with open("dummy.deb", "w") as f:
            f.write("fake deb content")
        with tarfile.open("software.tar", "w") as t:
            t.add("dummy.deb")

    def tearDown(self):
        os.chdir(self.orig_wd)
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    @patch('software.software_functions.sign_files', return_value=False)
    def test_write_patch_basic(self, _mock_sign):
        # sign_files is mocked but write_patch
        # expects signature.v2 to exist
        with open("signature.v2", "w") as f:
            f.write("fake detached sig")
        patchfile = os.path.join(self.tmpdir, "test.patch")
        PatchFile.write_patch(patchfile)
        self.assertTrue(os.path.exists(patchfile))
        # Verify it's a valid gzip tar
        self.assertTrue(tarfile.is_tarfile(patchfile))
        with tarfile.open(patchfile, "r:gz") as t:
            names = t.getnames()
            self.assertIn("metadata.tar", names)
            self.assertIn("software.tar", names)
            self.assertIn("signature", names)

    @patch('software.software_functions.sign_files', return_value=False)
    def test_write_patch_with_semantics(self, _mock_sign):
        with open("signature.v2", "w") as f:
            f.write("fake")
        # Create semantics.tar
        with open("semantics.sh", "w") as f:
            f.write("#!/bin/bash\nexit 0")
        with tarfile.open("semantics.tar", "w") as t:
            t.add("semantics.sh")
        patchfile = os.path.join(self.tmpdir, "test2.patch")
        PatchFile.write_patch(patchfile)
        with tarfile.open(patchfile, "r:gz") as t:
            self.assertIn("semantics.tar", t.getnames())

    @patch('subprocess.check_call', side_effect=Exception("no sign"))
    @patch('software.software_functions.sign_files', return_value=True)
    def test_write_patch_formal_resign_fail(self, _mock_sign, mock_call):
        mock_call.side_effect = subprocess.CalledProcessError(
            1, "sign_patch_formal.sh")
        with open("signature.v2", "w") as f:
            f.write("fake")
        patchfile = os.path.join(self.tmpdir, "fail.patch")
        with self.assertRaises(SystemExit):
            PatchFile.write_patch(patchfile)


class TestReadPatch(unittest.TestCase):
    """Tests for PatchFile.read_patch."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.destdir = tempfile.mkdtemp()
        self.orig_wd = os.getcwd()

    def tearDown(self):
        os.chdir(self.orig_wd)
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        shutil.rmtree(self.destdir, ignore_errors=True)

    def _create_patch(self, include_sig=True, valid_sig=True):
        """Create a minimal valid patch file."""
        os.chdir(self.tmpdir)
        # Create metadata.xml and metadata.tar
        with open("metadata.xml", "w") as f:
            f.write("<patch><id>P1</id></patch>")
        with tarfile.open("metadata.tar", "w") as t:
            t.add("metadata.xml")
        # Create software.tar
        with open("dummy.deb", "w") as f:
            f.write("fake")
        with tarfile.open("software.tar", "w") as t:
            t.add("dummy.deb")

        filelist = ["metadata.tar", "software.tar"]
        # Generate signature
        sig = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        for fn in filelist:
            sig ^= get_md5(fn)
        with open("signature", "w") as f:
            if valid_sig:
                f.write("%x" % sig)
            else:
                f.write("0")

        # Generate detached signature
        if include_sig:
            with open("signature.v2", "w") as f:
                f.write("detached sig")

        # Create the patch tar.gz
        patchfile = os.path.join(self.tmpdir, "test.patch")
        with tarfile.open(patchfile, "w:gz") as t:
            for fn in filelist:
                t.add(fn)
            t.add("signature")
            if include_sig:
                t.add("signature.v2")
        return patchfile

    @patch('software.software_functions.verify_files', return_value=True)
    def test_read_patch_success(self, _mock_verify):
        patchfile = self._create_patch()
        PatchFile.read_patch(patchfile, self.destdir)
        self.assertTrue(
            os.path.exists(
                os.path.join(
                    self.destdir,
                    "metadata.xml")))

    def test_read_patch_bad_signature(self):
        patchfile = self._create_patch(valid_sig=False)
        with self.assertRaises(ReleaseValidationFailure):
            PatchFile.read_patch(patchfile, self.destdir)

    @patch('software.software_functions.verify_files', return_value=False)
    def test_read_patch_verify_fails(self, _mock_verify):
        patchfile = self._create_patch()
        with self.assertRaises(ReleaseValidationFailure):
            PatchFile.read_patch(patchfile, self.destdir)

    def test_read_patch_no_detached_sig(self):
        patchfile = self._create_patch(include_sig=False)
        with self.assertRaises(ReleaseValidationFailure):
            PatchFile.read_patch(patchfile, self.destdir)


class TestExtractPatch(unittest.TestCase):
    """Tests for PatchFile.extract_patch."""

    @patch('software.software_functions.PatchFile.read_patch')
    @patch('software.software_functions.shutil.rmtree')
    @patch('software.software_functions.shutil.move')
    @patch('software.software_functions.os.makedirs')
    @patch('software.software_functions.os.path.exists', return_value=True)
    @patch('software.software_functions.os.chmod')
    @patch('software.software_functions.os.stat',
           return_value=MagicMock(st_mode=0o644))
    def test_extract_patch_success(self, _mock_stat, _mock_chmod, _mock_exists,
                                   _mock_makedirs, _mock_move, _mock_rmtree,
                                   mock_read):
        xml_content = """<?xml version="1.0" ?>
<patch>
  <id>PATCH_001</id>
  <sw_version>24.09.1</sw_version>
  <summary>Test</summary>
  <description>Test patch</description>
  <install_instructions/>
  <warnings/>
  <status>DEV</status>
  <unremovable>N</unremovable>
  <reboot_required>N</reboot_required>
</patch>
            """

        def fake_read(_path, dest, _cert_type=None):
            os.makedirs(dest, exist_ok=True)
            with open(os.path.join(dest, "metadata.xml"), "w") as f:
                f.write(xml_content)
            with open(os.path.join(dest, "software.tar"), "w") as f:
                f.write("fake")

        mock_read.side_effect = fake_read
        with patch(
                'software.software_functions.utils.get_major_release_version',
                return_value="24.09"):
            with patch(
                    'software.software_functions'
                    '.utils.compare_release_version',
                    return_value=False):
                with patch('software.software_functions.SW_VERSION', '24.09'):
                    _patch_id, _thispatch, error_msg = PatchFile.extract_patch(
                        "/tmp/test.patch",
                        metadata_dir="/tmp/avail",
                        base_pkgdata=None)
        self.assertEqual(_patch_id, "PATCH_001")
        self.assertIsNone(error_msg)

    @patch('software.software_functions.PatchFile.read_patch',
           side_effect=tarfile.TarError("bad tar"))
    @patch('software.software_functions.shutil.rmtree')
    def test_extract_patch_tar_error(self, _mock_rmtree, _mock_read):
        _patch_id, _thispatch, error_msg = PatchFile.extract_patch(
            "/tmp/bad.patch")
        self.assertIsNone(_patch_id)
        self.assertIn("Extract software failed", error_msg)

    @patch('software.software_functions.PatchFile.read_patch')
    @patch('software.software_functions.shutil.rmtree')
    def test_extract_patch_metadata_only_mismatch(
            self, _mock_rmtree, mock_read):
        xml_content = """<?xml version="1.0" ?>
<patch>
  <id>PATCH_002</id>
  <sw_version>24.09.1</sw_version>
  <summary>Test</summary>
</patch>
            """

        def fake_read(_path, dest, _cert_type=None):
            os.makedirs(dest, exist_ok=True)
            with open(os.path.join(dest, "metadata.xml"), "w") as f:
                f.write(xml_content)

        mock_read.side_effect = fake_read
        with patch(
                'software.software_functions.utils.get_major_release_version',
                return_value="24.09"):
            _patch_id, _thispatch, error_msg = PatchFile.extract_patch(
                "/tmp/test.patch",
                metadata_only=True,
                existing_content={"different": "content"})
        self.assertIsNotNone(error_msg)

    @patch('software.software_functions.PatchFile.read_patch')
    @patch('software.software_functions.shutil.rmtree')
    def test_extract_patch_key_error(self, _mock_rmtree, mock_read):
        def fake_read(_path, dest, _cert_type=None):
            os.makedirs(dest, exist_ok=True)
            with open(os.path.join(dest, "metadata.xml"), "w") as f:
                f.write("<patch><id>P1</id></patch>")

        mock_read.side_effect = fake_read
        with patch(
                'software.software_functions.utils.get_major_release_version',
                return_value="24.09"):
            _patch_id, _thispatch, error_msg = PatchFile.extract_patch(
                "/tmp/test.patch",
                base_pkgdata=MagicMock())
        self.assertIsNotNone(error_msg)


class TestUnpackPatch(unittest.TestCase):
    """Tests for PatchFile.unpack_patch."""

    @patch('software.software_functions.PatchFile.read_patch')
    @patch('software.software_functions.shutil.rmtree')
    def test_unpack_patch_tar_error(self, _mock_rmtree, mock_read):
        xml_content = """<?xml version="1.0" ?>
<patch><id>P1</id><sw_version>24.09.1</sw_version></patch>
            """

        def fake_read(_path, dest, _cert_type=None):
            os.makedirs(dest, exist_ok=True)
            with open(os.path.join(dest, "metadata.xml"), "w") as f:
                f.write(xml_content)

        mock_read.side_effect = fake_read
        with patch(
                'software.software_functions.package_dir',
                {"24.09": "/nonexistent"}):
            with patch(
                    'software.software_functions'
                    '.utils.get_major_release_version',
                    return_value="24.09"):
                with patch(
                        'tarfile.open',
                        side_effect=tarfile.TarError("bad")):
                    with self.assertRaises(OSTreeTarFail):
                        PatchFile.unpack_patch("/tmp/test.patch")


class TestPatchBuild(unittest.TestCase):
    """Tests for patch_build function."""

    @patch('software.software_functions.PatchFile')
    @patch('software.software_functions.configure_logging')
    def test_patch_build_basic(self, _mock_log, mock_pf_cls):
        mock_pf = MagicMock()
        mock_pf_cls.return_value = mock_pf
        mock_pf.meta = PatchMetadata()

        with patch.dict(os.environ, {'PLATFORM_RELEASE': '24.09'}):
            with patch.object(sys, 'argv', ['patch_build',
                                            '--id', 'PATCH_001',
                                            '--release', '24.09.1',
                                            '--summary', 'Test patch',
                                            '--status', 'DEV',
                                            '--desc', 'A test',
                                            '--reboot-required', 'N',
                                            'pkg1.deb']):
                patch_build()

        self.assertEqual(mock_pf.meta.id, "PATCH_001")
        self.assertEqual(mock_pf.meta.sw_version, "24.09.1")
        self.assertEqual(mock_pf.meta.summary, "Test patch")
        self.assertEqual(mock_pf.meta.reboot_required, "N")
        mock_pf.add_rpm.assert_called_once_with("pkg1.deb")
        mock_pf.gen_patch.assert_called_once()

    @patch('software.software_functions.PatchFile')
    @patch('software.software_functions.configure_logging')
    def test_patch_build_no_id(self, _mock_log, mock_pf_cls):
        mock_pf = MagicMock()
        mock_pf_cls.return_value = mock_pf
        mock_pf.meta = PatchMetadata()

        with patch.dict(os.environ, {'PLATFORM_RELEASE': '24.09'}):
            with patch.object(
                    sys, 'argv',
                    ['patch_build', '--release', '24.09']):
                with self.assertRaises(SystemExit):
                    patch_build()

    @patch('software.software_functions.PatchFile')
    @patch('software.software_functions.configure_logging')
    def test_patch_build_bad_reboot_required(self, _mock_log, mock_pf_cls):
        mock_pf = MagicMock()
        mock_pf_cls.return_value = mock_pf
        mock_pf.meta = PatchMetadata()

        with patch.dict(os.environ, {'PLATFORM_RELEASE': '24.09'}):
            with patch.object(sys, 'argv', ['patch_build',
                                            '--id', 'P1',
                                            '--reboot-required', 'X']):
                with self.assertRaises(SystemExit):
                    patch_build()

    @patch('software.software_functions.configure_logging')
    def test_patch_build_getopt_error(self, _mock_log):
        with patch.object(sys, 'argv', ['patch_build', '--invalid-option']):
            with self.assertRaises(SystemExit):
                patch_build()

    @patch('software.software_functions.PatchFile')
    @patch('software.software_functions.configure_logging')
    def test_patch_build_all_options(self, _mock_log, mock_pf_cls):
        mock_pf = MagicMock()
        mock_pf_cls.return_value = mock_pf
        mock_pf.meta = PatchMetadata()

        with patch.dict(os.environ, {'PLATFORM_RELEASE': '24.09'}):
            with patch.object(sys, 'argv', ['patch_build',
                                            '--id', 'P1',
                                            '--unremovable',
                                            '--warn', 'Be careful',
                                            '--inst', 'Run this',
                                            '--req', 'P0',
                                            '--apply-active-release-only']):
                patch_build()

        self.assertEqual(mock_pf.meta.unremovable, "Y")
        self.assertEqual(mock_pf.meta.warnings, "Be careful")
        self.assertEqual(mock_pf.meta.install_instructions, "Run this")
        self.assertIn("P0", mock_pf.meta.requires)
        self.assertEqual(mock_pf.meta.apply_active_release_only, "Y")


class TestGenPatch(unittest.TestCase):
    """Tests for PatchFile.gen_patch."""

    def test_gen_patch_empty_rpmlist(self):
        pf = PatchFile()
        pf.meta.id = "P1"
        with self.assertRaises(MetadataFail):
            pf.gen_patch(outdir="/tmp")

    @patch('subprocess.check_call',
           side_effect=__import__('subprocess').CalledProcessError(
               1, 'sign-rpms'))
    def test_gen_patch_sign_failure(self, _mock_call):
        pf = PatchFile()
        pf.meta.id = "P1"
        tmpdir = tempfile.mkdtemp()
        rpm_path = os.path.join(tmpdir, "test.rpm")
        with open(rpm_path, "w") as f:
            f.write("fake")
        pf.rpmlist[rpm_path] = True
        try:
            with self.assertRaises(SystemExit):
                pf.gen_patch(outdir=tmpdir)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestDeleteVersionedDirectory(unittest.TestCase):
    """Tests for PatchFile.delete_versioned_directory."""

    def test_delete_versioned_directory(self):
        tmpdir = tempfile.mkdtemp()
        try:
            ver_dir = os.path.join(tmpdir, "rel-24.09.1")
            os.makedirs(ver_dir)
            with patch(
                    'software.software_functions'
                    '.constants.SOFTWARE_STORAGE_DIR',
                    tmpdir):
                PatchFile.delete_versioned_directory("24.09.1")
            self.assertFalse(os.path.exists(ver_dir))
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
