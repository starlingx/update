#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for uncovered lines in software_functions.py."""

import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from unittest.mock import MagicMock

from software.tests import base as test_base  # noqa: F401
from software.software_functions import copy_pxeboot_cfg_files
from software.software_functions import copy_pxeboot_update_file
from software.software_functions import create_deploy_hosts
from software.software_functions import load_module
from software.software_functions import mount_remote_directory
from software.software_functions import PatchFile
from software.software_functions import PatchMetadata
from software.software_functions import ReleaseData
from software.software_functions import remove_major_release_deployment_flags
from software.software_functions import run_remove_temporary_data_script
from software.software_functions import validate_host_deploy_order
from software.exceptions import MetadataFail
from software.exceptions import ReleaseValidationFailure
from software.exceptions import SoftwareServiceError
from software.software_functions import get_md5


class TestPatchMetadata(unittest.TestCase):
    """Tests for PatchMetadata."""

    def test_add_rpm(self):
        pm = PatchMetadata()
        pm.id = "PATCH_001"
        pm.sw_version = "24.09"
        with tempfile.NamedTemporaryFile(suffix=".rpm", delete=False) as f:
            f.write(b"fake rpm")
            rpm_path = f.name
        try:
            pf = PatchFile()
            pf.meta = pm
            pf.add_rpm(rpm_path)
            self.assertIn(os.path.abspath(rpm_path), pf.rpmlist)
        finally:
            os.unlink(rpm_path)

    def test_gen_patch_empty_raises(self):
        pf = PatchFile()
        pf.meta = PatchMetadata()
        with self.assertRaises(MetadataFail):
            pf.gen_patch("/tmp")


class TestPatchFileWritePatch(unittest.TestCase):
    """Tests for PatchFile.write_patch -
    test the semantics.tar branch.
    """

    @patch('software.software_functions.sign_files', return_value=False)
    @patch('software.software_functions.get_md5', return_value=0x1234)
    def test_write_patch_with_semantics(self, _mock_md5, _mock_sign):
        tmpdir = tempfile.mkdtemp()
        orig_dir = os.getcwd()
        try:
            os.chdir(tmpdir)
            # Create all required files including semantics.tar
            open("metadata.xml", 'w').close()
            open("software.tar", 'w').close()
            open("metadata.tar", 'w').close()
            open("semantics.tar", 'w').close()
            open("signature.v2", 'w').close()

            patchfile = os.path.join(tmpdir, "test.patch")
            PatchFile.write_patch(patchfile)
            self.assertTrue(os.path.exists(patchfile))
        finally:
            os.chdir(orig_dir)
            shutil.rmtree(tmpdir)


class TestPatchFileReadPatch(unittest.TestCase):
    """Tests for PatchFile.read_patch."""

    def _make_patch(self, tmpdir, metadata_xml=None, _include_sig=True):
        """Helper to create a minimal patch tarball."""
        if metadata_xml is None:
            metadata_xml = "<patch><id>P1</id></patch>"
        build_dir = os.path.join(tmpdir, "build")
        os.makedirs(build_dir)

        # Create metadata.xml and tar it
        with open(os.path.join(build_dir, "metadata.xml"), "w") as f:
            f.write(metadata_xml)
        meta_tar = tarfile.open(os.path.join(build_dir, "metadata.tar"), "w")
        meta_tar.add(os.path.join(build_dir, "metadata.xml"), "metadata.xml")
        meta_tar.close()

        # Create software.tar
        sw_tar = tarfile.open(os.path.join(build_dir, "software.tar"), "w")
        sw_tar.close()

        # Create signature
        sig = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        for f in ["metadata.tar", "software.tar"]:
            sig ^= get_md5(os.path.join(build_dir, f))
        with open(os.path.join(build_dir, "signature"), "w") as f:
            f.write("%x" % sig)

        # Create patch tarball
        patch_path = os.path.join(tmpdir, "test.patch")
        tar = tarfile.open(patch_path, "w:gz")
        for f in ["metadata.tar", "software.tar", "signature"]:
            tar.add(os.path.join(build_dir, f), f)
        tar.close()
        return patch_path

    @patch('software.software_functions.verify_files', return_value=True)
    def test_read_patch_no_detached_sig(self, _mock_verify):
        tmpdir = tempfile.mkdtemp()
        try:
            patch_path = self._make_patch(tmpdir)
            dest = os.path.join(tmpdir, "dest")
            os.makedirs(dest)
            # Should warn but not fail (no detached sig)
            with self.assertRaises(ReleaseValidationFailure):
                PatchFile.read_patch(patch_path, dest)
        finally:
            shutil.rmtree(tmpdir)


class TestPatchFileQueryPatch(unittest.TestCase):
    """Tests for PatchFile.query_patch."""

    @patch('software.software_functions.PatchFile.read_patch')
    def test_query_patch_validation_failure(self, mock_read):
        mock_read.side_effect = ReleaseValidationFailure(error="bad")
        with self.assertRaises(ReleaseValidationFailure):
            PatchFile.query_patch("/fake/patch.patch")

    @patch('software.software_functions.PatchFile.read_patch')
    def test_query_patch_tar_error(self, mock_read):
        mock_read.side_effect = tarfile.TarError("corrupt")
        with self.assertRaises(ReleaseValidationFailure):
            PatchFile.query_patch("/fake/patch.patch")


class TestPatchFileModifyPatch(unittest.TestCase):
    """Tests for PatchFile.modify_patch."""

    @patch('software.software_functions.PatchFile.write_patch')
    @patch('software.software_functions.ReleaseData.modify_metadata_text')
    @patch('software.software_functions.PatchFile.read_patch')
    @patch('software.software_functions.PatchFile.query_patch',
           return_value={'cert': 'dev', 'id': 'P1'})
    @patch('os.rename')
    def test_modify_patch_success(self, _mock_rename, _mock_query,
                                  _mock_read, _mock_modify, _mock_write):
        result = PatchFile.modify_patch("/fake.patch", "summary", "new val")
        self.assertTrue(result)

    @patch('software.software_functions.PatchFile.query_patch',
           side_effect=tarfile.TarError("bad"))
    def test_modify_patch_tar_error(self, _mock_query):
        with self.assertRaises(ReleaseValidationFailure):
            PatchFile.modify_patch("/fake.patch", "key", "val")

    @patch('software.software_functions.PatchFile.query_patch',
           side_effect=Exception("generic"))
    def test_modify_patch_generic_error(self, _mock_query):
        result = PatchFile.modify_patch("/fake.patch", "key", "val")
        self.assertFalse(result)


class TestCreateDeployHosts(unittest.TestCase):
    """Tests for create_deploy_hosts."""

    @patch('software.software_functions.get_ihost_list')
    @patch('software.software_functions.get_instance')
    def test_create_all_hosts(self, mock_db, mock_hosts):
        h1 = MagicMock()
        h1.hostname = "controller-0"
        h2 = MagicMock()
        h2.hostname = "worker-0"
        mock_hosts.return_value = [h1, h2]
        create_deploy_hosts()
        self.assertEqual(mock_db.return_value.create_deploy_host.call_count, 2)

    @patch('software.software_functions.get_ihost_list',
           side_effect=Exception("db error"))
    @patch('software.software_functions.get_instance')
    def test_create_error(self, mock_db, _mock_hosts):
        with self.assertRaises(Exception):  # noqa: H202
            create_deploy_hosts()
        mock_db.return_value.end_update.assert_called_once()


class TestValidateHostDeployOrder(unittest.TestCase):
    """Tests for validate_host_deploy_order."""

    def _make_hosts(self):
        ctrl0 = MagicMock()
        ctrl0.hostname = "controller-0"
        ctrl0.personality = "controller"
        ctrl1 = MagicMock()
        ctrl1.hostname = "controller-1"
        ctrl1.personality = "controller"
        w0 = MagicMock()
        w0.hostname = "worker-0"
        w0.personality = "worker"
        s0 = MagicMock()
        s0.hostname = "storage-0"
        s0.personality = "storage"
        return [ctrl0, ctrl1, w0, s0]

    @patch('software.software_functions.get_ihost_list')
    @patch('software.software_functions.get_instance')
    def test_wrong_order_major(self, mock_db, mock_hosts):
        mock_hosts.return_value = self._make_hosts()
        mock_db.return_value.get_deploy_host.return_value = []
        with self.assertRaises(SoftwareServiceError):
            validate_host_deploy_order("controller-0", is_major_release=True)

    @patch('software.software_functions.get_ihost_list')
    @patch('software.software_functions.get_instance')
    def test_all_deployed_raises(self, mock_db, mock_hosts):
        mock_hosts.return_value = self._make_hosts()
        mock_db.return_value.get_deploy_host.return_value = [
            {"hostname": "controller-1", "state": "deployed"},
            {"hostname": "controller-0", "state": "deployed"},
            {"hostname": "storage-0", "state": "deployed"},
            {"hostname": "worker-0", "state": "deployed"},
        ]
        with self.assertRaises(SoftwareServiceError):
            validate_host_deploy_order("controller-0", is_major_release=True)


class TestMountRemoteDirectory(unittest.TestCase):
    """Tests for mount_remote_directory."""

    @patch('subprocess.check_call')
    @patch('os.path.isdir', return_value=True)
    def test_success(self, _mock_isdir, mock_call):
        with mount_remote_directory("host:/path", "/mnt/local"):
            pass
        self.assertEqual(mock_call.call_count, 2)  # mount + umount

    @patch('subprocess.check_call',
           side_effect=subprocess.CalledProcessError(1, 'mount'))
    @patch('os.path.isdir', return_value=True)
    def test_mount_failure(self, _mock_isdir, _mock_call):
        with self.assertRaises(subprocess.CalledProcessError):
            with mount_remote_directory("host:/path", "/mnt/local"):
                pass

    def test_invalid_remote_path(self):
        with self.assertRaises(OSError):
            with mount_remote_directory("invalid path!!", "/mnt"):
                pass


class TestRemoveMajorReleaseFlags(unittest.TestCase):
    """Tests for remove_major_release_deployment_flags."""

    @patch('os.remove')
    @patch('os.path.isfile', return_value=True)
    def test_removes_flags(self, _mock_isfile, mock_remove):
        remove_major_release_deployment_flags()
        self.assertTrue(mock_remove.call_count > 0)


class TestRunRemoveTemporaryData(unittest.TestCase):
    """Tests for run_remove_temporary_data_script."""

    @patch('os.path.exists', return_value=True)
    @patch('software.software_functions.utils.get_software_deploy_script',
           return_value='/tmp/script.sh')
    @patch('subprocess.check_output',
           side_effect=subprocess.CalledProcessError(1, 'cmd'))
    def test_failure(self, _mock_run, _mock_script, _mock_exists):
        with self.assertRaises(subprocess.CalledProcessError):
            run_remove_temporary_data_script("24.09")


class TestCopyPxebootUpdateFile(unittest.TestCase):
    """Tests for copy_pxeboot_update_file."""

    @patch('os.chmod')
    @patch('shutil.copy')
    @patch('os.path.isfile', return_value=False)
    def test_copy_rollback(self, _mock_isfile, mock_copy, _mock_chmod):
        copy_pxeboot_update_file("24.09", rollback=True)
        args = mock_copy.call_args[0]
        self.assertIn("/ostree/2/", args[0])

    @patch('shutil.copy', side_effect=Exception("fail"))
    @patch('os.path.isfile', return_value=False)
    def test_copy_failure(self, _mock_isfile, _mock_copy):
        with self.assertRaises(Exception):  # noqa: H202
            copy_pxeboot_update_file("24.09")


class TestCopyPxebootCfgFiles(unittest.TestCase):
    """Tests for copy_pxeboot_cfg_files."""

    @patch('shutil.copytree', side_effect=Exception("fail"))
    @patch('os.path.exists', return_value=True)
    def test_failure(self, _mock_exists, _mock_copy):
        with self.assertRaises(Exception):  # noqa: H202
            copy_pxeboot_cfg_files("24.09")


class TestLoadModule(unittest.TestCase):
    """Tests for load_module."""

    def test_load_existing_module(self):
        # Create a temp python file
        tmpdir = tempfile.mkdtemp()
        mod_path = os.path.join(tmpdir, "test_mod.py")
        with open(mod_path, "w") as f:
            f.write("VALUE = 42\n")
        try:
            mod = load_module(mod_path, "test_mod_temp")
            self.assertEqual(mod.VALUE, 42)
        finally:
            shutil.rmtree(tmpdir)
            sys.modules.pop("test_mod_temp", None)

    def test_load_nonexistent_raises(self):
        with self.assertRaises(Exception):  # noqa: H202
            load_module("/nonexistent/module.py", "bad_mod")


class TestReleaseDataLoadAll(unittest.TestCase):
    """Tests for ReleaseData.load_all."""

    @patch('glob.glob', return_value=[])
    def test_load_all_no_files(self, _mock_glob):
        rd = ReleaseData()
        rd.load_all()
        self.assertEqual(rd.metadata, {})


class TestPatchFileExtractPatch(unittest.TestCase):
    """Tests for PatchFile.extract_patch."""

    @patch('software.software_functions.PatchFile.read_patch',
           side_effect=tarfile.TarError("corrupt"))
    def test_tar_error(self, _mock_read):
        pid, _tp, err = PatchFile.extract_patch("/fake.patch")
        self.assertIsNone(pid)
        self.assertIn("Extract software failed", err)

    @patch('software.software_functions.PatchFile.read_patch',
           side_effect=KeyError("missing_key"))
    def test_key_error(self, _mock_read):
        pid, _tp, err = PatchFile.extract_patch("/fake.patch")
        self.assertIsNone(pid)
        self.assertIn("missing required value", err)

    @patch('software.software_functions.PatchFile.read_patch',
           side_effect=Exception("generic"))
    def test_generic_error(self, _mock_read):
        pid, _tp, err = PatchFile.extract_patch("/fake.patch")
        self.assertIsNone(pid)
        self.assertIn("Error while extracting", err)
