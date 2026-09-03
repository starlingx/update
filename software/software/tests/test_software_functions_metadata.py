#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from lxml import etree as ElementTree

from software.software_functions import add_text_tag_to_xml
from software.software_functions import BasePackageData
from software.software_functions import configure_logging
from software.software_functions import get_metadata_files
from software.software_functions import get_release_from_patch
from software.software_functions import get_sw_version
from software.software_functions import get_to_release_from_metadata_file
from software.software_functions import handle_exception
from software.software_functions import is_deploy_state_in_sync
from software.software_functions import parse_release_metadata
from software.software_functions import PatchFile
from software.software_functions import read_attributes_from_metadata_file
from software.software_functions import ReleaseData
from software.software_functions import remove_major_release_deployment_flags
from software.software_functions import write_xml_file
from software.tests import base as test_base  # noqa: F401
from software.exceptions import SoftwareServiceError
from software.exceptions import ReleaseValidationFailure
import tarfile

METADATA_XML = """<?xml version="1.0" ?>
<patch>
  <id>PATCH_0001</id>
  <sw_version>24.09.1</sw_version>
  <summary>Test summary</summary>
  <description>Test description</description>
  <install_instructions>Test instructions</install_instructions>
  <warnings>Test warnings</warnings>
  <status>DEV</status>
  <unremovable>Y</unremovable>
  <reboot_required>Y</reboot_required>
  <contents>
    <ostree>
      <number_of_commits>1</number_of_commits>
      <base>
        <commit>aaa111</commit>
        <checksum>bbb222</checksum>
      </base>
      <commit1>
        <commit>ccc333</commit>
        <checksum>ddd444</checksum>
      </commit1>
    </ostree>
  </contents>
  <requires>
    <req_patch_id>REQ_001</req_patch_id>
  </requires>
  <packages>
    <deb>pkg1.deb</deb>
  </packages>
</patch>
    """

UPGRADE_METADATA_XML = """<?xml version="1.0" ?>
<upgrade>
  <version>24.09</version>
  <supported_upgrades>
    <upgrade>
      <version>24.03</version>
      <required_patch>PATCH_001</required_patch>
    </upgrade>
  </supported_upgrades>
</upgrade>
    """


class TestGetSwVersionExtended(unittest.TestCase):

    def test_single_file(self):
        tmpdir = tempfile.mkdtemp()
        try:
            fpath = os.path.join(tmpdir, "r1-metadata.xml")
            top = ElementTree.Element("patch")
            add_text_tag_to_xml(top, "sw_version", "24.09.0")
            with open(fpath, 'wb') as f:
                f.write(ElementTree.tostring(top))
            result = get_sw_version([fpath])
            self.assertEqual(result, "24.09.0")
        finally:
            shutil.rmtree(tmpdir)

    def test_unparseable_file_skipped(self):
        tmpdir = tempfile.mkdtemp()
        try:
            bad = os.path.join(tmpdir, "bad-metadata.xml")
            with open(bad, 'w') as f:
                f.write("not xml")
            with self.assertRaises(SoftwareServiceError):
                get_sw_version([bad])
        finally:
            shutil.rmtree(tmpdir)

    def test_mixed_valid_invalid(self):
        tmpdir = tempfile.mkdtemp()
        try:
            bad = os.path.join(tmpdir, "bad-metadata.xml")
            with open(bad, 'w') as f:
                f.write("not xml")
            good = os.path.join(tmpdir, "good-metadata.xml")
            top = ElementTree.Element("patch")
            add_text_tag_to_xml(top, "sw_version", "25.01.0")
            with open(good, 'wb') as f:
                f.write(ElementTree.tostring(top))
            result = get_sw_version([bad, good])
            self.assertEqual(result, "25.01.0")
        finally:
            shutil.rmtree(tmpdir)


class TestGetToReleaseFromMetadataFile(unittest.TestCase):

    def test_pre_usm_iso(self):
        tmpdir = tempfile.mkdtemp()
        try:
            upgrades_dir = os.path.join(tmpdir, "upgrades")
            os.makedirs(upgrades_dir)
            meta_file = os.path.join(upgrades_dir, "metadata.xml")
            with open(meta_file, 'w') as f:
                f.write(UPGRADE_METADATA_XML)
            result = get_to_release_from_metadata_file(tmpdir)
            self.assertEqual(result, "24.09")
        finally:
            shutil.rmtree(tmpdir)

    def test_usm_iso_with_release_metadata(self):
        tmpdir = tempfile.mkdtemp()
        try:
            upgrades_dir = os.path.join(tmpdir, "upgrades")
            os.makedirs(upgrades_dir)
            meta_file = os.path.join(upgrades_dir, "metadata.xml")
            with open(meta_file, 'w') as f:
                f.write(UPGRADE_METADATA_XML)
            rel_meta = os.path.join(upgrades_dir, "rel-metadata.xml")
            top = ElementTree.Element("patch")
            add_text_tag_to_xml(top, "sw_version", "25.03.0")
            with open(rel_meta, 'wb') as f:
                f.write(ElementTree.tostring(top))
            result = get_to_release_from_metadata_file(tmpdir)
            self.assertEqual(result, "25.03.0")
        finally:
            shutil.rmtree(tmpdir)


class TestReadAttributesFromMetadataFile(unittest.TestCase):

    def test_reads_attributes(self):
        tmpdir = tempfile.mkdtemp()
        try:
            upgrades_dir = os.path.join(tmpdir, "upgrades")
            os.makedirs(upgrades_dir)
            meta_file = os.path.join(upgrades_dir, "metadata.xml")
            with open(meta_file, 'w') as f:
                f.write(UPGRADE_METADATA_XML)
            attrs = read_attributes_from_metadata_file(tmpdir)
            self.assertEqual(attrs["to_release"], "24.09")
            self.assertEqual(len(attrs["supported_from_releases"]), 1)
            self.assertEqual(
                attrs["supported_from_releases"][0]["version"], "24.03")
            self.assertEqual(
                attrs["supported_from_releases"][0]
                ["required_patch"],
                "PATCH_001")
        finally:
            shutil.rmtree(tmpdir)

    def test_missing_file_raises(self):
        tmpdir = tempfile.mkdtemp()
        try:
            with self.assertRaises(SoftwareServiceError):
                read_attributes_from_metadata_file(tmpdir)
        finally:
            shutil.rmtree(tmpdir)


class TestGetMetadataFilesExtended(unittest.TestCase):

    def test_filters_correctly(self):
        tmpdir = tempfile.mkdtemp()
        try:
            for name in ["P1-metadata.xml", "P2-metadata.xml",
                         "notes.xml", "readme.txt", "data-metadata.xml"]:
                open(os.path.join(tmpdir, name), 'w').close()
            result = get_metadata_files(tmpdir)
            basenames = [os.path.basename(f) for f in result]
            self.assertIn("P1-metadata.xml", basenames)
            self.assertIn("P2-metadata.xml", basenames)
            self.assertIn("data-metadata.xml", basenames)
            self.assertNotIn("notes.xml", basenames)
            self.assertNotIn("readme.txt", basenames)
        finally:
            shutil.rmtree(tmpdir)


class TestRemoveMajorReleaseDeploymentFlagsExtended(unittest.TestCase):

    @mock.patch('software.software_functions.os.remove')
    def test_partial_failure(self, mock_remove):
        mock_remove.side_effect = [None, OSError("fail")]
        result = remove_major_release_deployment_flags()
        self.assertFalse(result)

    @mock.patch('software.software_functions.os.remove')
    def test_all_succeed(self, mock_remove):
        result = remove_major_release_deployment_flags()
        self.assertTrue(result)
        self.assertEqual(mock_remove.call_count, 2)


class TestIsDeployStateInSyncExtended(unittest.TestCase):

    @mock.patch('software.software_functions.get_instance')
    @mock.patch('software.software_functions.os.path.isfile')
    def test_host_state_mismatch(self, mock_isfile, mock_db):
        mock_isfile.return_value = True
        db = mock.MagicMock()
        db.get_deploy_all.return_value = [{"state": "x"}]
        db.get_deploy_all_synced.return_value = [{"state": "x"}]
        db.get_deploy_host.return_value = [{"host": "c0"}]
        db.get_deploy_host_synced.return_value = [{"host": "c1"}]
        mock_db.return_value = db
        self.assertFalse(is_deploy_state_in_sync())

    @mock.patch('software.software_functions.os.path.isfile')
    def test_synced_exists_software_not(self, mock_isfile):
        mock_isfile.side_effect = [True, False]
        self.assertFalse(is_deploy_state_in_sync())


class TestBasePackageDataExtended(unittest.TestCase):

    @mock.patch('software.software_functions.glob.glob')
    @mock.patch('software.software_functions.os.path.exists')
    def test_loaddirs_multiple_releases(self, mock_exists, mock_glob):
        base = "/var/www/pages/feed"
        mock_exists.return_value = True
        mock_glob.return_value = [base + "/rel-24.03", base + "/rel-24.09"]
        bpd = BasePackageData()
        self.assertIn("24.03", bpd.pkgs)
        self.assertIn("24.09", bpd.pkgs)

    @mock.patch('software.software_functions.glob.glob')
    @mock.patch('software.software_functions.os.path.exists')
    def test_loaddirs_skip_already_parsed(self, mock_exists, mock_glob):
        base = "/var/www/pages/feed"
        mock_exists.return_value = True
        mock_glob.return_value = [base + "/rel-24.09"]
        bpd = BasePackageData()
        bpd.pkgs["24.09"]["testpkg"] = {"amd64": "1.0"}
        mock_glob.return_value = [base + "/rel-24.09"]
        bpd.loaddirs()
        self.assertEqual(bpd.pkgs["24.09"]["testpkg"]["amd64"], "1.0")

    @mock.patch('software.software_functions.glob.glob')
    @mock.patch('software.software_functions.os.path.exists')
    def test_find_version_found(self, mock_exists, mock_glob):
        base = "/var/www/pages/feed"
        mock_exists.return_value = True
        mock_glob.return_value = [base + "/rel-24.09"]
        bpd = BasePackageData()
        bpd.pkgs["24.09"]["mypkg"] = {"amd64": "2.0"}
        self.assertEqual(bpd.find_version("24.09", "mypkg", "amd64"), "2.0")


class TestReleaseDataExtended(unittest.TestCase):

    def test_parse_metadata_file_from_disk(self):
        tmpdir = tempfile.mkdtemp()
        try:
            fpath = os.path.join(tmpdir, "metadata.xml")
            with open(fpath, 'w') as f:
                f.write(METADATA_XML)
            rd = ReleaseData()
            rid = rd.parse_metadata_file(fpath, state="available")
            self.assertEqual(rid, "PATCH_0001")
            self.assertEqual(rd.metadata[rid]["sw_version"], "24.09.1")
        finally:
            shutil.rmtree(tmpdir)

    def test_modify_metadata_text_updates_value(self):
        tmpdir = tempfile.mkdtemp()
        try:
            fpath = os.path.join(tmpdir, "meta.xml")
            top = ElementTree.Element("patch")
            add_text_tag_to_xml(top, "id", "P1")
            add_text_tag_to_xml(top, "summary", "old_summary")
            with open(fpath, 'wb') as f:
                f.write(ElementTree.tostring(top))
            ReleaseData.modify_metadata_text(fpath, "summary", "new_summary")
            tree = ElementTree.parse(fpath)
            self.assertEqual(tree.getroot().findtext("summary"), "new_summary")
        finally:
            shutil.rmtree(tmpdir)

    def test_modify_metadata_text_missing_key_raises(self):
        tmpdir = tempfile.mkdtemp()
        try:
            fpath = os.path.join(tmpdir, "meta.xml")
            top = ElementTree.Element("patch")
            add_text_tag_to_xml(top, "id", "P1")
            with open(fpath, 'wb') as f:
                f.write(ElementTree.tostring(top))
            with self.assertRaises(ReleaseValidationFailure):
                ReleaseData.modify_metadata_text(fpath, "nonexistent", "val")
        finally:
            shutil.rmtree(tmpdir)

    def test_delete_release_removes_both(self):
        rd = ReleaseData()
        rd.parse_metadata_string(METADATA_XML, state="available")
        self.assertIn("PATCH_0001", rd.metadata)
        rd.delete_release("PATCH_0001")
        self.assertNotIn("PATCH_0001", rd.metadata)
        self.assertNotIn("PATCH_0001", rd.contents)

    def test_delete_release_missing_raises(self):
        rd = ReleaseData()
        with self.assertRaises(KeyError):
            rd.delete_release("NONEXISTENT")

    def test_update_release_preserves_state(self):
        rd = ReleaseData()
        rd.parse_metadata_string(METADATA_XML, state="available")
        updated = ReleaseData()
        xml2 = METADATA_XML.replace(
            "<summary>Test summary</summary>",
            "<summary>Updated summary</summary>")
        updated.parse_metadata_string(xml2, state="deployed")
        rd.update_release(updated)
        self.assertEqual(rd.metadata["PATCH_0001"]["state"], "available")
        self.assertEqual(
            rd.metadata["PATCH_0001"]["summary"],
            "Updated summary")

    def test_load_all(self):
        rd = ReleaseData()
        with mock.patch.object(rd, '_read_all_metafile') as mock_read:
            mock_read.return_value = iter([])
            rd.load_all()
            self.assertEqual(rd.metadata, {})


class TestGetReleaseFromPatchExtended(unittest.TestCase):

    @mock.patch('software.software_functions.subprocess.check_output')
    def test_extracts_id(self, mock_check):
        xml_bytes = (
            b"<patch><id>PATCH_99</id>"
            b"<sw_version>24.09</sw_version>"
            b"</patch>")
        mock_check.return_value = xml_bytes
        result = get_release_from_patch("/fake.patch", key="id")
        self.assertEqual(result, "PATCH_99")

    @mock.patch('software.software_functions.subprocess.check_output')
    def test_key_not_found_returns_none(self, mock_check):
        xml_bytes = b"<patch><id>P1</id></patch>"
        mock_check.return_value = xml_bytes
        result = get_release_from_patch("/fake.patch", key="missing")
        self.assertIsNone(result)

    @mock.patch('software.software_functions.subprocess.check_output')
    def test_subprocess_error(self, mock_check):
        mock_check.side_effect = subprocess.CalledProcessError(
            1, 'tar', b"err")
        with self.assertRaises(subprocess.CalledProcessError):
            get_release_from_patch("/fake.patch")


class TestWriteXmlFileExtended(unittest.TestCase):

    def test_writes_to_disk(self):
        tmpdir = tempfile.mkdtemp()
        try:
            fpath = os.path.join(tmpdir, "out.xml")
            top = ElementTree.Element("root")
            add_text_tag_to_xml(top, "item", "value")
            write_xml_file(top, fpath)
            with open(fpath, 'r') as f:
                content = f.read()
            self.assertIn("<item>", content)
            self.assertIn("value", content)
        finally:
            shutil.rmtree(tmpdir)


class TestConfigureLoggingExtended(unittest.TestCase):

    @mock.patch('software.software_functions.os.chmod')
    @mock.patch('software.software_functions.logging.FileHandler')
    @mock.patch('software.software_functions.cfg')
    def test_sets_excepthook(self, mock_cfg, mock_fh, _mock_chmod):
        mock_cfg.logging_default_format_string = (
            "%(asctime)s %(exec)s %(message)s")
        mock_fh.return_value = mock.MagicMock()
        logger = logging.getLogger('main_logger')
        audit = logging.getLogger('audit_logger')
        orig_h = logger.handlers[:]
        orig_a = audit.handlers[:]
        orig_hook = sys.excepthook
        try:
            configure_logging(logtofile=True, level=logging.INFO)
            self.assertEqual(sys.excepthook, handle_exception)
        finally:
            logger.handlers = orig_h
            audit.handlers = orig_a
            sys.excepthook = orig_hook


class TestCreateVersionedPrecheck(unittest.TestCase):

    def test_extracts_precheck_script(self):
        tmpdir = tempfile.mkdtemp()
        try:
            patch_path = os.path.join(tmpdir, "test.patch")
            script_name = "deploy-precheck"
            utils_name = "upgrade_utils.py"
            script_path = os.path.join(tmpdir, script_name)
            utils_path = os.path.join(tmpdir, utils_name)
            with open(script_path, 'w') as f:
                f.write("#!/bin/bash\necho precheck")
            with open(utils_path, 'w') as f:
                f.write("# utils")
            with tarfile.open(patch_path, "w:gz") as tar:
                tar.add(script_path, arcname=script_name)
                tar.add(utils_path, arcname=utils_name)
            versioned_dir = os.path.join(tmpdir, "versioned")
            with mock.patch('software.software_functions.constants') as mc:
                mc.VERSIONED_SCRIPTS_DIR = versioned_dir + "/%s"
                mc.DEPLOY_PRECHECK_SCRIPT = script_name
                mc.UPGRADE_UTILS_SCRIPT = utils_name
                PatchFile.create_versioned_precheck(patch_path, "24.09.1")
            target = versioned_dir + "/24.09.1"
            self.assertTrue(os.path.exists(os.path.join(target, script_name)))
            self.assertTrue(os.path.exists(os.path.join(target, utils_name)))
        finally:
            shutil.rmtree(tmpdir)

    def test_symlinks_when_no_precheck(self):
        tmpdir = tempfile.mkdtemp()
        try:
            patch_path = os.path.join(tmpdir, "test.patch")
            dummy = os.path.join(tmpdir, "dummy.txt")
            with open(dummy, 'w') as f:
                f.write("data")
            with tarfile.open(patch_path, "w:gz") as tar:
                tar.add(dummy, arcname="dummy.txt")
            versioned_dir = os.path.join(tmpdir, "versioned")
            with mock.patch('software.software_functions.constants') as mc:
                mc.VERSIONED_SCRIPTS_DIR = versioned_dir + "/%s"
                mc.DEPLOY_PRECHECK_SCRIPT = "deploy-precheck"
                mc.UPGRADE_UTILS_SCRIPT = "upgrade_utils.py"
                PatchFile.create_versioned_precheck(
                    patch_path, "24.09.1", req_patch_version="24.09.0")
            link = os.path.join(versioned_dir, "24.09.1", "deploy-precheck")
            self.assertTrue(os.path.islink(link))
        finally:
            shutil.rmtree(tmpdir)


class TestParseReleaseMetadataExtended(unittest.TestCase):

    def test_with_requires(self):
        tmpdir = tempfile.mkdtemp()
        try:
            fpath = os.path.join(tmpdir, "meta.xml")
            top = ElementTree.Element("patch")
            add_text_tag_to_xml(top, "id", "R1")
            add_text_tag_to_xml(top, "sw_version", "24.09")
            add_text_tag_to_xml(top, "summary", "test")
            req = ElementTree.SubElement(top, "requires")
            req1 = ElementTree.SubElement(req, "req_patch_id")
            req1.text = "REQ1"
            req2 = ElementTree.SubElement(req, "req_patch_id")
            req2.text = "REQ2"
            with open(fpath, 'wb') as f:
                f.write(ElementTree.tostring(top))
            data = parse_release_metadata(fpath)
            self.assertEqual(data["id"], "R1")
            self.assertIn("REQ1", data["requires"])
            self.assertIn("REQ2", data["requires"])
        finally:
            shutil.rmtree(tmpdir)

    def test_no_requires(self):
        tmpdir = tempfile.mkdtemp()
        try:
            fpath = os.path.join(tmpdir, "meta.xml")
            top = ElementTree.Element("patch")
            add_text_tag_to_xml(top, "id", "R2")
            with open(fpath, 'wb') as f:
                f.write(ElementTree.tostring(top))
            data = parse_release_metadata(fpath)
            self.assertEqual(data["id"], "R2")
            self.assertNotIn("requires", data)
        finally:
            shutil.rmtree(tmpdir)
