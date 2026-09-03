#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import hashlib
import logging
import os
import subprocess
import unittest
from unittest import mock

from lxml import etree as ElementTree

from software.software_functions import add_text_tag_to_xml
from software.software_functions import BasePackageData
from software.software_functions import configure_logging
from software.software_functions import get_md5
from software.software_functions import get_metadata_files
from software.software_functions import get_release_from_patch
from software.software_functions import get_sw_version
from software.software_functions import is_deploy_state_in_sync
from software.software_functions import parse_release_metadata
from software.software_functions import ReleaseData
from software.software_functions import remove_major_release_deployment_flags
from software.software_functions import to_bool
from software.software_functions import write_xml_file
from software.tests import base as test_base  # noqa: F401
import tempfile
import shutil
from software.exceptions import ReleaseValidationFailure
from software.exceptions import SoftwareServiceError


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
  <pre_install>pre-install.sh</pre_install>
  <post_install>post-install.sh</post_install>
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


class TestGetMd5(unittest.TestCase):

    def test_get_md5_known_data(self):
        data = b"hello world"
        expected = int(hashlib.md5(data).hexdigest(), 16)
        m = mock.mock_open(read_data=data)
        with mock.patch('builtins.open', m):
            result = get_md5("/fake/path")
        self.assertEqual(result, expected)

    def test_get_md5_empty_file(self):
        expected = int(hashlib.md5(b"").hexdigest(), 16)
        m = mock.mock_open(read_data=b"")
        with mock.patch('builtins.open', m):
            result = get_md5("/fake/path")
        self.assertEqual(result, expected)


class TestAddTextTagToXml(unittest.TestCase):

    def test_add_tag(self):
        parent = ElementTree.Element("root")
        tag = add_text_tag_to_xml(parent, "child", "value")
        self.assertEqual(tag.tag, "child")
        self.assertEqual(tag.text, "value")
        self.assertEqual(len(parent), 1)

    def test_add_multiple_tags(self):
        parent = ElementTree.Element("root")
        add_text_tag_to_xml(parent, "a", "1")
        add_text_tag_to_xml(parent, "b", "2")
        self.assertEqual(len(parent), 2)
        self.assertEqual(parent.find("a").text, "1")
        self.assertEqual(parent.find("b").text, "2")


class TestWriteXmlFile(unittest.TestCase):

    @mock.patch('platform.python_version', return_value="3.9.18")
    def test_write_xml_file(self, _mock_ver):
        top = ElementTree.Element("root")
        add_text_tag_to_xml(top, "child", "text")
        m = mock.mock_open()
        with mock.patch('builtins.open', m):
            write_xml_file(top, "/fake/output.xml")
        m.assert_called_once_with("/fake/output.xml", 'w')
        written = m().write.call_args[0][0]
        self.assertIn("<child>", written)
        self.assertIn("text", written)


class TestGetReleaseFromPatch(unittest.TestCase):

    @mock.patch('software.software_functions.subprocess.check_output')
    def test_extracts_sw_version(self, mock_check):
        xml_bytes = b"<patch><sw_version>24.09</sw_version></patch>"
        mock_check.return_value = xml_bytes
        result = get_release_from_patch("/fake/patch.patch")
        self.assertEqual(result, "24.09")
        mock_check.assert_called_once()

    @mock.patch('software.software_functions.subprocess.check_output')
    def test_extracts_custom_key(self, mock_check):
        xml_bytes = b"<patch><id>PATCH_01</id></patch>"
        mock_check.return_value = xml_bytes
        result = get_release_from_patch("/fake/patch.patch", key="id")
        self.assertEqual(result, "PATCH_01")

    @mock.patch('software.software_functions.subprocess.check_output')
    def test_missing_key_returns_none(self, mock_check):
        xml_bytes = b"<patch><id>PATCH_01</id></patch>"
        mock_check.return_value = xml_bytes
        result = get_release_from_patch("/fake/patch.patch", key="sw_version")
        self.assertIsNone(result)

    @mock.patch('software.software_functions.subprocess.check_output')
    def test_subprocess_error_raises(self, mock_check):
        mock_check.side_effect = subprocess.CalledProcessError(
            1, 'tar', b"err")
        with self.assertRaises(subprocess.CalledProcessError):
            get_release_from_patch("/fake/patch.patch")

    @mock.patch('software.software_functions.subprocess.check_output')
    def test_invalid_xml_raises(self, mock_check):
        mock_check.return_value = b"not xml"
        with self.assertRaises(ElementTree.XMLSyntaxError):
            get_release_from_patch("/fake/patch.patch")


class TestConfigureLogging(unittest.TestCase):

    @mock.patch('software.software_functions.os.chmod')
    @mock.patch('software.software_functions.logging.FileHandler')
    @mock.patch('software.software_functions.cfg')
    def test_configure_logging_to_file(self, mock_cfg, mock_fh, _mock_chmod):
        mock_cfg.logging_default_format_string = (
            "%(asctime)s %(exec)s %(message)s")
        mock_handler = mock.MagicMock()
        mock_fh.return_value = mock_handler
        logger = logging.getLogger('main_logger')
        audit = logging.getLogger('audit_logger')
        orig_handlers = logger.handlers[:]
        orig_audit = audit.handlers[:]
        try:
            configure_logging(logtofile=True, level=logging.DEBUG)
            self.assertEqual(mock_fh.call_count, 2)
        finally:
            logger.handlers = orig_handlers
            audit.handlers = orig_audit


class TestBasePackageData(unittest.TestCase):

    @mock.patch('software.software_functions.glob.glob', return_value=[])
    @mock.patch('software.software_functions.os.path.exists',
                return_value=False)
    def test_loaddirs_no_base_dir(self, _mock_exists, _mock_glob):
        bpd = BasePackageData()
        self.assertEqual(bpd.pkgs, {})

    @mock.patch('software.software_functions.glob.glob')
    @mock.patch('software.software_functions.os.path.exists')
    def test_loaddirs_finds_releases(self, mock_exists, mock_glob):
        base = "/var/www/pages/feed"
        mock_exists.return_value = True
        mock_glob.return_value = [base + "/rel-24.09"]
        bpd = BasePackageData()
        self.assertIn("24.09", bpd.pkgs)

    @mock.patch('software.software_functions.glob.glob', return_value=[])
    @mock.patch('software.software_functions.os.path.exists',
                return_value=True)
    def test_check_release_false(self, _e, _g):
        bpd = BasePackageData()
        self.assertFalse(bpd.check_release("99.99"))

    @mock.patch('software.software_functions.glob.glob')
    @mock.patch('software.software_functions.os.path.exists')
    def test_check_release_true(self, mock_exists, mock_glob):
        base = "/var/www/pages/feed"
        mock_exists.return_value = True
        mock_glob.return_value = [base + "/rel-24.09"]
        bpd = BasePackageData()
        self.assertTrue(bpd.check_release("24.09"))

    @mock.patch('software.software_functions.glob.glob', return_value=[])
    @mock.patch('software.software_functions.os.path.exists',
                return_value=False)
    def test_find_version_missing(self, _e, _g):
        bpd = BasePackageData()
        self.assertIsNone(bpd.find_version("24.09", "pkg", "amd64"))

    @mock.patch('software.software_functions.glob.glob')
    @mock.patch('software.software_functions.os.path.exists')
    def test_loaddirs_cleans_deleted(self, mock_exists, mock_glob):
        base = "/var/www/pages/feed"
        mock_glob.return_value = [base + "/rel-24.09"]
        mock_exists.side_effect = lambda path: path == base
        bpd = BasePackageData()
        self.assertEqual(bpd.pkgs, {})


class TestReleaseData(unittest.TestCase):

    def test_parse_metadata_string_basic(self):
        rd = ReleaseData()
        rid = rd.parse_metadata_string(METADATA_XML, state="available")
        self.assertEqual(rid, "PATCH_0001")
        self.assertEqual(rd.metadata[rid]["state"], "available")
        self.assertEqual(rd.metadata[rid]["sw_version"], "24.09.1")
        self.assertEqual(rd.metadata[rid]["summary"], "Test summary")
        self.assertEqual(rd.metadata[rid]["status"], "DEV")
        self.assertEqual(rd.metadata[rid]["reboot_required"], "Y")
        self.assertEqual(rd.metadata[rid]["unremovable"], "Y")

    def test_parse_metadata_string_requires(self):
        rd = ReleaseData()
        rid = rd.parse_metadata_string(METADATA_XML)
        self.assertIn("REQ_001", rd.metadata[rid]["requires"])

    def test_parse_metadata_string_packages(self):
        rd = ReleaseData()
        rid = rd.parse_metadata_string(METADATA_XML)
        self.assertIn("pkg1.deb", rd.metadata[rid]["packages"])

    def test_parse_metadata_string_contents(self):
        rd = ReleaseData()
        rid = rd.parse_metadata_string(METADATA_XML)
        self.assertEqual(rd.contents[rid]["number_of_commits"], "1")
        self.assertEqual(rd.contents[rid]["base"]["commit"], "aaa111")
        self.assertEqual(rd.contents[rid]["commit1"]["commit"], "ccc333")

    def test_parse_metadata_no_id_returns_none(self):
        xml_no_id = "<patch><summary>no id</summary></patch>"
        rd = ReleaseData()
        result = rd.parse_metadata_string(xml_no_id)
        self.assertIsNone(result)

    def test_reboot_required_defaults_to_y(self):
        xml_str = "<patch><id>P1</id><sw_version>1.0</sw_version></patch>"
        rd = ReleaseData()
        rd.parse_metadata_string(xml_str)
        self.assertEqual(rd.metadata["P1"]["reboot_required"], "Y")

    def test_reboot_required_n(self):
        xml_str = (
            "<patch><id>P2</id><sw_version>1.0</sw_version>"
            "<reboot_required>N</reboot_required></patch>"
        )
        rd = ReleaseData()
        rd.parse_metadata_string(xml_str)
        self.assertEqual(rd.metadata["P2"]["reboot_required"], "N")

    def test_prepatched_iso_defaults_to_n(self):
        xml_str = "<patch><id>P3</id><sw_version>1.0</sw_version></patch>"
        rd = ReleaseData()
        rd.parse_metadata_string(xml_str)
        self.assertEqual(rd.metadata["P3"]["prepatched_iso"], "N")

    def test_prepatched_iso_y(self):
        xml_str = (
            "<patch><id>P4</id><sw_version>1.0</sw_version>"
            "<prepatched_iso>Y</prepatched_iso></patch>"
        )
        rd = ReleaseData()
        rd.parse_metadata_string(xml_str)
        self.assertEqual(rd.metadata["P4"]["prepatched_iso"], "Y")

    def test_add_release(self):
        rd1 = ReleaseData()
        rd1.parse_metadata_string(METADATA_XML, state="available")
        xml2 = (
            "<patch><id>P5</id><sw_version>24.09</sw_version>"
            "<summary>s</summary></patch>"
        )
        rd2 = ReleaseData()
        rd2.parse_metadata_string(xml2, state="deployed")
        rd1.add_release(rd2)
        self.assertIn("PATCH_0001", rd1.metadata)
        self.assertIn("P5", rd1.metadata)

    def test_update_release_preserves_state(self):
        rd = ReleaseData()
        rd.parse_metadata_string(METADATA_XML, state="available")
        updated = ReleaseData()
        updated_xml = METADATA_XML.replace(
            "<summary>Test summary</summary>",
            "<summary>Updated</summary>"
        )
        updated.parse_metadata_string(updated_xml, state="deployed")
        rd.update_release(updated)
        self.assertEqual(rd.metadata["PATCH_0001"]["state"], "available")
        self.assertEqual(rd.metadata["PATCH_0001"]["summary"], "Updated")

    def test_delete_release(self):
        rd = ReleaseData()
        rd.parse_metadata_string(METADATA_XML, state="available")
        rd.delete_release("PATCH_0001")
        self.assertNotIn("PATCH_0001", rd.metadata)
        self.assertNotIn("PATCH_0001", rd.contents)

    def test_reset(self):
        rd = ReleaseData()
        rd.parse_metadata_string(METADATA_XML)
        rd._reset()
        self.assertEqual(rd.metadata, {})
        self.assertEqual(rd.contents, {})

    def test_query_line(self):
        rd = ReleaseData()
        rd.parse_metadata_string(METADATA_XML, state="available")
        self.assertEqual(
            rd.query_line(
                "PATCH_0001",
                "summary"),
            "Test summary")
        self.assertIsNone(rd.query_line("PATCH_0001", "nonexistent"))
        self.assertIsNone(rd.query_line("PATCH_0001", None))
        self.assertEqual(
            rd.query_line("PATCH_0001", "contents"),
            rd.contents["PATCH_0001"])

    @mock.patch('builtins.open', mock.mock_open(read_data=METADATA_XML))
    def test_parse_metadata_file(self):
        rd = ReleaseData()
        rid = rd.parse_metadata_file("/fake/metadata.xml", state="deployed")
        self.assertEqual(rid, "PATCH_0001")
        self.assertEqual(rd.metadata[rid]["state"], "deployed")

    def test_modify_metadata_text(self):
        tmpdir = tempfile.mkdtemp()
        try:
            fpath = os.path.join(tmpdir, "meta.xml")
            top = ElementTree.Element("patch")
            add_text_tag_to_xml(top, "id", "P1")
            add_text_tag_to_xml(top, "summary", "old")
            with open(fpath, 'wb') as f:
                f.write(ElementTree.tostring(top))
            ReleaseData.modify_metadata_text(fpath, "summary", "new")
            tree = ElementTree.parse(fpath)
            self.assertEqual(tree.getroot().findtext("summary"), "new")
        finally:
            shutil.rmtree(tmpdir)

    def test_modify_metadata_text_missing_key(self):
        tmpdir = tempfile.mkdtemp()
        try:
            fpath = os.path.join(tmpdir, "meta.xml")
            top = ElementTree.Element("patch")
            add_text_tag_to_xml(top, "id", "P1")
            with open(fpath, 'wb') as f:
                f.write(ElementTree.tostring(top))
            with self.assertRaises(ReleaseValidationFailure):
                ReleaseData.modify_metadata_text(fpath, "missing_key", "val")
        finally:
            shutil.rmtree(tmpdir)


class TestIsDeployStateInSync(unittest.TestCase):

    @mock.patch('software.software_functions.get_instance')
    @mock.patch('software.software_functions.os.path.isfile')
    def test_both_exist_in_sync(self, mock_isfile, mock_db):
        mock_isfile.return_value = True
        db = mock.MagicMock()
        db.get_deploy_all.return_value = [{"state": "activated"}]
        db.get_deploy_all_synced.return_value = [{"state": "activated"}]
        db.get_deploy_host.return_value = [{"host": "c0"}]
        db.get_deploy_host_synced.return_value = [{"host": "c0"}]
        mock_db.return_value = db
        self.assertTrue(is_deploy_state_in_sync())

    @mock.patch('software.software_functions.get_instance')
    @mock.patch('software.software_functions.os.path.isfile')
    def test_both_exist_not_in_sync(self, mock_isfile, mock_db):
        mock_isfile.return_value = True
        db = mock.MagicMock()
        db.get_deploy_all.return_value = [{"state": "activated"}]
        db.get_deploy_all_synced.return_value = [{"state": "failed"}]
        db.get_deploy_host.return_value = []
        db.get_deploy_host_synced.return_value = []
        mock_db.return_value = db
        self.assertFalse(is_deploy_state_in_sync())

    @mock.patch('software.software_functions.os.path.isfile')
    def test_neither_exists(self, mock_isfile):
        mock_isfile.return_value = False
        self.assertTrue(is_deploy_state_in_sync())

    @mock.patch('software.software_functions.os.path.isfile')
    def test_only_one_exists(self, mock_isfile):
        mock_isfile.side_effect = [False, True]
        self.assertFalse(is_deploy_state_in_sync())


class TestGetMetadataFiles(unittest.TestCase):

    @mock.patch('software.software_functions.os.listdir')
    def test_finds_metadata_xml(self, mock_listdir):
        mock_listdir.return_value = [
            "PATCH_01-metadata.xml",
            "PATCH_02-metadata.xml",
            "random.txt",
            "other.xml",
        ]
        result = get_metadata_files("/fake/dir")
        self.assertEqual(len(result), 2)
        self.assertIn("/fake/dir/PATCH_01-metadata.xml", result)
        self.assertIn("/fake/dir/PATCH_02-metadata.xml", result)

    @mock.patch('software.software_functions.os.listdir')
    def test_empty_dir(self, mock_listdir):
        mock_listdir.return_value = []
        result = get_metadata_files("/fake/dir")
        self.assertEqual(result, [])


class TestGetSwVersion(unittest.TestCase):

    def test_returns_latest_version(self):
        tmpdir = tempfile.mkdtemp()
        try:
            for ver in ["24.09.0", "24.09.1"]:
                fpath = os.path.join(tmpdir, "%s-metadata.xml" % ver)
                top = ElementTree.Element("patch")
                add_text_tag_to_xml(top, "sw_version", ver)
                with open(fpath, 'wb') as f:
                    f.write(ElementTree.tostring(top))
            files = [os.path.join(tmpdir, f) for f in os.listdir(tmpdir)]
            result = get_sw_version(files)
            self.assertEqual(result, "24.09.1")
        finally:
            shutil.rmtree(tmpdir)

    def test_no_valid_version_raises(self):
        tmpdir = tempfile.mkdtemp()
        try:
            fpath = os.path.join(tmpdir, "bad-metadata.xml")
            top = ElementTree.Element("patch")
            add_text_tag_to_xml(top, "id", "P1")
            with open(fpath, 'wb') as f:
                f.write(ElementTree.tostring(top))
            files = [fpath]
            with self.assertRaises(SoftwareServiceError):
                get_sw_version(files)
        finally:
            shutil.rmtree(tmpdir)


class TestRemoveMajorReleaseDeploymentFlags(unittest.TestCase):

    @mock.patch('software.software_functions.os.remove')
    def test_removes_flags(self, mock_remove):
        result = remove_major_release_deployment_flags()
        self.assertTrue(result)
        self.assertEqual(mock_remove.call_count, 2)

    @mock.patch('software.software_functions.os.remove',
                side_effect=FileNotFoundError)
    def test_flags_not_found(self, _mock_remove):
        result = remove_major_release_deployment_flags()
        self.assertTrue(result)

    @mock.patch('software.software_functions.os.remove',
                side_effect=PermissionError("denied"))
    def test_flags_permission_error(self, _mock_remove):
        result = remove_major_release_deployment_flags()
        self.assertFalse(result)


class TestParseReleaseMetadata(unittest.TestCase):

    def test_parse_release_metadata(self):
        tmpdir = tempfile.mkdtemp()
        try:
            fpath = os.path.join(tmpdir, "meta.xml")
            top = ElementTree.Element("patch")
            add_text_tag_to_xml(top, "id", "R1")
            add_text_tag_to_xml(top, "sw_version", "24.09")
            req = ElementTree.SubElement(top, "requires")
            add_text_tag_to_xml(req, "req_patch_id", "REQ1")
            with open(fpath, 'wb') as f:
                f.write(ElementTree.tostring(top))
            data = parse_release_metadata(fpath)
            self.assertEqual(data["id"], "R1")
            self.assertEqual(data["sw_version"], "24.09")
            self.assertIn("REQ1", data["requires"])
        finally:
            shutil.rmtree(tmpdir)


class TestToBool(unittest.TestCase):

    def test_bool_true(self):
        self.assertTrue(to_bool(True))

    def test_bool_false(self):
        self.assertFalse(to_bool(False))

    def test_string_true(self):
        self.assertTrue(to_bool("true"))
        self.assertTrue(to_bool("True"))
        self.assertTrue(to_bool("TRUE"))

    def test_string_false(self):
        self.assertFalse(to_bool("false"))
        self.assertFalse(to_bool(""))

    def test_other_types(self):
        self.assertFalse(to_bool(0))
        self.assertFalse(to_bool(None))
