#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import os
import tempfile
import unittest
from unittest.mock import mock_open
from unittest.mock import patch

from lxml import etree

from software.tests import base  # noqa: F401
from software.software_functions import PatchFile
from software.software_functions import ReleaseData
from software.software_functions import BasePackageData
from software.software_functions import get_release_from_patch
from software.software_functions import write_xml_file
from software.software_functions import add_text_tag_to_xml


class TestAddTextTagToXml(unittest.TestCase):
    def test_adds_tag(self):
        parent = etree.Element("root")
        add_text_tag_to_xml(parent, "child", "value")
        child = parent.find("child")
        self.assertIsNotNone(child)
        self.assertEqual(child.text, "value")

    def test_empty_text(self):
        parent = etree.Element("root")
        add_text_tag_to_xml(parent, "child", "")
        child = parent.find("child")
        self.assertIsNotNone(child)


class TestWriteXmlFile(unittest.TestCase):
    def test_writes_file(self):
        top = etree.Element("root")
        etree.SubElement(top, "child").text = "data"
        with tempfile.NamedTemporaryFile(
                mode='w', suffix='.xml',
                delete=False) as tmpf:
            fname = tmpf.name
        try:
            write_xml_file(top, fname)
            self.assertTrue(os.path.exists(fname))
            with open(fname, 'r') as f:
                content = f.read()
            self.assertIn("child", content)
        finally:
            os.unlink(fname)


class TestGetReleaseFromPatch(unittest.TestCase):
    @patch('software.software_functions.subprocess.check_output')
    def test_extracts_sw_version(self, mock_check):
        xml_content = (
            '<patch><sw_version>24.09'
            '</sw_version><id>P1</id>'
            '</patch>')
        mock_check.return_value = xml_content
        result = get_release_from_patch("/path/to/patch.patch", "sw_version")
        self.assertEqual(result, "24.09")

    @patch('software.software_functions.subprocess.check_output')
    def test_extracts_id(self, mock_check):
        xml_content = (
            '<patch><sw_version>24.09'
            '</sw_version>'
            '<id>PATCH_001</id></patch>')
        mock_check.return_value = xml_content
        result = get_release_from_patch("/path/to/patch.patch", "id")
        self.assertEqual(result, "PATCH_001")

    @patch('software.software_functions.subprocess.check_output')
    def test_missing_key(self, mock_check):
        xml_content = '<patch><sw_version>24.09</sw_version></patch>'
        mock_check.return_value = xml_content
        result = get_release_from_patch("/path/to/patch.patch", "nonexistent")
        self.assertIsNone(result)

    @patch('software.software_functions.subprocess.check_output',
           side_effect=Exception("bad xml"))
    def test_exception(self, _mock_check):
        with self.assertRaises(Exception):  # noqa: H202
            get_release_from_patch("/path/to/patch.patch", "sw_version")


class TestBasePackageData(unittest.TestCase):
    @patch('software.software_functions.os.path.isdir', return_value=False)
    def test_loaddirs_no_dir(self, _mock_isdir):
        bpd = BasePackageData.__new__(BasePackageData)
        bpd.pkgs = {}
        bpd.loaddirs()
        self.assertEqual(bpd.pkgs, {})

    def test_find_version_found(self):
        bpd = BasePackageData.__new__(BasePackageData)
        bpd.pkgs = {"24.09": {"pkg1": {"x86_64": "1.0"}}}
        result = bpd.find_version("24.09", "pkg1", "x86_64")
        self.assertEqual(result, "1.0")

    def test_find_version_not_found(self):
        bpd = BasePackageData.__new__(BasePackageData)
        bpd.pkgs = {"24.09": {}}
        result = bpd.find_version("24.09", "pkg1", "x86_64")
        self.assertIsNone(result)


class TestReleaseData(unittest.TestCase):
    def test_reset(self):
        rd = ReleaseData.__new__(ReleaseData)
        rd._reset()
        self.assertEqual(rd.metadata, {})
        self.assertEqual(rd.contents, {})

    def test_add_release(self):
        rd = ReleaseData.__new__(ReleaseData)
        rd.metadata = {}
        rd.contents = {}
        new_release = ReleaseData.__new__(ReleaseData)
        new_release.metadata = {"PATCH_001": {"sw_version": "24.09"}}
        new_release.contents = {"PATCH_001": ["pkg1"]}
        rd.add_release(new_release)
        self.assertIn("PATCH_001", rd.metadata)
        self.assertIn("PATCH_001", rd.contents)

    def test_update_release(self):
        rd = ReleaseData.__new__(ReleaseData)
        rd.metadata = {"PATCH_001": {"sw_version": "24.09"}}
        rd.contents = {"PATCH_001": ["pkg1"]}
        updated = ReleaseData.__new__(ReleaseData)
        updated.metadata = {"PATCH_002": {"sw_version": "24.09.1"}}
        updated.contents = {"PATCH_002": ["pkg2"]}
        rd.add_release(updated)
        self.assertIn("PATCH_002", rd.metadata)

    def test_delete_release(self):
        rd = ReleaseData.__new__(ReleaseData)
        rd.metadata = {"PATCH_001": {"sw_version": "24.09"}}
        rd.contents = {"PATCH_001": ["pkg1"]}
        rd.delete_release("PATCH_001")
        self.assertNotIn("PATCH_001", rd.metadata)
        self.assertNotIn("PATCH_001", rd.contents)

    @patch('builtins.open',
           mock_open(
               read_data='<patch><id>P1</id><status>REL</status></patch>'))
    def test_parse_metadata_string(self):
        rd = ReleaseData.__new__(ReleaseData)
        rd.metadata = {}
        rd.contents = {}
        xml_text = """<patch>
            <id>PATCH_001</id>
            <sw_version>24.09</sw_version>
            <status>REL</status>
            <summary>Test</summary>
            <description>Test patch</description>
            <install_instructions/>
            <warnings/>
            <reboot_required>N</reboot_required>
            <contents>
                <deb>pkg1.deb</deb>
            </contents>
        </patch>
            """
        rd.parse_metadata_string(xml_text)
        self.assertIn("PATCH_001", rd.metadata)


class TestPatchFileStaticMethods(unittest.TestCase):
    @patch('software.software_functions.os.path.isfile', return_value=False)
    def test_query_patch_file_not_found(self, _mock_isfile):
        with self.assertRaises(Exception):  # noqa: H202
            PatchFile.query_patch("/nonexistent/patch.patch")
