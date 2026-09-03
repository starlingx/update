#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for software.software_functions — metadata parsing,
XML utilities, and extract_patch error handling.

Tests actual parsing results, error paths, and data transformation.
"""

import os
import shutil
import tempfile
import unittest
from unittest import mock
from lxml import etree as ElementTree

from software.tests import base  # noqa: F401
from software import constants
from software.exceptions import ReleaseValidationFailure
from software.software_functions import add_text_tag_to_xml
from software.software_functions import copy_xml_file
from software.software_functions import ReleaseData
from software.software_functions import PatchFile


PRODUCT_XML = """<product>
  <id>starlingx-24.09</id>
  <sw_version>24.09</sw_version>
  <metapackages>
    <pkg>platform</pkg>
    <pkg>networking</pkg>
  </metapackages>
</product>
    """

LEGACY_XML = """<patch>
  <id>PATCH_0001</id>
  <sw_version>24.09.1</sw_version>
  <summary>Fix critical bug</summary>
  <description>Longer description of the fix</description>
  <status>Dev</status>
  <reboot_required>Y</reboot_required>
  <unremovable>Y</unremovable>
</patch>
    """

METAPACKAGE_XML = """<metapackage>
  <id>platform_24.09</id>
  <sw_version>24.09</sw_version>
  <summary>Platform metapackage</summary>
  <description>Core platform components</description>
  <reboot_required>Y</reboot_required>
  <deployable>Y</deployable>
  <data_migration>N</data_migration>
  <pre_upgrade_deploy>N</pre_upgrade_deploy>
  <packages>
    <deb>sysinv.deb</deb>
    <deb>mtce.deb</deb>
  </packages>
</metapackage>
    """


class TestAddTextTagToXml(unittest.TestCase):
    """Tests for add_text_tag_to_xml — pure XML manipulation."""

    def test_creates_new_element(self):
        """Creates new sub-element when tag doesn't exist."""
        root = ElementTree.Element("root")
        elem = add_text_tag_to_xml(root, "version", "24.09")
        self.assertEqual(elem.tag, "version")
        self.assertEqual(elem.text, "24.09")
        self.assertIs(root.find("version"), elem)

    def test_updates_existing_element(self):
        """Updates text of existing element."""
        root = ElementTree.Element("root")
        ElementTree.SubElement(root, "version").text = "old"
        elem = add_text_tag_to_xml(root, "version", "new")
        self.assertEqual(elem.text, "new")
        # Should not create duplicate
        self.assertEqual(len(root.findall("version")), 1)

    def test_none_text_preserves_element(self):
        """None text doesn't overwrite existing text."""
        root = ElementTree.Element("root")
        ElementTree.SubElement(root, "commit").text = "abc123"
        elem = add_text_tag_to_xml(root, "commit", None)
        self.assertEqual(elem.text, "abc123")

    def test_creates_empty_element_with_none(self):
        """Creates element with no text when None passed for new tag."""
        root = ElementTree.Element("root")
        elem = add_text_tag_to_xml(root, "empty_tag", None)
        self.assertIsNone(elem.text)
        self.assertIs(root.find("empty_tag"), elem)


class TestCopyXmlFile(unittest.TestCase):
    """Tests for copy_xml_file — parse, add data, write."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_copies_and_adds_data(self):
        """Copies XML file and adds additional tags."""
        src = os.path.join(self.tmpdir, "src.xml")
        dst = os.path.join(self.tmpdir, "dst.xml")
        with open(src, 'w') as f:
            f.write("<root><id>test</id></root>")

        copy_xml_file(src, dst, {"version": "24.09"})

        tree = ElementTree.parse(dst)
        root = tree.getroot()
        self.assertEqual(root.findtext("id"), "test")
        self.assertEqual(root.findtext("version"), "24.09")

    def test_copies_without_additional_data(self):
        """Copies XML file without modifications."""
        src = os.path.join(self.tmpdir, "src.xml")
        dst = os.path.join(self.tmpdir, "dst.xml")
        with open(src, 'w') as f:
            f.write("<root><id>original</id></root>")

        copy_xml_file(src, dst)

        tree = ElementTree.parse(dst)
        self.assertEqual(tree.getroot().findtext("id"), "original")


class TestParseMetadataStringProduct(unittest.TestCase):
    """Tests for ReleaseData.parse_metadata_string — product release."""

    def test_parses_product_release(self):
        """Parses product XML and extracts id, sw_version, metapackages."""
        rd = ReleaseData()
        release_id = rd.parse_metadata_string(PRODUCT_XML, state="available")

        self.assertEqual(release_id, "starlingx-24.09")
        self.assertIn("starlingx-24.09", rd.metadata)
        self.assertEqual(rd.metadata["starlingx-24.09"]["sw_version"], "24.09")
        self.assertEqual(rd.metadata["starlingx-24.09"]["state"], "available")
        # Metapackages should be registered
        metapackages = rd.metadata["starlingx-24.09"][constants.METAPACKAGES_TAG]
        self.assertIn("platform_24.09", metapackages)
        self.assertIn("networking_24.09", metapackages)

    def test_product_without_id_returns_none(self):
        """Product XML without <id> tag returns None."""
        bad_xml = "<product><sw_version>24.09</sw_version></product>"
        rd = ReleaseData()
        result = rd.parse_metadata_string(bad_xml)
        self.assertIsNone(result)

    def test_product_without_sw_version_defaults_unknown(self):
        """Product XML without sw_version defaults to 'unknown'."""
        xml = """<product>
          <id>starlingx-24.09</id>
          <metapackages><pkg>base</pkg></metapackages>
        </product>
            """
        rd = ReleaseData()
        release_id = rd.parse_metadata_string(xml)
        self.assertEqual(release_id, "starlingx-24.09")
        self.assertEqual(rd.metadata["starlingx-24.09"]["sw_version"], "unknown")


class TestParseMetadataStringLegacy(unittest.TestCase):
    """Tests for ReleaseData.parse_metadata_string — legacy release."""

    def test_parses_legacy_release(self):
        """Parses legacy patch XML and extracts all fields."""
        rd = ReleaseData()
        release_id = rd.parse_metadata_string(LEGACY_XML, state="available")

        self.assertEqual(release_id, "PATCH_0001")
        meta = rd.metadata["PATCH_0001"]
        self.assertEqual(meta["sw_version"], "24.09.1")
        self.assertEqual(meta["summary"], "Fix critical bug")
        self.assertEqual(meta["description"], "Longer description of the fix")
        self.assertEqual(meta["status"], "Dev")
        self.assertEqual(meta["reboot_required"], "Y")
        self.assertEqual(meta["state"], "available")

    def test_legacy_without_id_returns_none(self):
        """Legacy XML without <id> returns None."""
        bad_xml = "<patch><sw_version>24.09.1</sw_version></patch>"
        rd = ReleaseData()
        result = rd.parse_metadata_string(bad_xml)
        self.assertIsNone(result)

    def test_legacy_without_sw_version_returns_none(self):
        """Legacy XML without <sw_version> returns None."""
        bad_xml = "<patch><id>PATCH_001</id></patch>"
        rd = ReleaseData()
        result = rd.parse_metadata_string(bad_xml)
        self.assertIsNone(result)

    def test_legacy_default_reboot_required(self):
        """Legacy without reboot_required defaults to Y."""
        xml = """<patch>
          <id>PATCH_002</id>
          <sw_version>24.09.2</sw_version>
        </patch>
            """
        rd = ReleaseData()
        rd.parse_metadata_string(xml)
        self.assertEqual(rd.metadata["PATCH_002"]["reboot_required"], "Y")

    def test_legacy_reboot_not_required(self):
        """Legacy with reboot_required=N parses correctly."""
        xml = """<patch>
          <id>PATCH_003</id>
          <sw_version>24.09.3</sw_version>
          <reboot_required>N</reboot_required>
        </patch>
            """
        rd = ReleaseData()
        rd.parse_metadata_string(xml)
        self.assertEqual(rd.metadata["PATCH_003"]["reboot_required"], "N")

    def test_legacy_packages_parsed(self):
        """Legacy with packages list parses all debs."""
        xml = """<patch>
          <id>PATCH_004</id>
          <sw_version>24.09.4</sw_version>
          <packages>
            <deb>pkg1.deb</deb>
            <deb>pkg2.deb</deb>
          </packages>
        </patch>
            """
        rd = ReleaseData()
        rd.parse_metadata_string(xml)
        self.assertEqual(rd.metadata["PATCH_004"]["packages"],
                         ["pkg1.deb", "pkg2.deb"])

    def test_legacy_requires_parsed(self):
        """Legacy with requires list parses dependencies."""
        xml = """<patch>
          <id>PATCH_005</id>
          <sw_version>24.09.5</sw_version>
          <requires>
            <req_patch_id>PATCH_004</req_patch_id>
            <req_patch_id>PATCH_003</req_patch_id>
          </requires>
        </patch>
            """
        rd = ReleaseData()
        rd.parse_metadata_string(xml)
        self.assertEqual(rd.metadata["PATCH_005"]["requires"],
                         ["PATCH_004", "PATCH_003"])


class TestParseMetadataStringMetapackage(unittest.TestCase):
    """Tests for ReleaseData.parse_metadata_string — metapackage release."""

    def test_parses_metapackage_release(self):
        """Parses metapackage XML when product already loaded."""
        rd = ReleaseData()
        # First load the product
        rd.parse_metadata_string(PRODUCT_XML, state="available")
        # Then load the metapackage
        release_id = rd.parse_metadata_string(METAPACKAGE_XML, state="available")

        self.assertEqual(release_id, "starlingx-24.09")
        mp_meta = rd.metadata["starlingx-24.09"][constants.METAPACKAGES_TAG]["platform_24.09"]
        self.assertEqual(mp_meta["sw_version"], "24.09")
        self.assertEqual(mp_meta["component"], "platform")
        self.assertEqual(mp_meta["product"], "starlingx-24.09")
        self.assertEqual(mp_meta["deployable"], "Y")
        self.assertEqual(mp_meta["data_migration"], "N")
        self.assertEqual(mp_meta["reboot_required"], "Y")
        self.assertEqual(mp_meta["packages"], ["sysinv.deb", "mtce.deb"])

    def test_metapackage_without_id_returns_none(self):
        """Metapackage XML without <id> returns None."""
        bad_xml = "<metapackage><sw_version>24.09</sw_version></metapackage>"
        rd = ReleaseData()
        rd.parse_metadata_string(PRODUCT_XML)
        result = rd.parse_metadata_string(bad_xml)
        self.assertIsNone(result)

    def test_metapackage_without_matching_product_returns_none(self):
        """Metapackage with no matching product release returns None."""
        xml = """<metapackage>
          <id>orphan_99.99</id>
          <sw_version>99.99</sw_version>
        </metapackage>
            """
        rd = ReleaseData()
        result = rd.parse_metadata_string(xml)
        self.assertIsNone(result)


class TestExtractPatchErrorHandling(unittest.TestCase):
    """Tests for PatchFile.extract_patch error handling.

    Only mocks the boundary (PatchFile.read_patch, filesystem)
    and asserts on error return values.
    """

    @mock.patch('software.software_functions.shutil.rmtree')
    @mock.patch('software.software_functions.tempfile.mkdtemp',
                return_value='/tmp/patch_test')
    @mock.patch('software.software_functions.PatchFile.read_patch',
                side_effect=Exception("corrupt archive"))
    def test_generic_exception_returns_error_msg(self, _mock_read, _mock_tmp, _mock_rm):
        """Generic exception during read_patch returns error message."""
        patch_id, _thispatch, error_msg = PatchFile.extract_patch("/tmp/test.patch")
        self.assertIsNone(patch_id)
        self.assertIn("Error while extracting patch", error_msg)
        self.assertIn("corrupt archive", error_msg)

    @mock.patch('software.software_functions.shutil.rmtree')
    @mock.patch('software.software_functions.tempfile.mkdtemp',
                return_value='/tmp/patch_test')
    @mock.patch('software.software_functions.PatchFile.read_patch')
    def test_missing_metadata_returns_validation_error(self, mock_read, _mock_tmp, _mock_rm):
        """When metadata.xml can't be parsed, returns error."""
        # read_patch succeeds but metadata.xml doesn't exist
        mock_read.return_value = None
        with mock.patch('builtins.open', side_effect=FileNotFoundError("metadata.xml")):
            patch_id, _thispatch, error_msg = PatchFile.extract_patch("/tmp/test.patch")
        self.assertIsNone(patch_id)
        self.assertIn("Error while extracting patch", error_msg)

    @mock.patch('software.software_functions.shutil.rmtree')
    @mock.patch('software.software_functions.tempfile.mkdtemp',
                return_value='/tmp/patch_test')
    @mock.patch('software.software_functions.PatchFile.read_patch',
                side_effect=KeyError("sw_version"))
    def test_key_error_returns_missing_metadata_msg(self, _mock_read, _mock_tmp, _mock_rm):
        """KeyError during extraction returns metadata missing message."""
        patch_id, _thispatch, error_msg = PatchFile.extract_patch("/tmp/test.patch")
        self.assertIsNone(patch_id)
        self.assertIn("metadata missing required value", error_msg)
        self.assertIn("sw_version", error_msg)


class TestReleaseDataQueryLine(unittest.TestCase):
    """Tests for ReleaseData.query_line — metadata field lookup."""

    def test_query_existing_field(self):
        """Returns value for existing metadata field."""
        rd = ReleaseData()
        rd.parse_metadata_string(LEGACY_XML, state="available")
        result = rd.query_line("PATCH_0001", "summary")
        self.assertEqual(result, "Fix critical bug")

    def test_query_nonexistent_field_returns_none(self):
        """Returns None for missing field."""
        rd = ReleaseData()
        rd.parse_metadata_string(LEGACY_XML, state="available")
        result = rd.query_line("PATCH_0001", "nonexistent_field")
        self.assertIsNone(result)

    def test_query_nonexistent_release_raises(self):
        """Raises KeyError for missing release."""
        rd = ReleaseData()
        with self.assertRaises(KeyError):
            rd.query_line("MISSING_RELEASE", "summary")


class TestModifyMetadataText(unittest.TestCase):
    """Tests for ReleaseData.modify_metadata_text — XML key update."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_modifies_existing_key(self):
        """Replaces text of existing XML element."""
        filepath = os.path.join(self.tmpdir, "metadata.xml")
        with open(filepath, 'w') as f:
            f.write("<patch><id>P1</id><status>Dev</status></patch>")

        ReleaseData.modify_metadata_text(filepath, "status", "Released")

        tree = ElementTree.parse(filepath)
        self.assertEqual(tree.getroot().findtext("status"), "Released")

    def test_missing_key_raises(self):
        """Missing key raises ReleaseValidationFailure."""
        filepath = os.path.join(self.tmpdir, "metadata.xml")
        with open(filepath, 'w') as f:
            f.write("<patch><id>P1</id></patch>")

        with self.assertRaises(ReleaseValidationFailure) as ctx:
            ReleaseData.modify_metadata_text(filepath, "nonexistent", "value")
        self.assertIn("failed to find tag", str(ctx.exception))
