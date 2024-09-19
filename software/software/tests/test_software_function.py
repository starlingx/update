#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2024 Wind River Systems, Inc.
#
import unittest
from unittest.mock import patch
from unittest.mock import mock_open
import xml.etree.ElementTree as ET

from software.software_functions import get_to_release_from_metadata_file, read_attributes_from_metadata_file
from software.software_functions import is_deploy_state_in_sync
from software.release_data import SWReleaseCollection
from software.software_functions import ReleaseData

metadata = """<?xml version="1.0" ?>
<patch>
  <id>23.09_RR_ALL_NODES</id>
  <sw_version>23.09</sw_version>
  <summary>Debian patch test</summary>
  <description>Reboot required patch</description>
  <install_instructions>Sample instructions</install_instructions>
  <warnings>Sample warning</warnings>
  <status>TST</status>
  <unremovable>Y</unremovable>
  <reboot_required>Y</reboot_required>
  <pre_install>pre-install.sh</pre_install>
  <post_install>post-install.sh</post_install>
  <contents>
    <ostree>
      <number_of_commits>1</number_of_commits>
      <base>
        <commit>0db647647b009c5cc02410d461de0870049bdeb66caf1bdc1ccd189ac83b8e92</commit>
        <checksum>bae3ff59c5f59c95aa8d3ccf8c1364c4c869cd428f7b5032a00a8b777cc132f7</checksum>
      </base>
      <commit1>
        <commit>38453dcb1aeb5bb9394ed02c0e6b8f2f913d00a827c89faf98cb63dff503b8e2</commit>
        <checksum>2f742b1b719f19b302c306604659ccf4aa61a1fdb7742ac79b009c79af18c79b</checksum>
      </commit1>
    </ostree>
  </contents>
  <requires/>
  <semantics/>
</patch>"""

metadata2 = """<?xml version="1.0" ?>
<patch>
  <id>23.09_NRR_INSVC</id>
  <sw_version>23.09</sw_version>
  <summary>Debian patch test</summary>
  <description>In service patch</description>
  <install_instructions>Sample instructions2</install_instructions>
  <warnings>Sample warning2</warnings>
  <status>DEV</status>
  <unremovable>N</unremovable>
  <reboot_required>N</reboot_required>
  <pre_install>pre-install.sh</pre_install>
  <post_install>post-install.sh</post_install>
  <contents>
    <ostree>
      <number_of_commits>1</number_of_commits>
      <base>
        <commit>0db647647b009c5cc02410d461de0870049bdeb66caf1bdc1ccd189ac83b8e92</commit>
        <checksum>bae3ff59c5f59c95aa8d3ccf8c1364c4c869cd428f7b5032a00a8b777cc132f7</checksum>
      </base>
      <commit1>
        <commit>0b53576092a189133d56eac49ae858c1218f480a4a859eaca2b47f2604a4e0e7</commit>
        <checksum>2f742b1b719f19b302c306604659ccf4aa61a1fdb7742ac79b009c79af18c79b</checksum>
      </commit1>
    </ostree>
  </contents>
  <requires/>
  <semantics/>
</patch>"""


expected_values = [
    {
        "release_id": "23.09_NRR_INSVC",
        "version": "23.09",
        "state": "deployed",
        "summary": "Debian patch test",
        "description": "In service patch",
        "install_instructions": "Sample instructions2",
        "warnings": "Sample warning2",
        "status": "DEV",
        "unremovable": "N",
        "pre_install": "pre-install.sh",
        "post_install": "post-install.sh",
        "commit_id": "0b53576092a189133d56eac49ae858c1218f480a4a859eaca2b47f2604a4e0e7",
        "checksum": "2f742b1b719f19b302c306604659ccf4aa61a1fdb7742ac79b009c79af18c79b",
    },
    {
        "release_id": "23.09_RR_ALL_NODES",
        "version": "23.09",
        "state": "available",
        "summary": "Debian patch test",
        "description": "Reboot required patch",
        "install_instructions": "Sample instructions",
        "warnings": "Sample warning",
        "status": "TST",
        "unremovable": "Y",
        "pre_install": "pre-install.sh",
        "post_install": "post-install.sh",
        "commit_id": "38453dcb1aeb5bb9394ed02c0e6b8f2f913d00a827c89faf98cb63dff503b8e2",
        "checksum": "2f742b1b719f19b302c306604659ccf4aa61a1fdb7742ac79b009c79af18c79b",
    }
]

package_dir = {"23.09": "/var/www/page/feed/rel_23.09"}


class TestSoftwareFunction(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    @property
    def release_collection(self):
        rd = ReleaseData()
        rd.parse_metadata_string(metadata, "available")
        rd2 = ReleaseData()
        rd2.parse_metadata_string(metadata2, "deployed")
        rd.add_release(rd2)

        rc = SWReleaseCollection(rd)
        return rc

    def test_SWReleaseCollection_iterate_releases(self):
        idx = 0
        for r in self.release_collection.iterate_releases():
            val = expected_values[idx]
            idx += 1
            self.assertEqual(val["release_id"], r.id)
            self.assertEqual(val["version"], r.sw_version)
            self.assertEqual(val["state"], r.state)
            self.assertEqual(val["summary"], r.summary)
            self.assertEqual(val["description"], r.description)
            self.assertEqual(val["install_instructions"], r.install_instructions)
            self.assertEqual(val["warnings"], r.warnings)
            self.assertEqual(val["status"], r.status)
            self.assertEqual(val["unremovable"] == 'Y', r.unremovable)
            if val["pre_install"] is None:
                self.assertIsNone(r.pre_install)
            else:
                self.assertEqual(val["pre_install"], r.pre_install)
            self.assertEqual(val["commit_id"], r.commit_id)
            self.assertEqual(val["checksum"], r.commit_checksum)

    def test_SWReleaseCollection_get_release_by_id(self):
        rd = ReleaseData()
        rd.parse_metadata_string(metadata, "available")
        rd2 = ReleaseData()
        rd2.parse_metadata_string(metadata2, "deployed")
        rd.add_release(rd2)

        rc = SWReleaseCollection(rd)

        idx = 0
        rid = expected_values[idx]["release_id"]
        r = rc.get_release_by_id(rid)
        val = expected_values[idx]
        self.assertEqual(val["release_id"], r.id)
        self.assertEqual(val["version"], r.sw_version)
        self.assertEqual(val["state"], r.state)
        self.assertEqual(val["summary"], r.summary)
        self.assertEqual(val["description"], r.description)
        self.assertEqual(val["install_instructions"], r.install_instructions)
        self.assertEqual(val["warnings"], r.warnings)
        self.assertEqual(val["status"], r.status)
        self.assertEqual(val["unremovable"] == 'Y', r.unremovable)
        if val["pre_install"] is None:
            self.assertIsNone(r.pre_install)
        else:
            self.assertEqual(val["pre_install"], r.pre_install)
        self.assertEqual(val["commit_id"], r.commit_id)
        self.assertEqual(val["checksum"], r.commit_checksum)

    def test_SWReleaseCollection_iterate_release_by_state(self):
        val = expected_values[0]
        for r in self.release_collection.iterate_releases_by_state('deployed'):
            self.assertEqual(val["release_id"], r.id)
            self.assertEqual(val["version"], r.sw_version)
            self.assertEqual(val["state"], r.state)
            self.assertEqual(val["summary"], r.summary)
            self.assertEqual(val["description"], r.description)
            self.assertEqual(val["install_instructions"], r.install_instructions)
            self.assertEqual(val["warnings"], r.warnings)
            self.assertEqual(val["status"], r.status)
            self.assertEqual(val["unremovable"] == 'Y', r.unremovable)
            if val["pre_install"] is None:
                self.assertIsNone(r.pre_install)
            else:
                self.assertEqual(val["pre_install"], r.pre_install)
            self.assertEqual(val["commit_id"], r.commit_id)
            self.assertEqual(val["checksum"], r.commit_checksum)

    @patch('os.path.join')
    @patch('lxml.etree.parse')
    def test_read_attributes_valid_xml(self, mock_parse, mock_join):
        mock_join.return_value = "/test/upgrades/metadata.xml"

        # Creating a mock XML structure
        root = ET.Element("root")
        version_elem = ET.SubElement(root, "version")
        version_elem.text = "1.0.0"

        supported_upgrades_elem = ET.SubElement(root, "supported_upgrades")
        upgrade_elem = ET.SubElement(supported_upgrades_elem, "upgrade")
        version_elem = ET.SubElement(upgrade_elem, "version")
        version_elem.text = "0.9.0"
        required_patch_elem = ET.SubElement(upgrade_elem, "required_patch")
        required_patch_elem.text = "patch_001"

        mock_parse.return_value = root

        result = read_attributes_from_metadata_file("/mocked/path")

        expected_result = {
            "to_release": "1.0.0",
            "supported_from_releases": [
                {
                    "version": "0.9.0",
                    "required_patch": "patch_001"
                }
            ]
        }

        self.assertEqual(result, expected_result)

    @patch('software.software_functions.get_metadata_files')
    @patch('software.software_functions.read_attributes_from_metadata_file')
    def test_get_to_release_from_metadata_file_without_usm(self,
                                                           mock_read_attributes,
                                                           mock_get_metadata_files):
        mock_get_metadata_files.return_value = []
        mock_read_attributes.return_value = {
            "to_release": "1.0.0",
        }

        result = get_to_release_from_metadata_file('/mnt/iso')

        assert result == "1.0.0"

    @patch('software.software_functions.get_metadata_files')
    @patch('software.software_functions.get_sw_version')
    def test_get_to_release_from_metadata_file_with_usm(self,
                                                        mock_get_ver,
                                                        mock_get_metadata_files):
        mock_get_metadata_files.return_value = ["/mnt/iso/metadata.xml"]
        mock_get_ver.return_value = "1.0.0"

        result = get_to_release_from_metadata_file('/mnt/iso')

        assert result == "1.0.0"


    @patch('software.software_controller.os.path.isfile')
    @patch('software.software_controller.json.load')
    def test_is_deploy_state_in_sync(self,
                                     mock_json_load,
                                     mock_isfile
                                    ):
        mock_isfile.side_effect = [True, True]
        state_1 = {"deploy_host": [{"hostname": "controller-0", "state": "deployed"}, {"hostname": "controller-1", "state": "deployed"}],
                   "deploy": [{"from_release": "22.12.0", "to_release": "24.09.0", "feed_repo": "/var/www/pages/feed/rel-24.09/ostree_repo",
                               "commit_id": "67d36b8f06cf3ddca871612012b283b540d118c7c738afd2b7839458eb3db42d", "reboot_required": True,
                               "state": "activate-failed"}]}
        state_2 = {"deploy_host": [{"hostname": "controller-0", "state": "deployed"}, {"hostname": "controller-1", "state": "deployed"}],
                   "deploy": [{"from_release": "22.12.0", "to_release": "24.09.0", "feed_repo": "/var/www/pages/feed/rel-24.09/ostree_repo",
                               "commit_id": "67d36b8f06cf3ddca871612012b283b540d118c7c738afd2b7839458eb3db42d", "reboot_required": True,
                               "state": "activate-failed"}]}
        mock_json_load.side_effect = [state_1, state_2]
        m = mock_open()
        with patch('builtins.open', m):
            res = is_deploy_state_in_sync()

        assert res is True


    @patch('software.software_controller.os.path.isfile')
    @patch('software.software_controller.json.load')
    def test_is_deploy_state_not_in_sync(self,
                                         mock_json_load,
                                         mock_isfile
                                        ):
        mock_isfile.side_effect = [True, True]
        state_1 = {"deploy_host": [{"hostname": "controller-0", "state": "deployed"}, {"hostname": "controller-1", "state": "deployed"}],
                   "deploy": [{"from_release": "22.12.0", "to_release": "24.09.0", "feed_repo": "/var/www/pages/feed/rel-24.09/ostree_repo",
                               "commit_id": "67d36b8f06cf3ddca871612012b283b540d118c7c738afd2b7839458eb3db42d", "reboot_required": True,
                               "state": "activate"}]}
        state_2 = {"deploy_host": [{"hostname": "controller-0", "state": "deployed"}, {"hostname": "controller-1", "state": "deployed"}],
                   "deploy": [{"from_release": "22.12.0", "to_release": "24.09.0", "feed_repo": "/var/www/pages/feed/rel-24.09/ostree_repo",
                               "commit_id": "67d36b8f06cf3ddca871612012b283b540d118c7c738afd2b7839458eb3db42d", "reboot_required": True,
                               "state": "activate-failed"}]}
        mock_json_load.side_effect = [state_1, state_2]
        m = mock_open()
        with patch('builtins.open', m):
            res = is_deploy_state_in_sync()

        assert res is False

    @patch('software.software_controller.os.path.isfile')
    @patch('software.software_controller.json.load')
    def test_is_deploy_state_in_sync_no_state(self,
                                              mock_json_load,
                                              mock_isfile
                                             ):
        mock_isfile.side_effect = [False, False]
        state_1 = {"deploy_host": [{"hostname": "controller-0", "state": "deployed"}, {"hostname": "controller-1", "state": "deployed"}],
                   "deploy": [{"from_release": "22.12.0", "to_release": "24.09.0", "feed_repo": "/var/www/pages/feed/rel-24.09/ostree_repo",
                               "commit_id": "67d36b8f06cf3ddca871612012b283b540d118c7c738afd2b7839458eb3db42d", "reboot_required": True,
                               "state": "activate-failed"}]}
        state_2 = {"deploy_host": [{"hostname": "controller-0", "state": "deployed"}, {"hostname": "controller-1", "state": "deployed"}],
                   "deploy": [{"from_release": "22.12.0", "to_release": "24.09.0", "feed_repo": "/var/www/pages/feed/rel-24.09/ostree_repo",
                               "commit_id": "67d36b8f06cf3ddca871612012b283b540d118c7c738afd2b7839458eb3db42d", "reboot_required": True,
                               "state": "activate-failed"}]}
        mock_json_load.side_effect = [state_1, state_2]
        m = mock_open()
        with patch('builtins.open', m):
            res = is_deploy_state_in_sync()

        assert res is True

    @patch('software.software_controller.os.path.isfile')
    @patch('software.software_controller.json.load')
    def test_is_deploy_state_not_in_sync_no_synced(self,
                                                   mock_json_load,
                                                   mock_isfile
                                                  ):
        mock_isfile.side_effect = [False, True]
        state_1 = {"deploy_host": [{"hostname": "controller-0", "state": "deployed"}, {"hostname": "controller-1", "state": "deployed"}],
                   "deploy": [{"from_release": "22.12.0", "to_release": "24.09.0", "feed_repo": "/var/www/pages/feed/rel-24.09/ostree_repo",
                               "commit_id": "67d36b8f06cf3ddca871612012b283b540d118c7c738afd2b7839458eb3db42d", "reboot_required": True,
                               "state": "activate-failed"}]}
        state_2 = {"deploy_host": [{"hostname": "controller-0", "state": "deployed"}, {"hostname": "controller-1", "state": "deployed"}],
                   "deploy": [{"from_release": "22.12.0", "to_release": "24.09.0", "feed_repo": "/var/www/pages/feed/rel-24.09/ostree_repo",
                               "commit_id": "67d36b8f06cf3ddca871612012b283b540d118c7c738afd2b7839458eb3db42d", "reboot_required": True,
                               "state": "activate-failed"}]}
        mock_json_load.side_effect = [state_1, state_2]
        m = mock_open()
        with patch('builtins.open', m):
            res = is_deploy_state_in_sync()

        assert res is False
