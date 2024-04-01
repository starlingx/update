#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2024 Wind River Systems, Inc.
#
import unittest
from unittest.mock import MagicMock
from unittest.mock import patch

from software import states
from software.exceptions import SoftwareServiceError
from software.release_data import SWReleaseCollection
from software.software_functions import ReleaseData
from software.software_functions import validate_host_state_to_deploy_host

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
  <restart_script>23.09_NRR_INSVC_example-cgcs-patch-restart</restart_script>
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
        "restart_script": "23.09_NRR_INSVC_example-cgcs-patch-restart",
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
        "restart_script": None,
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
            if val["restart_script"] is None:
                self.assertIsNone(r.restart_script)
            else:
                self.assertEqual(val["restart_script"], r.restart_script)
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
        if val["restart_script"] is None:
            self.assertIsNone(r.restart_script)
        else:
            self.assertEqual(val["restart_script"], r.restart_script)
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
            if val["restart_script"] is None:
                self.assertIsNone(r.restart_script)
            else:
                self.assertEqual(val["restart_script"], r.restart_script)
            self.assertEqual(val["commit_id"], r.commit_id)
            self.assertEqual(val["checksum"], r.commit_checksum)


    @patch('software.db.api.SoftwareAPI')
    def test_validate_host_state_to_deploy_host_raises_exception_if_deploy_host_state_is_wrong(self, software_api_mock):
        # Arrange
        deploy_host_state = states.DEPLOY_HOST_STATES.DEPLOYED.value
        deploy_by_hostname = MagicMock(return_value={"state": deploy_host_state})
        software_api_mock.return_value = MagicMock(get_deploy_host_by_hostname=deploy_by_hostname)
        with self.assertRaises(SoftwareServiceError) as error:
        # Actions
            validate_host_state_to_deploy_host(hostname="abc")
        # Assertions
        error_msg = "Host state is deployed and should be pending"
        self.assertEqual(str(error.exception), error_msg)
