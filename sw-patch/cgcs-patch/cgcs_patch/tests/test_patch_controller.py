#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2019-2023 Wind River Systems, Inc.
#

import mock
import testtools
import time

from cgcs_patch import ostree_utils
from cgcs_patch.patch_controller import AgentNeighbour
from cgcs_patch.patch_controller import ControllerNeighbour
from cgcs_patch.patch_controller import PatchController


PATCH_LIST_WITH_DEPENDENCIES = \
    {
        "value": {
            "First_Patch": {"sw_version": "12.34",
                            "requires": []},
            "Second_Patch": {"sw_version": "12.34",
                             "requires": ["First_Patch"]},
            "Third_Patch": {"sw_version": "12.34",
                            "requires": ["Second_Patch"]},
            "Fourth_Patch": {"sw_version": "12.34",
                             "requires": ["Third_Patch"]}},
        "patch_id_list": ["First_Patch", "Second_Patch", "Third_Patch", "Fourth_Patch"]
    }


PATCH_LIST_WITH_DIFFERENT_SW_VERSION = \
    {
        "value": {
            "First_Patch": {"sw_version": "12.34",
                            "requires": []},
            "Second_Patch": {"sw_version": "12.34",
                             "requires": ["First_Patch"]},
            "Third_Patch": {"sw_version": "11.11",
                            "requires": ["Second_Patch"]},
            "Fourth_Patch": {"sw_version": "11.11",
                             "requires": ["Third_Patch"]}},
        "patch_id_list": ["First_Patch", "Second_Patch", "Third_Patch", "Fourth_Patch"]
    }


SINGLE_PATCH = \
    {
        "value": {
            "First_Patch": {"sw_version": "12.34",
                            "requires": []}},
        "patch_id_list": ["First_Patch"]
    }


class CgcsPatchControllerTestCase(testtools.TestCase):

    @mock.patch('builtins.open')
    def test_controller(self, _mock_open):
        # Disable the 'open'
        test_obj = PatchController()
        self.assertIsNotNone(test_obj)

    def test_controller_neighbour(self):
        test_obj = ControllerNeighbour()
        self.assertIsNotNone(test_obj)

        # reset the age
        test_obj.rx_ack()
        # get the age.  this number should be zero
        first_age = test_obj.get_age()
        # delay one second. The age should be one
        delay = 1
        time.sleep(delay)
        second_age = test_obj.get_age()
        self.assertTrue(second_age > first_age)
        # second_age should equal delay
        # to accomodate overloaded machines,  we use >=
        self.assertTrue(second_age >= delay)
        # reset the age.  the new age should be zero
        test_obj.rx_ack()
        third_age = test_obj.get_age()
        self.assertTrue(third_age < second_age)

        # set synched to True
        test_obj.rx_synced()
        self.assertTrue(test_obj.get_synced())
        # set synched to False
        test_obj.clear_synced()
        self.assertFalse(test_obj.get_synced())

    def test_agent_neighbour(self):
        test_ip = '127.0.0.1'
        test_obj = AgentNeighbour(test_ip)
        self.assertIsNotNone(test_obj)

    def create_patch_data(self, pc, metadata_obj):
        pc.patch_data.metadata = metadata_obj["value"]
        return metadata_obj["patch_id_list"]

    @mock.patch('builtins.open')
    @mock.patch.object(ostree_utils, 'get_ostree_latest_commit')
    @mock.patch.object(ostree_utils, 'get_feed_latest_commit')
    def test_patch_remove_order_with_dependencies(self, _mock_open,
                                                  _mock_ostree_latest_commit,
                                                  _mock_feed_latest_commit):
        pc = PatchController()
        patch_ids = self.create_patch_data(pc, PATCH_LIST_WITH_DEPENDENCIES)
        patch_list = pc.patch_remove_order(patch_ids)
        self.assertEqual(patch_list,
                         ["Fourth_Patch", "Third_Patch", "Second_Patch", "First_Patch"])

    @mock.patch('builtins.open')
    @mock.patch.object(ostree_utils, 'get_ostree_latest_commit')
    @mock.patch.object(ostree_utils, 'get_feed_latest_commit')
    def test_patch_remove_order_different_sw_version(self, _mock_open,
                                                     _mock_ostree_latest_commit,
                                                     _mock_feed_latest_commit):
        pc = PatchController()
        patch_ids = self.create_patch_data(pc, PATCH_LIST_WITH_DIFFERENT_SW_VERSION)
        patch_list = pc.patch_remove_order(patch_ids)
        self.assertIsNone(patch_list)

    @mock.patch('builtins.open')
    @mock.patch.object(ostree_utils, 'get_ostree_latest_commit')
    @mock.patch.object(ostree_utils, 'get_feed_latest_commit')
    def test_patch_remove_order_single_patch(self, _mock_open,
                                             _mock_ostree_latest_commit,
                                             _mock_feed_latest_commit):
        pc = PatchController()
        patch_ids = self.create_patch_data(pc, SINGLE_PATCH)
        patch_list = pc.patch_remove_order(patch_ids)
        self.assertEqual(patch_list, ["First_Patch"])
