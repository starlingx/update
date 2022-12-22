#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2019 Wind River Systems, Inc.
#

import mock
import testtools
import time

from cgcs_patch.patch_controller import AgentNeighbour
from cgcs_patch.patch_controller import ControllerNeighbour
from cgcs_patch.patch_controller import PatchController


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
