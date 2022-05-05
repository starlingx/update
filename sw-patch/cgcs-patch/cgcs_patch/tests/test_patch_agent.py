#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2019-2022 Wind River Systems, Inc.
#
import testtools

from cgcs_patch import patch_agent


class CgcsPatchAgentTestCase(testtools.TestCase):

    def test_cgcs_patch_agent_instantiate(self):
        pc = patch_agent.PatchAgent()
        self.assertIsNotNone(pc)
