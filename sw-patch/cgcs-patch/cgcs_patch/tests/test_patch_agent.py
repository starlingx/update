#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2019-2022 Wind River Systems, Inc.
#

import mock
import sys
import testtools

sys.modules['dnf'] = mock.Mock()
sys.modules['dnf.callback'] = mock.Mock()
sys.modules['dnf.comps'] = mock.Mock()
sys.modules['dnf.exceptions'] = mock.Mock()
sys.modules['dnf.rpm'] = mock.Mock()
sys.modules['dnf.sack'] = mock.Mock()
sys.modules['dnf.transaction'] = mock.Mock()
sys.modules['libdnf'] = mock.Mock()
sys.modules['libdnf.transaction'] = mock.Mock()

# Need to suppress E402 because the sys.modules need
# to be mocked before importing patch_agent
from cgcs_patch import patch_agent  # noqa: E402


class CgcsPatchAgentTestCase(testtools.TestCase):

    def test_cgcs_patch_agent_instantiate(self):
        pc = patch_agent.PatchAgent()
        self.assertIsNotNone(pc)
