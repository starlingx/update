#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2019 Wind River Systems, Inc.
#

import mock
import six  # pylint: disable=unused-import
import sys
import testtools

sys.modules['rpm'] = mock.Mock()

import cgcs_patch.patch_agent  # noqa: E402


class CgcsPatchAgentTestCase(testtools.TestCase):

    def test_cgcs_patch_agent_instantiate(self):
        # pylint: disable=unused-variable
        pc = cgcs_patch.patch_agent.PatchAgent()  # noqa: F841
