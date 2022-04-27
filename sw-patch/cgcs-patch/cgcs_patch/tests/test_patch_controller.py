#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2019 Wind River Systems, Inc.
#

import mock
import testtools

from cgcs_patch.patch_controller import PatchController


class CgcsPatchControllerTestCase(testtools.TestCase):

    @mock.patch('six.moves.builtins.open')
    def test_cgcs_patch_controller_instantiate(self, _mock_open):
        pc = PatchController()
        self.assertIsNotNone(pc)
