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
sys.modules['rpmUtils'] = mock.Mock()
sys.modules['rpmUtils.miscutils'] = mock.Mock()

import cgcs_patch.patch_controller  # noqa: E402


class CgcsPatchControllerTestCase(testtools.TestCase):

    @mock.patch('six.moves.builtins.open')
    def test_cgcs_patch_controller_instantiate(self, mock_open):  # pylint: disable=unused-argument
        # pylint: disable=unused-variable
        pc = cgcs_patch.patch_controller.PatchController()  # noqa: F841
