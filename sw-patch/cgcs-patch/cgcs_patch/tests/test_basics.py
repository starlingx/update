#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2019 Wind River Systems, Inc.
#

import os
import testtools

from cgcs_patch import patch_functions


class CgcsPatchTestCase(testtools.TestCase):

    def test_cgcs_patch_functions_get_md5(self):
        md5testfile = os.path.join(os.path.dirname(__file__), 'md5test.txt')
        expected_result = 0x7179a07a8a5c50a3fc9f1971f1ec317f

        md5result = patch_functions.get_md5(md5testfile)

        self.assertEqual(expected_result, md5result)
