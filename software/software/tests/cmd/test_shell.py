#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for shell.py"""

# standard imports
from unittest import mock

# third party imports
import testtools

# local imports
from software.cmd import shell


class SoftwareShellTestCase(testtools.TestCase):
    """Unit tests for shell"""

    @mock.patch('sys.argv', [''])
    def test_no_args(self):
        """Test main method with no args"""
        shell.main()
