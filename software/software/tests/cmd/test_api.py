#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for software.cmd.api"""

# standard imports
import logging
from unittest import mock
from wsgiref.simple_server import WSGIServer

# third-party libraries
from oslo_log import fixture as log_fixture
import testtools

# local imports
from software.cmd import api


class SoftwareCmdAPITestCase(testtools.TestCase):
    """Unit tests for software.cmd.api"""

    @mock.patch.object(WSGIServer, 'handle_request')
    def test_main(self, mock_handle_request):
        """Test main method"""
        # Info and Warning logs are expected for this unit test.
        # 'ERROR' logs are not expected.
        self.useFixture(
            log_fixture.SetLogLevel(['software'], logging.ERROR)
        )
        mock_handle_request.side_effect = KeyboardInterrupt
        api.main()
