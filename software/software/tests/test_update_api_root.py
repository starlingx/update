#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for software.api.controllers.root module."""

import unittest
from unittest import mock

from software.tests import base as test_base  # noqa: F401
from software.api.controllers.root import Version
from software.api.controllers.root import Root


class TestVersion(unittest.TestCase):
    """Tests for Version class."""

    @mock.patch('pecan.request')
    def test_convert(self, mock_request):
        """Test Version.convert creates version with link."""
        mock_request.host_url = 'http://localhost:5493'
        ver = Version.convert('v1')
        self.assertEqual(ver.id, 'v1')
        self.assertIsNotNone(ver.links)
        self.assertEqual(len(ver.links), 1)


class TestRoot(unittest.TestCase):
    """Tests for Root class."""

    @mock.patch('pecan.request')
    def test_convert(self, mock_request):
        """Test Root.convert creates root with versions."""
        mock_request.host_url = 'http://localhost:5493'
        root = Root.convert()
        self.assertEqual(root.name, "StarlingX USM API")
        self.assertIsNotNone(root.description)
        self.assertIsNotNone(root.versions)
        self.assertIsNotNone(root.default_version)
