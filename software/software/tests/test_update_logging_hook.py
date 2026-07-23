#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for software.logging_hook module."""

import logging
import unittest

from software.logging_hook import CustomSoftwareApiLogFilter


class TestCustomSoftwareApiLogFilter(unittest.TestCase):
    """Tests for CustomSoftwareApiLogFilter."""

    def test_filter_allows_normal_message(self):
        """Test normal message passes filter."""
        log_filter = CustomSoftwareApiLogFilter(
            suppress_patterns=[r"GET /v1/deploy/software_upgrade"])
        record = logging.LogRecord(
            name='test', level=logging.INFO, pathname='',
            lineno=0, msg='POST /v1/deploy/start', args=(),
            exc_info=None)
        self.assertTrue(log_filter.filter(record))

    def test_filter_suppresses_matching_message(self):
        """Test matching message is suppressed."""
        log_filter = CustomSoftwareApiLogFilter(
            suppress_patterns=[r"GET /v1/deploy/software_upgrade"])
        record = logging.LogRecord(
            name='test', level=logging.INFO, pathname='',
            lineno=0,
            msg='GET /v1/deploy/software_upgrade request',
            args=(), exc_info=None)
        self.assertFalse(log_filter.filter(record))

    def test_filter_empty_patterns(self):
        """Test empty patterns allows all messages."""
        log_filter = CustomSoftwareApiLogFilter(suppress_patterns=[])
        record = logging.LogRecord(
            name='test', level=logging.INFO, pathname='',
            lineno=0, msg='any message', args=(), exc_info=None)
        self.assertTrue(log_filter.filter(record))

    def test_filter_multiple_patterns(self):
        """Test multiple patterns."""
        log_filter = CustomSoftwareApiLogFilter(
            suppress_patterns=[r"pattern1", r"pattern2"])
        record1 = logging.LogRecord(
            name='test', level=logging.INFO, pathname='',
            lineno=0, msg='contains pattern1', args=(), exc_info=None)
        record2 = logging.LogRecord(
            name='test', level=logging.INFO, pathname='',
            lineno=0, msg='contains pattern2', args=(), exc_info=None)
        record3 = logging.LogRecord(
            name='test', level=logging.INFO, pathname='',
            lineno=0, msg='no match', args=(), exc_info=None)
        self.assertFalse(log_filter.filter(record1))
        self.assertFalse(log_filter.filter(record2))
        self.assertTrue(log_filter.filter(record3))
