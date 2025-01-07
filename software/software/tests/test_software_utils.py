#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2025 Wind River Systems, Inc.
#
import unittest
from unittest.mock import patch

from software.utils import get_component_and_versions
from software.utils import find_file_by_regex


class TestSoftwareUtils(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_full_version_with_component(self):
        result = get_component_and_versions("component-22.12.0")
        self.assertEqual(result, ("component", "22.12.0", "22.12", "0"))

    def test_full_version_without_component(self):
        result = get_component_and_versions("22.12.0")
        self.assertEqual(result, (None, "22.12.0", "22.12", "0"))

    def test_version_without_patch(self):
        result = get_component_and_versions("22.12")
        self.assertEqual(result, (None, "22.12.0", "22.12", "0"))

    def test_version_with_component_without_patch(self):
        result = get_component_and_versions("component-22.12")
        self.assertEqual(result, ("component", "22.12.0", "22.12", "0"))

    def test_invalid_version(self):
        result = get_component_and_versions("invalid-version")
        self.assertEqual(result, (None, None, None, None))

    @patch('os.path.exists')
    @patch('os.listdir')
    def test_find_files_basic_regex(self, mock_listdir, mock_exists):
        """Test basic regex matching"""
        mock_exists.return_value = True
        mock_listdir.return_value = ['file1.txt', 'file2.log', 'data.csv']
        result = find_file_by_regex('/test', r'file\d\.txt')
        self.assertEqual(result, ['file1.txt'])

    @patch('os.path.exists')
    @patch('os.listdir')
    def test_find_files_no_matches(self, mock_listdir, mock_exists):
        """Test when no files match the pattern"""
        mock_exists.return_value = True
        mock_listdir.return_value = ['file1.txt', 'file2.log', 'data.csv']
        result = find_file_by_regex('/test', r'no_match.*')
        self.assertEqual(result, [])

    @patch('os.path.exists')
    def test_invalid_directory(self, mock_exists):
        """Test with invalid directory path"""
        mock_exists.return_value = False
        result = find_file_by_regex('/invalid/path', r'.*')
        self.assertEqual(result, [])

    @patch('os.path.exists')
    @patch('os.listdir')
    def test_multiple_matches(self, mock_listdir, mock_exists):
        """Test multiple files matching pattern"""
        mock_exists.return_value = True
        mock_listdir.return_value = ['file1.txt', 'file2.txt', 'data.csv']
        result = find_file_by_regex('/test', r'file\d\.txt')
        self.assertEqual(sorted(result), ['file1.txt', 'file2.txt'])
