#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2025-2026 Wind River Systems, Inc.
#
import unittest

from software.utils import find_file_by_regex
from software.utils import get_component_and_versions
from software.utils import get_major_release_version


class TestSoftwareUtils(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_major_release_standard_version(self):
        self.assertEqual(get_major_release_version("22.12.0"), "22.12")

    def test_major_release_without_patch(self):
        self.assertEqual(get_major_release_version("22.12"), "22.12")

    def test_major_release_str_without_patch(self):
        self.assertEqual(get_major_release_version("starlingx-22.12"), "22.12")

    def test_major_release_with_str_patch(self):
        self.assertEqual(get_major_release_version("starlingx-22.12.2"), "22.12")

    def test_major_release_none_input(self):
        self.assertIsNone(get_major_release_version(None))

    def test_major_release_empty_string(self):
        self.assertIsNone(get_major_release_version(""))

    def test_major_release_invalid_input(self):
        self.assertIsNone(get_major_release_version("invalid"))

    def test_major_release_partial_version(self):
        self.assertIsNone(get_major_release_version("22"))

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

    @unittest.mock.patch('os.path.exists')
    @unittest.mock.patch('os.listdir')
    def test_find_files_basic_regex(self, mock_listdir, mock_exists):
        """Test basic regex matching"""
        mock_exists.return_value = True
        mock_listdir.return_value = ['file1.txt', 'file2.log', 'data.csv']
        result = find_file_by_regex('/test', r'file\d\.txt')
        self.assertEqual(result, ['file1.txt'])

    @unittest.mock.patch('os.path.exists')
    @unittest.mock.patch('os.listdir')
    def test_find_files_no_matches(self, mock_listdir, mock_exists):
        """Test when no files match the pattern"""
        mock_exists.return_value = True
        mock_listdir.return_value = ['file1.txt', 'file2.log', 'data.csv']
        result = find_file_by_regex('/test', r'no_match.*')
        self.assertEqual(result, [])

    @unittest.mock.patch('os.path.exists')
    def test_invalid_directory(self, mock_exists):
        """Test with invalid directory path"""
        mock_exists.return_value = False
        result = find_file_by_regex('/invalid/path', r'.*')
        self.assertEqual(result, [])

    @unittest.mock.patch('os.path.exists')
    @unittest.mock.patch('os.listdir')
    def test_multiple_matches(self, mock_listdir, mock_exists):
        """Test multiple files matching pattern"""
        mock_exists.return_value = True
        mock_listdir.return_value = ['file1.txt', 'file2.txt', 'data.csv']
        result = find_file_by_regex('/test', r'file\d\.txt')
        self.assertEqual(sorted(result), ['file1.txt', 'file2.txt'])
