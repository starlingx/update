#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2025-2026 Wind River Systems, Inc.
#
import os
import shutil
import tempfile
import unittest
from unittest import mock

from packaging.version import InvalidVersion
from packaging.version import Version

from software.utils import find_file_by_regex
from software.utils import get_component_and_versions
from software.utils import get_major_release_version
from software.utils import get_repo_codename
from software.utils import get_system_debian_codename
from software.utils import parse_release_version


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

    @mock.patch('os.path.exists')
    @mock.patch('os.listdir')
    def test_find_files_basic_regex(self, mock_listdir, mock_exists):
        """Test basic regex matching"""
        mock_exists.return_value = True
        mock_listdir.return_value = ['file1.txt', 'file2.log', 'data.csv']
        result = find_file_by_regex('/test', r'file\d\.txt')
        self.assertEqual(result, ['file1.txt'])

    @mock.patch('os.path.exists')
    @mock.patch('os.listdir')
    def test_find_files_no_matches(self, mock_listdir, mock_exists):
        """Test when no files match the pattern"""
        mock_exists.return_value = True
        mock_listdir.return_value = ['file1.txt', 'file2.log', 'data.csv']
        result = find_file_by_regex('/test', r'no_match.*')
        self.assertEqual(result, [])

    @mock.patch('os.path.exists')
    def test_invalid_directory(self, mock_exists):
        """Test with invalid directory path"""
        mock_exists.return_value = False
        result = find_file_by_regex('/invalid/path', r'.*')
        self.assertEqual(result, [])

    @mock.patch('os.path.exists')
    @mock.patch('os.listdir')
    def test_multiple_matches(self, mock_listdir, mock_exists):
        """Test multiple files matching pattern"""
        mock_exists.return_value = True
        mock_listdir.return_value = ['file1.txt', 'file2.txt', 'data.csv']
        result = find_file_by_regex('/test', r'file\d\.txt')
        self.assertEqual(sorted(result), ['file1.txt', 'file2.txt'])


class TestParseReleaseVersion(unittest.TestCase):
    """

    Verifies that release IDs with component prefixes (e.g., 'starlingx-26.10.0')
    are correctly parsed into packaging.version.Version objects on Python 3.12+
    where packaging enforces strict PEP 440.
    """

    def test_prefixed_release_id(self):
        """Test parsing a release ID with 'starlingx-' prefix."""
        result = parse_release_version("starlingx-26.10.0")
        self.assertEqual(result, Version("26.10.0"))

    def test_prefixed_release_id_two_part(self):
        """Test parsing a prefixed release ID without patch version."""
        result = parse_release_version("starlingx-26.10")
        self.assertEqual(result, Version("26.10.0"))

    def test_plain_version_string(self):
        """Test parsing a plain version string without prefix."""
        result = parse_release_version("26.10.1")
        self.assertEqual(result, Version("26.10.1"))

    def test_plain_version_two_part(self):
        """Test parsing a two-part version string."""
        result = parse_release_version("26.10")
        self.assertEqual(result, Version("26.10.0"))

    def test_different_component_prefix(self):
        """Test parsing with a non-starlingx component prefix."""
        result = parse_release_version("component-22.12.3")
        self.assertEqual(result, Version("22.12.3"))

    def test_sorting_prefixed_versions(self):
        """Test that parsed versions sort correctly — the core use case."""
        ids = ["starlingx-26.10.0", "starlingx-26.10.2", "starlingx-26.10.1"]
        parsed = [(parse_release_version(dep_id), dep_id) for dep_id in ids]
        parsed.sort(key=lambda x: x[0])
        # Latest should be 26.10.2
        self.assertEqual(parsed[-1][1], "starlingx-26.10.2")
        self.assertEqual(parsed[0][1], "starlingx-26.10.0")

    def test_sorting_mixed_versions(self):
        """Test sorting a mix of prefixed and plain versions."""
        ids = ["starlingx-26.10.0", "26.10.3", "starlingx-26.10.1"]
        parsed = [(parse_release_version(dep_id), dep_id) for dep_id in ids]
        parsed.sort(key=lambda x: x[0])
        self.assertEqual(parsed[-1][1], "26.10.3")

    def test_invalid_version_raises(self):
        """Test that a completely invalid string raises InvalidVersion."""
        with self.assertRaises(InvalidVersion):
            parse_release_version("not-a-version-at-all")

    def test_preserves_original_id(self):
        """Test that the tuple pattern used in software_controller preserves the dep_id."""
        dep_id = "starlingx-26.10.0"
        ver = parse_release_version(dep_id)
        # The version object should represent 26.10.0
        self.assertEqual(str(ver), "26.10.0")
        # But the original dep_id is unchanged
        self.assertEqual(dep_id, "starlingx-26.10.0")


class TestGetSystemDebianCodename(unittest.TestCase):
    """Tests for utils.get_system_debian_codename."""

    def _write_os_release(self, content):
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir, ignore_errors=True)
        os_release = os.path.join(tmpdir, "os-release")
        with open(os_release, "w") as f:
            f.write(content)
        return os_release

    def test_reads_codename(self):
        os_release = self._write_os_release(
            'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\n'
            'VERSION_CODENAME=trixie\n'
            'ID=debian\n')
        with mock.patch('software.utils.constants.OS_RELEASE_FILE',
                        os_release):
            self.assertEqual(get_system_debian_codename(), "trixie")

    def test_reads_bullseye_codename(self):
        os_release = self._write_os_release(
            'VERSION_CODENAME=bullseye\n')
        with mock.patch('software.utils.constants.OS_RELEASE_FILE',
                        os_release):
            self.assertEqual(get_system_debian_codename(), "bullseye")

    def test_strips_quotes(self):
        os_release = self._write_os_release(
            'VERSION_CODENAME="trixie"\n')
        with mock.patch('software.utils.constants.OS_RELEASE_FILE',
                        os_release):
            self.assertEqual(get_system_debian_codename(), "trixie")

    def test_missing_codename_raises(self):
        os_release = self._write_os_release(
            'PRETTY_NAME="Debian GNU/Linux"\nID=debian\n')
        with mock.patch('software.utils.constants.OS_RELEASE_FILE',
                        os_release):
            with self.assertRaises(ValueError):
                get_system_debian_codename()


class TestGetRepoCodename(unittest.TestCase):
    """Tests for utils.get_repo_codename."""

    def _make_repo(self, codename):
        """Create a repo dir with a reprepro conf/distributions file."""
        repo_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, repo_dir, ignore_errors=True)
        conf_dir = os.path.join(repo_dir, "conf")
        os.makedirs(conf_dir)
        with open(os.path.join(conf_dir, "distributions"), "w") as f:
            f.write(
                "Origin: updates\n"
                "Label: StarlingX project updates.\n"
                "Codename: %s\n"
                "Architectures: amd64\n"
                "Components: updates\n" % codename)
        return repo_dir

    def test_reads_bullseye_repo(self):
        repo_dir = self._make_repo("bullseye")
        self.assertEqual(get_repo_codename(repo_dir), "bullseye")

    def test_reads_trixie_repo(self):
        repo_dir = self._make_repo("trixie")
        self.assertEqual(get_repo_codename(repo_dir), "trixie")

    @mock.patch('software.utils.get_system_debian_codename',
                return_value='trixie')
    def test_missing_repo_falls_back_to_system(self, _mock_system):
        # Repo dir has no conf/distributions yet.
        missing_repo = os.path.join(tempfile.mkdtemp(), "rel-99.99")
        self.addCleanup(shutil.rmtree,
                        os.path.dirname(missing_repo), ignore_errors=True)
        self.assertEqual(get_repo_codename(missing_repo), "trixie")

    def test_codename_missing_in_config_raises(self):
        repo_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, repo_dir, ignore_errors=True)
        conf_dir = os.path.join(repo_dir, "conf")
        os.makedirs(conf_dir)
        with open(os.path.join(conf_dir, "distributions"), "w") as f:
            f.write("Origin: updates\nComponents: updates\n")
        with self.assertRaises(ValueError):
            get_repo_codename(repo_dir)
