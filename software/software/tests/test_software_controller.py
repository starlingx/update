#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2023 Wind River Systems, Inc.
#
import unittest
from unittest.mock import MagicMock
from unittest.mock import patch
from unittest.mock import call
from software import constants

from software.software_controller import PatchController


class TestSoftwareController(unittest.TestCase):

    def setUp(self):
        self.upgrade_files = {
            constants.ISO_EXTENSION: "test.iso",
            constants.SIG_EXTENSION: "test.sig"
        }

    def tearDown(self):
        pass

    @patch('software.software_controller.PatchController.__init__', return_value=None)
    @patch('software.software_controller.verify_files')
    @patch('software.software_controller.mount_iso_load')
    @patch('software.software_controller.read_upgrade_metadata')
    @patch('software.software_functions.shutil.copyfile')
    @patch('os.makedirs')
    @patch('software.software_functions.shutil.copytree')
    @patch('software.software_controller.unmount_iso_load')
    def test_process_upload_upgrade_files(self,
                                          mock_unmount_iso_load,  # pylint: disable=unused-argument
                                          mock_copytree,  # pylint: disable=unused-argument
                                          mock_makedirs,  # pylint: disable=unused-argument
                                          mock_copyfile,  # pylint: disable=unused-argument
                                          mock_read_upgrade_metadata,
                                          mock_mount_iso_load,
                                          mock_verify_files,
                                          mock_init  # pylint: disable=unused-argument
                                          ):
        controller = PatchController()
        controller.release_data = MagicMock()
        controller.base_pkgdata = MagicMock()

        # Mock the return values of the mocked functions
        mock_verify_files.return_value = True
        mock_mount_iso_load.return_value = '/mnt/iso'
        mock_read_upgrade_metadata.return_value = ('2.0', [{'version': '1.0'}])

        # Create a mock ReleaseData object
        release_data = MagicMock()

        # Call the function being tested
        with patch("software.software_controller.SW_VERSION", "1.0"):
            info, warning, error = controller._process_upload_upgrade_files(self.upgrade_files,  # pylint: disable=protected-access
                                                                            release_data)

        # Verify that the expected functions were called with the expected arguments
        mock_mount_iso_load.assert_called_once_with(self.upgrade_files[constants.ISO_EXTENSION], '/tmp')
        mock_read_upgrade_metadata.assert_called_once_with('/mnt/iso')

        # Verify that the expected messages were returned
        self.assertEqual(info, '')
        self.assertEqual(warning, '')
        self.assertEqual(error, '')

        # Verify that the expected methods were called on the ReleaseData object
        release_data.parse_metadata.assert_called_once_with('/mnt/iso/upgrades/starlingx-2.0.0-metadata.xml', state='available')

        # Verify that the expected files were copied to the expected directories
        mock_copyfile.assert_called_once_with('/mnt/iso/upgrades/starlingx-2.0.0-metadata.xml',
                                              constants.AVAILABLE_DIR + '/starlingx-2.0.0-metadata.xml')
        expected_calls = [call(constants.AVAILABLE_DIR, exist_ok=True),
                          call(constants.FEED_OSTREE_BASE_DIR, exist_ok=True)]
        self.assertEqual(mock_makedirs.call_count, 2)
        mock_makedirs.assert_has_calls(expected_calls)
        mock_unmount_iso_load.assert_called_once_with('/mnt/iso')

    @patch('software.software_controller.PatchController.__init__', return_value=None)
    @patch('software.software_controller.verify_files')
    def test_process_upload_upgrade_files_invalid_signature(self, mock_verify_files, mock_init):  # pylint: disable=unused-argument
        controller = PatchController()
        controller.release_data = MagicMock()
        controller.base_pkgdata = MagicMock()

        # Mock the return values of the mocked functions
        mock_verify_files.return_value = False

        # Create a mock ReleaseData object
        release_data = MagicMock()

        # Call the function being tested
        with patch("software.software_controller.SW_VERSION", "1.0"):
            info, warning, error = controller._process_upload_upgrade_files(self.upgrade_files,  # pylint: disable=protected-access
                                                                            release_data)

        # Verify that the expected messages were returned
        self.assertEqual(info, '')
        self.assertEqual(warning, '')
        self.assertEqual(error, 'Upgrade file signature verification failed\n')

        # Verify that the expected methods were called on the ReleaseData object
        release_data.parse_metadata.assert_not_called()

    @patch('software.software_controller.PatchController.__init__', return_value=None)
    @patch('software.software_controller.verify_files')
    @patch('software.software_controller.mount_iso_load')
    @patch('software.software_controller.read_upgrade_metadata')
    def test_process_upload_upgrade_files_unsupported_version(self,
                                                              mock_read_upgrade_metadata,
                                                              mock_mount_iso_load,
                                                              mock_verify_files,
                                                              mock_init):  # pylint: disable=unused-argument
        controller = PatchController()
        controller.release_data = MagicMock()
        controller.base_pkgdata = MagicMock()

        # Mock the return values of the mocked functions
        mock_verify_files.return_value = True
        mock_mount_iso_load.return_value = '/mnt/iso'
        mock_read_upgrade_metadata.return_value = ('2.0', [{'version': '1.5'}])

        # Create a mock ReleaseData object
        release_data = MagicMock()

        # Call the function being tested
        with patch("software.software_controller.SW_VERSION", "1.0"):
            info, warning, error = controller._process_upload_upgrade_files(self.upgrade_files,  # pylint: disable=protected-access
                                                                            release_data)

        # Verify that the expected messages were returned
        self.assertEqual(info, '')
        self.assertEqual(warning, '')
        self.assertEqual(error, 'Upgrade is not supported for current release 1.0\n')

        # Verify that the expected methods were called on the ReleaseData object
        release_data.parse_metadata.assert_not_called()
