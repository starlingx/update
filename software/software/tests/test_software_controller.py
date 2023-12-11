#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2023 Wind River Systems, Inc.
#
from software.software_controller import PatchController
from software.software_controller import ReleaseValidationFailure
import unittest
from unittest.mock import MagicMock
from unittest.mock import patch
from software import constants


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
    @patch('software.software_controller.shutil.copyfile')
    @patch('software.software_controller.os.chmod')
    @patch('software.software_controller.read_upgrade_metadata')
    @patch('software.software_controller.subprocess.run')
    @patch('software.software_controller.unmount_iso_load')
    def test_process_upload_upgrade_files(self,
                                          mock_unmount_iso_load,
                                          mock_run,
                                          mock_read_upgrade_metadata,
                                          mock_chmod,  # pylint: disable=unused-argument
                                          mock_copyfile,  # pylint: disable=unused-argument
                                          mock_mount_iso_load,
                                          mock_verify_files,
                                          mock_init):   # pylint: disable=unused-argument
        controller = PatchController()
        controller.release_data = MagicMock()

        # Mock the return values of the mocked functions
        mock_verify_files.return_value = True
        mock_mount_iso_load.return_value = '/test/iso'
        mock_read_upgrade_metadata.return_value = ('2.0', [{'version': '1.0'}, {'version': '2.0'}])
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = 'Load import successful'

        # Call the function being tested
        with patch('software.software_controller.SW_VERSION', '1.0'):
            info, warning, error = controller._process_upload_upgrade_files(self.upgrade_files,   # pylint: disable=protected-access
                                                                            controller.release_data)

        # Verify that the expected functions were called with the expected arguments
        mock_verify_files.assert_called_once_with([self.upgrade_files[constants.ISO_EXTENSION]],
                                                  self.upgrade_files[constants.SIG_EXTENSION])
        mock_mount_iso_load.assert_called_once_with(self.upgrade_files[constants.ISO_EXTENSION], constants.TMP_DIR)
        mock_read_upgrade_metadata.assert_called_once_with('/test/iso')

        self.assertEqual(mock_run.call_args[0][0], [constants.LOCAL_LOAD_IMPORT_FILE,
                         "--from-release=1.0", "--to-release=2.0", "--iso-dir=/test/iso"])
        mock_unmount_iso_load.assert_called_once_with('/test/iso')

        # Verify that the expected messages were returned
        self.assertEqual(
            info, 'iso and signature files uploaded completed\nImporting iso is in progress\nLoad import successful')
        self.assertEqual(warning, '')
        self.assertEqual(error, '')

    @patch('software.software_controller.PatchController.__init__', return_value=None)
    @patch('software.software_controller.verify_files')
    @patch('software.software_controller.mount_iso_load')
    @patch('software.software_controller.unmount_iso_load')
    def test_process_upload_upgrade_files_invalid_signature(self,
                                                            mock_unmount_iso_load,  # pylint: disable=unused-argument
                                                            mock_mount_iso_load,
                                                            mock_verify_files,
                                                            mock_init):  # pylint: disable=unused-argument
        controller = PatchController()
        controller.release_data = MagicMock()

        # Mock the return values of the mocked functions
        mock_verify_files.return_value = False
        mock_mount_iso_load.return_value = '/test/iso'

        # Call the function being tested
        with patch('software.software_controller.SW_VERSION', '1.0'):
            info, warning, error = controller._process_upload_upgrade_files(self.upgrade_files,  # pylint: disable=protected-access
                                                                            controller.release_data)

        # Verify that the expected messages were returned
        self.assertEqual(info, '')
        self.assertEqual(warning, '')
        self.assertEqual(error, 'Upgrade file signature verification failed\n')

    @patch('software.software_controller.PatchController.__init__', return_value=None)
    @patch('software.software_controller.verify_files', side_effect=ReleaseValidationFailure('Invalid signature file'))
    def test_process_upload_upgrade_files_validation_error(self,
                                                           mock_verify_files,
                                                           mock_init):  # pylint: disable=unused-argument
        controller = PatchController()
        controller.release_data = MagicMock()

        mock_verify_files.return_value = False

        # Call the function being tested
        info, warning, error = controller._process_upload_upgrade_files(self.upgrade_files,  # pylint: disable=protected-access
                                                                        controller.release_data)

        # Verify that the expected messages were returned
        self.assertEqual(info, '')
        self.assertEqual(warning, '')
        self.assertEqual(error, 'Upgrade file signature verification failed\n')
