#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2023-2026 Wind River Systems, Inc.
#

# This import has to be first
import os
import socket
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

from packaging import version

from software.tests import base  # pylint: disable=unused-import # noqa: F401
from software.exceptions import HostNotFound
from software.exceptions import ReleasePrecheckInvalidRequest
from software.exceptions import SoftwareServiceError
from software.exceptions import UpgradeNotSupported
from software.software_controller import PatchController
from software.software_controller import AgentNeighbour
from software import constants
from software import states
from software.states import DEPLOY_STATES


class TestSoftwareController(unittest.TestCase):

    def setUp(self):
        self.upgrade_files = {
            constants.ISO_EXTENSION: "test.iso",
            constants.SIG_EXTENSION: "test.sig"
        }

    def tearDown(self):
        pass

    @unittest.mock.patch('software.software_controller.PatchController.__init__',
                         return_value=None)
    @unittest.mock.patch('software.software_controller.PatchController.major_release_upload_check')
    @unittest.mock.patch('software.software_controller.SW_VERSION', '1.0.0')
    @unittest.mock.patch('software.software_controller.PatchController._run_load_import')
    def test_process_upload_upgrade_files(self,
                                          mock_run_load_import,
                                          mock_major_release_upload_check,
                                          mock_init):   # pylint: disable=unused-argument
        controller = PatchController()
        mock_run_load_import.return_value = "Load import successful"
        mock_major_release_upload_check.return_value = True
        from_release = '1.0.0'
        to_release = '2.0.0'
        iso_mount_dir = '/test/iso'
        upgrade_files = {
            constants.ISO_EXTENSION: "test.iso",
            constants.SIG_EXTENSION: "test.sig"
        }
        supported_from_releases = [{'version': '1.0.0'}, {'version': '1.1.0'}]
        result = controller._process_upload_upgrade_files(   # pylint: disable=protected-access
            from_release,
            to_release,
            iso_mount_dir,
            supported_from_releases,
            upgrade_files
            )

        self.assertEqual(result, "Load import successful")

    @unittest.mock.patch('software.software_controller.PatchController.__init__',
                         return_value=None)
    @unittest.mock.patch('software.software_controller.PatchController.major_release_upload_check')
    @unittest.mock.patch('software.software_controller.SW_VERSION', '1.0.0')
    def test_process_upload_upgrade_files_upgrade_not_supported(self,
                                                                mock_major_release_upload_check,
                                                                mock_init):   # pylint: disable=unused-argument
        controller = PatchController()
        mock_major_release_upload_check.return_value = True
        from_release = '1.0.0'
        to_release = '2.0.0'
        iso_mount_dir = '/test/iso'
        upgrade_files = {
            constants.ISO_EXTENSION: "test.iso",
            constants.SIG_EXTENSION: "test.sig"
        }
        supported_from_releases = [{'version': '1.1.0'}, {'version': '1.2.0'}]
        try:
            controller._process_upload_upgrade_files(   # pylint: disable=protected-access
                from_release,
                to_release,
                iso_mount_dir,
                supported_from_releases,
                upgrade_files
                )
        except UpgradeNotSupported as e:
            self.assertEqual(e.message, 'Current release 1.0.0 not supported to upgrade to 2.0.0')

    @unittest.mock.patch('software.software_controller.PatchController.__init__', return_value=None)
    @unittest.mock.patch('software.software_controller.PatchController.major_release_upload_check')
    @unittest.mock.patch('software.software_controller.read_upgrade_support_versions')
    @unittest.mock.patch('software.software_controller.SW_VERSION', '4.0.0')
    @unittest.mock.patch('software.software_controller.PatchController._run_load_import')
    def test_process_inactive_upgrade_files(self,
                                            mock_run_load_import,
                                            mock_read_upgrade_support_versions,
                                            mock_major_release_upload_check,
                                            mock_init):   # pylint: disable=unused-argument
        controller = PatchController()
        mock_run_load_import.return_value = "Load import successful"
        mock_major_release_upload_check.return_value = True
        mock_read_upgrade_support_versions.return_value = [{'version': '3.0'}, {'version': '2.0'}]
        from_release = None
        to_release = '2.0.0'
        iso_mount_dir = '/test/iso'
        upgrade_files = {
            constants.ISO_EXTENSION: "test.iso",
            constants.SIG_EXTENSION: "test.sig"
        }
        result = controller._process_inactive_upgrade_files(  # pylint: disable=protected-access
            from_release, to_release, iso_mount_dir, upgrade_files)

        self.assertEqual(result, "Load import successful")

    @unittest.mock.patch('software.software_controller.PatchController.__init__', return_value=None)
    @unittest.mock.patch('software.software_controller.PatchController.major_release_upload_check')
    @unittest.mock.patch('software.software_controller.read_upgrade_support_versions')
    @unittest.mock.patch('software.software_controller.SW_VERSION', '4.0.0')
    @unittest.mock.patch('software.software_controller.PatchController._run_load_import')
    def test_process_inactive_upgrade_files_upgrade_not_supported(self,
                                                                  mock_run_load_import,
                                                                  mock_read_upgrade_support_versions,
                                                                  mock_major_release_upload_check,
                                                                  mock_init):   # pylint: disable=unused-argument
        controller = PatchController()
        mock_run_load_import.return_value = "Load import successful"
        mock_major_release_upload_check.return_value = True
        mock_read_upgrade_support_versions.return_value = [{'version': '3.0.0'}, {'version': '2.0.0'}]
        from_release = None
        to_release = '1.0.0'
        iso_mount_dir = '/test/iso'
        upgrade_files = {
            constants.ISO_EXTENSION: "test.iso",
            constants.SIG_EXTENSION: "test.sig"
        }
        try:
            controller._process_inactive_upgrade_files(   # pylint: disable=protected-access
                from_release, to_release, iso_mount_dir, upgrade_files)
        except UpgradeNotSupported as e:
            self.assertEqual(
                e.message, 'ISO file release version 1.0 not supported to upgrade to 4.0.0')

    @unittest.mock.patch('software.software_controller.PatchController.__init__', return_value=None)
    @unittest.mock.patch('os.path.isfile', return_value=False)
    @unittest.mock.patch('os.path.join', return_value="/usr/sbin/software-deploy/major-release-upload")
    @unittest.mock.patch('software.software_controller.PatchController.get_release_meta_info')
    @unittest.mock.patch('software.software_controller.reload_release_data')
    @unittest.mock.patch('shutil.copyfile')
    @unittest.mock.patch('subprocess.run')
    @unittest.mock.patch('shutil.copytree')
    @unittest.mock.patch('shutil.rmtree')
    @unittest.mock.patch('software.software_controller.ostree_utils.add_gpg_verify_false')
    @unittest.mock.patch('os.path.exists')
    def test_run_load_import_success_without_usm_script(self,
                                                        mock_path_exists,
                                                        mock_add_gpg_verify_false,   # pylint: disable=unused-argument
                                                        mock_rmtree,   # pylint: disable=unused-argument
                                                        mock_copytree,   # pylint: disable=unused-argument
                                                        mock_subprocess_run,
                                                        mock_copyfile,     # pylint: disable=unused-argument
                                                        mock_reload_release_data,      # pylint: disable=unused-argument
                                                        mock_get_release_meta_info,
                                                        mock_join,    # pylint: disable=unused-argument
                                                        mock_isfile,   # pylint: disable=unused-argument
                                                        mock_init):    # pylint: disable=unused-argument
        # Setup
        mock_path_exists.return_value = True
        mock_subprocess_run.return_value = unittest.mock.MagicMock(returncode=0, stdout="Load import successful")
        mock_get_release_meta_info.return_value = {
            "test.iso": {"id": "starlingx-22.12", "sw_release": "22.12"},
            "test.sig": {"id": None, "sw_release": None}
        }

        controller = PatchController()
        from_release = None
        to_release = "22.12"
        iso_mount_dir = "/mnt/iso"
        upgrade_files = {
            constants.ISO_EXTENSION: "test.iso",
            constants.SIG_EXTENSION: "test.sig"
        }

        # Call the method
        local_info, local_warning, local_error, release_meta_info = controller._run_load_import(    # pylint: disable=protected-access
            from_release,
            to_release,
            iso_mount_dir,
            upgrade_files)

        # Assertions
        self.assertEqual(local_info, "Load import successful")
        self.assertEqual(local_warning, "")
        self.assertEqual(local_error, "")
        self.assertEqual(
            release_meta_info,
            {
                "test.iso": {"id": "starlingx-22.12", "sw_release": "22.12"},
                "test.sig": {"id": None, "sw_release": None}
            }
        )

    @unittest.mock.patch('software.software_controller.PatchController.__init__', return_value=None)
    @unittest.mock.patch('os.path.isfile', return_value=True)
    @unittest.mock.patch('software.software_controller.PatchController.get_release_meta_info')
    @unittest.mock.patch('software.software_controller.reload_release_data')
    @unittest.mock.patch('shutil.copyfile')
    @unittest.mock.patch('subprocess.run')
    @unittest.mock.patch('shutil.copytree')
    @unittest.mock.patch('shutil.rmtree')
    @unittest.mock.patch('software.software_controller.ostree_utils.add_gpg_verify_false')
    @unittest.mock.patch('os.path.exists')
    def test_run_load_import_success_with_usm_script(self,
                                                     mock_path_exists,
                                                     mock_add_gpg_verify_false,   # pylint: disable=unused-argument
                                                     mock_rmtree,
                                                     mock_copytree,
                                                     mock_subprocess_run,
                                                     mock_copyfile,     # pylint: disable=unused-argument
                                                     mock_reload_release_data,      # pylint: disable=unused-argument
                                                     mock_get_release_meta_info,
                                                     mock_isfile,   # pylint: disable=unused-argument
                                                     mock_init):    # pylint: disable=unused-argument
        # Setup
        mock_path_exists.return_value = True
        mock_subprocess_run.return_value = unittest.mock.MagicMock(returncode=0, stdout="Load import successful")
        mock_get_release_meta_info.return_value = {"test.iso": {"id": "123", "sw_version": "2.0.0"}}

        controller = PatchController()
        from_release = "1.0.0"
        to_release = "2.0.0"
        iso_mount_dir = "/mnt/iso"
        upgrade_files = {
            constants.ISO_EXTENSION: "test.iso",
            constants.SIG_EXTENSION: "test.sig"
        }

        # Call the method
        local_info, local_warning, local_error, release_meta_info = controller._run_load_import(    # pylint: disable=protected-access
            from_release,
            to_release,
            iso_mount_dir,
            upgrade_files)

        # Assertions
        self.assertEqual(local_info, "Load import successful")
        self.assertEqual(local_warning, "")
        self.assertEqual(local_error, "")
        self.assertEqual(release_meta_info, {"test.iso": {"id": "123", "sw_version": "2.0.0"}})
        mock_rmtree.assert_called_once_with("/opt/software/rel-2.0.0/bin")
        mock_copytree.assert_called_once_with(
            "/mnt/iso/upgrades/software-deploy", "/opt/software/rel-2.0.0/bin", symlinks=True)

    @unittest.mock.patch('software.software_controller.PatchController.__init__', return_value=None)
    @unittest.mock.patch('os.path.isfile', return_value=True)
    @unittest.mock.patch('software.software_controller.PatchController.get_release_meta_info')
    @unittest.mock.patch('software.software_controller.reload_release_data')
    @unittest.mock.patch('shutil.copyfile')
    @unittest.mock.patch('subprocess.run')
    @unittest.mock.patch('shutil.copytree')
    @unittest.mock.patch('shutil.rmtree')
    @unittest.mock.patch('software.software_controller.ostree_utils.add_gpg_verify_false')
    @unittest.mock.patch('os.path.exists')
    def test_run_load_import_script_with_usm_script_failure(self,
                                                            mock_path_exists,
                                                            mock_add_gpg_verify_false,   # pylint: disable=unused-argument
                                                            mock_rmtree,
                                                            mock_copytree,
                                                            mock_subprocess_run,
                                                            mock_copyfile,     # pylint: disable=unused-argument
                                                            mock_reload_release_data,      # pylint: disable=unused-argument
                                                            mock_get_release_meta_info,
                                                            mock_isfile,    # pylint: disable=unused-argument
                                                            mock_init):    # pylint: disable=unused-argument
        # Setup
        mock_path_exists.return_value = True
        mock_subprocess_run.return_value = unittest.mock.MagicMock(returncode=1, stdout="Load import failed")
        mock_get_release_meta_info.return_value = {}

        controller = PatchController()
        from_release = "1.0.0"
        to_release = "2.0.0"
        iso_mount_dir = "/mnt/iso"
        upgrade_files = {
            constants.ISO_EXTENSION: "test.iso",
            constants.SIG_EXTENSION: "test.sig"
        }

        # Call the method
        local_info, local_warning, local_error, release_meta_info = controller._run_load_import(    # pylint: disable=protected-access
            from_release,
            to_release,
            iso_mount_dir,
            upgrade_files)

        # Assertions
        self.assertEqual(local_info, "")
        self.assertEqual(local_warning, "")
        self.assertEqual(local_error, "Load import failed")
        self.assertEqual(release_meta_info, {})
        mock_rmtree.assert_called_once_with("/opt/software/rel-2.0.0/bin")
        mock_copytree.assert_called_once_with(
            "/mnt/iso/upgrades/software-deploy", "/opt/software/rel-2.0.0/bin", symlinks=True)

    @unittest.mock.patch('software.software_controller.PatchController.__init__', return_value=None)
    @unittest.mock.patch('os.path.isfile', return_value=True)
    @unittest.mock.patch('software.software_controller.PatchController.get_release_meta_info')
    @unittest.mock.patch('software.software_controller.reload_release_data')
    @unittest.mock.patch('shutil.copyfile')
    @unittest.mock.patch('subprocess.run')
    @unittest.mock.patch('shutil.copytree')
    @unittest.mock.patch('shutil.rmtree')
    @unittest.mock.patch('software.software_controller.ostree_utils.add_gpg_verify_false')
    @unittest.mock.patch('os.path.exists')
    def test_run_load_import_script_with_usm_script_exception(self,
                                                              mock_path_exists,
                                                              mock_add_gpg_verify_false,   # pylint: disable=unused-argument
                                                              mock_rmtree,
                                                              mock_copytree,
                                                              mock_subprocess_run,
                                                              mock_copyfile,     # pylint: disable=unused-argument
                                                              mock_reload_release_data,      # pylint: disable=unused-argument
                                                              mock_get_release_meta_info,
                                                              mock_isfile,    # pylint: disable=unused-argument
                                                              mock_init):    # pylint: disable=unused-argument
        # Setup
        mock_path_exists.return_value = True
        mock_subprocess_run.side_effect = FileNotFoundError("Unexpected error")
        mock_get_release_meta_info.return_value = {}

        controller = PatchController()
        from_release = "1.0.0"
        to_release = "2.0.0"
        iso_mount_dir = "/mnt/iso"
        upgrade_files = {
            constants.ISO_EXTENSION: "test.iso",
            constants.SIG_EXTENSION: "test.sig"
        }

        # Call the method and assert exception
        with self.assertRaises(FileNotFoundError) as context:
            controller._run_load_import(from_release, to_release, iso_mount_dir, upgrade_files)  # pylint: disable=protected-access

        self.assertTrue("Unexpected error" in str(context.exception))
        mock_rmtree.assert_called_once_with("/opt/software/rel-2.0.0/bin")
        mock_copytree.assert_called_once_with(
            "/mnt/iso/upgrades/software-deploy", "/opt/software/rel-2.0.0/bin", symlinks=True)

    @unittest.mock.patch('software.software_controller.PatchController.__init__', return_value=None)
    def test_get_software_host_upgrade_deployed(self,
                                                mock_init):  # pylint: disable=unused-argument
        controller = PatchController()
        controller.db_api_instance = unittest.mock.MagicMock()
        controller._get_software_upgrade = unittest.mock.MagicMock(return_value={  # pylint: disable=protected-access
            "from_release": "1.0.0",
            "to_release": "2.0.0"
        })
        controller.db_api_instance.get_deploy_host = unittest.mock.MagicMock(return_value=[
            {"hostname": "host1", "state": states.DEPLOYED},
            {"hostname": "host2", "state": states.DEPLOYING}
        ])

        # Test when the host is deployed
        result = controller.get_one_software_host_upgrade("host1")
        self.assertEqual(result, [{
            "hostname": "host1",
            "current_sw_version": "2.0.0",
            "target_sw_version": "2.0.0",
            "host_state": states.DEPLOYED
        }])

    @unittest.mock.patch('software.software_controller.PatchController.__init__', return_value=None)
    def test_get_software_host_upgrade_deploying(self,
                                                 mock_init):  # pylint: disable=unused-argument
        controller = PatchController()
        controller.db_api_instance = unittest.mock.MagicMock()
        controller._get_software_upgrade = unittest.mock.MagicMock(return_value={  # pylint: disable=protected-access
            "from_release": "1.0.0",
            "to_release": "2.0.0"
        })
        controller.db_api_instance.get_deploy_host = unittest.mock.MagicMock(return_value=[
            {"hostname": "host1", "state": states.DEPLOYED},
            {"hostname": "host2", "state": states.DEPLOYING}
        ])

        # Test when the host is deploying
        result = controller.get_one_software_host_upgrade("host2")
        self.assertEqual(result, [{
            "hostname": "host2",
            "current_sw_version": "1.0.0",
            "target_sw_version": "2.0.0",
            "host_state": states.DEPLOYING
        }])

    @unittest.mock.patch('software.software_controller.PatchController.__init__', return_value=None)
    def test_get_all_software_host_upgrade_deploying(self,
                                                     mock_init):  # pylint: disable=unused-argument
        controller = PatchController()
        controller.db_api_instance = unittest.mock.MagicMock()
        controller._get_software_upgrade = unittest.mock.MagicMock(return_value={  # pylint: disable=protected-access
            "from_release": "1.0.0",
            "to_release": "2.0.0"
        })
        controller.db_api_instance.get_deploy_host = unittest.mock.MagicMock(return_value=[
            {"hostname": "host1", "state": states.DEPLOYED},
            {"hostname": "host2", "state": states.DEPLOYING}
        ])

        # Test when the host is deploying
        result = controller.get_all_software_host_upgrade()
        self.assertEqual(result, [{
            "hostname": "host1",
            "current_sw_version": "2.0.0",
            "target_sw_version": "2.0.0",
            "host_state": states.DEPLOYED
        }, {
            "hostname": "host2",
            "current_sw_version": "1.0.0",
            "target_sw_version": "2.0.0",
            "host_state": states.DEPLOYING
        }])

    @unittest.mock.patch('software.software_controller.PatchController.__init__', return_value=None)
    def test_get_software_host_upgrade_none_state(self,
                                                  mock_init):  # pylint: disable=unused-argument
        controller = PatchController()
        controller.db_api_instance = unittest.mock.MagicMock()

        # Test when the deploy or deploy_hosts is None
        controller._get_software_upgrade = unittest.mock.MagicMock(  # pylint: disable=protected-access
            return_value=None)
        controller.db_api_instance.get_deploy_host.return_value = None
        result = controller.get_one_software_host_upgrade("host1")
        self.assertIsNone(result)

    @unittest.mock.patch('software.software_controller.PatchController.__init__', return_value=None)
    def test_get_software_upgrade_get_deploy_all(self,
                                                 mock_init):  # pylint: disable=unused-argument

        controller = PatchController()

        # Create a mock instance of the db_api
        db_api_instance_mock = unittest.mock.MagicMock()
        controller.db_api_instance = db_api_instance_mock

        # Create a mock return value for the get_deploy_all method
        deploy_all_mock = [{"from_release": "1.0.0", "to_release": "2.0.0", "state": "start"}]
        db_api_instance_mock.get_deploy_all.return_value = deploy_all_mock

        # Call the method being tested
        result = controller._get_software_upgrade()  # pylint: disable=protected-access

        # Verify that the expected methods were called
        db_api_instance_mock.get_deploy_all.assert_called_once()

        # Verify the expected result
        expected_result = {
            "from_release": "1.0",
            "to_release": "2.0",
            "state": "start",
            "pre_upgrade_deploy": False,
        }
        self.assertEqual(result, expected_result)

    @unittest.mock.patch('software.software_controller.PatchController.__init__', return_value=None)
    def test_get_software_upgrade_get_deploy_all_none(self,
                                                      mock_init):  # pylint: disable=unused-argument

        controller = PatchController()

        # Create a mock instance of the db_api
        db_api_instance_mock = unittest.mock.MagicMock()
        controller.db_api_instance = db_api_instance_mock

        # Create a mock return value for the get_deploy_all method
        db_api_instance_mock.get_deploy_all.return_value = None

        # Call the method being tested
        result = controller._get_software_upgrade()  # pylint: disable=protected-access

        # Verify that the expected methods were called
        db_api_instance_mock.get_deploy_all.assert_called_once()

        self.assertIsNone(result)

    @unittest.mock.patch('software.software_controller.PatchController.__init__', return_value=None)
    @unittest.mock.patch('software.software_controller.utils.gethostbyname', side_effect=socket.gaierror)
    def test_deploy_host_hostname_not_found(self,
                                            mock_gethostbyname,     # pylint: disable=unused-argument
                                            mock_init):  # pylint: disable=unused-argument
        controller = PatchController()
        controller.db_api_instance = unittest.mock.MagicMock()
        hostname = "nonexistent_host"
        force = False
        async_req = False
        rollback = False

        result = controller._deploy_host(hostname, force, async_req, rollback)  # pylint: disable=protected-access

        self.assertIn("Host %s not found" % hostname, result['error'])
        self.assertEqual(result['info'], "")
        self.assertEqual(result['warning'], "")

    @unittest.mock.patch('software.software_controller.PatchController.__init__', return_value=None)
    @unittest.mock.patch('software.software_controller.utils.gethostbyname', return_value='192.168.1.1')
    @unittest.mock.patch('software.software_controller.AgentNeighbour.is_alive', new_callable=unittest.mock.PropertyMock)
    def test_deploy_host_raises_host_not_found(self,
                                               mock_is_alive,
                                               mock_gethostbyname,  # pylint: disable=unused-argument
                                               mock_init):  # pylint: disable=unused-argument

        mock_is_alive.return_value = True

        controller = PatchController()
        agent_neighbor = AgentNeighbour('192.168.1.1')
        controller.db_api_instance = unittest.mock.MagicMock()
        controller.socket_lock = unittest.mock.MagicMock()
        controller.sock_out = unittest.mock.MagicMock()
        controller.db_api_instance.get_deploy_host_by_hostname.return_value = None
        controller.hosts = {'192.168.1.1': agent_neighbor}

        with self.assertRaises(HostNotFound):
            controller._deploy_host('test-host', force=True)    # pylint: disable=protected-access

    @unittest.mock.patch('software.software_controller.PatchController.__init__', return_value=None)
    @unittest.mock.patch('software.software_controller.utils.gethostbyname', return_value='192.168.1.1')
    @unittest.mock.patch('software.software_controller.DeployState.get_instance')
    @unittest.mock.patch('software.software_controller.DeployHostState')
    @unittest.mock.patch('software.software_controller.copy_pxeboot_update_file',
                         side_effect=subprocess.CalledProcessError(returncode=1, cmd='ls'))
    @unittest.mock.patch('software.software_controller.AgentNeighbour.is_alive', new_callable=unittest.mock.PropertyMock)
    def test_deploy_host_set_host_target_load_exception(self,
                                                        mock_is_alive,
                                                        mock_copy_pxeboot_update_file,  # pylint: disable=unused-argument
                                                        mock_deploy_host_state,
                                                        mock_deploy_state,
                                                        mock_gethostbyname,     # pylint: disable=unused-argument
                                                        mock_patch_controller_init):    # pylint: disable=unused-argument
        mock_is_alive.return_value = True
        mock_deploy_state_instance = unittest.mock.MagicMock()
        mock_deploy_state.return_value = mock_deploy_state_instance
        mock_deploy_host_state_instance = unittest.mock.MagicMock()
        mock_deploy_host_state.return_value = mock_deploy_host_state_instance

        controller = PatchController()
        agent_neighbor = AgentNeighbour('192.168.1.1')
        controller.hosts = {'192.168.1.1': agent_neighbor}
        controller.hosts_lock = unittest.mock.MagicMock()
        controller.socket_lock = unittest.mock.MagicMock()
        controller.sock_out = unittest.mock.MagicMock()
        controller.db_api_instance = unittest.mock.MagicMock()
        controller.db_api_instance.get_deploy_host_by_hostname.return_value = unittest.mock.MagicMock()
        controller.db_api_instance.get_deploy_all.return_value = [
            {'to_release': '2.1.1', 'commit_id': 'commit_1'}]
        controller.allow_insvc_patching = False
        controller.install_local = True
        controller.pre_bootstrap = False
        controller.check_upgrade_in_progress = unittest.mock.MagicMock(return_value=True)
        controller.get_software_upgrade = unittest.mock.MagicMock(return_value={'to_release': '2.1.1'})
        controller.manage_software_alarm = unittest.mock.MagicMock()

        with self.assertRaises(subprocess.CalledProcessError):
            controller._deploy_host('hostname', force=False, async_req=False)    # pylint: disable=protected-access
            assert mock_deploy_host_state.assert_called_once()

    @unittest.mock.patch('software.software_controller.PatchController.__init__', return_value=None)
    @unittest.mock.patch('software.software_controller.utils.gethostbyname', return_value='192.168.1.1')
    @unittest.mock.patch('software.software_controller.DeployState.get_instance')
    @unittest.mock.patch('software.software_controller.DeployHostState')
    @unittest.mock.patch('software.software_controller.copy_pxeboot_update_file', side_effect=FileNotFoundError)
    @unittest.mock.patch('software.software_controller.AgentNeighbour.is_alive', new_callable=unittest.mock.PropertyMock)
    def test_copy_pxeboot_update_file_exception(self,
                                                mock_is_alive,
                                                mock_copy_pxeboot_update_file,  # pylint: disable=unused-argument
                                                mock_deploy_host_state,
                                                mock_deploy_state,
                                                mock_gethostbyname,     # pylint: disable=unused-argument
                                                mock_patch_controller_init):    # pylint: disable=unused-argument
        mock_is_alive.return_value = True
        mock_deploy_state_instance = unittest.mock.MagicMock()
        mock_deploy_state.return_value = mock_deploy_state_instance
        mock_deploy_host_state_instance = unittest.mock.MagicMock()
        mock_deploy_host_state.return_value = mock_deploy_host_state_instance

        controller = PatchController()
        agent_neighbor = AgentNeighbour('192.168.1.1')
        controller.hosts = {'192.168.1.1': agent_neighbor}
        controller.hosts_lock = unittest.mock.MagicMock()
        controller.socket_lock = unittest.mock.MagicMock()
        controller.sock_out = unittest.mock.MagicMock()
        controller.db_api_instance = unittest.mock.MagicMock()
        controller.db_api_instance.get_deploy_host_by_hostname.return_value = unittest.mock.MagicMock()
        controller.db_api_instance.get_deploy_all.return_value = [
            {'to_release': '2.1.1', 'commit_id': 'commit_1'}]
        controller.allow_insvc_patching = False
        controller.install_local = True
        controller.pre_bootstrap = False
        controller.check_upgrade_in_progress = unittest.mock.MagicMock(return_value=True)
        controller.get_software_upgrade = unittest.mock.MagicMock(return_value={'to_release': '2.1.1'})
        controller.manage_software_alarm = unittest.mock.MagicMock()

        with self.assertRaises(FileNotFoundError):
            controller._deploy_host('hostname', force=False, async_req=False)    # pylint: disable=protected-access
            assert mock_deploy_host_state.assert_called_once()

    @unittest.mock.patch('software.software_controller.PatchController.__init__',
                         return_value=None
                         )
    @unittest.mock.patch('os.path.exists')
    @unittest.mock.patch('shutil.rmtree')
    @unittest.mock.patch('os.remove')
    @unittest.mock.patch('software.utils.find_file_by_regex')
    def test_clean_up_inactive_load_import(self,
                                           mock_find_file,
                                           mock_remove,
                                           mock_rmtree,
                                           mock_exists,
                                           mock_init  # pylint: disable=unused-argument
                                           ):

        controller = PatchController()

        # Mock directory existence
        mock_exists.return_value = True

        # Mock file finding
        mock_find_file.side_effect = [
            ['component-22.12-metadata.xml'],
            ['component_22.12_PATCH_001-metadata.xml', 'component_22.12_PATCH_002-metadata.xml']
        ]

        # Call the method
        release_version = "22.12"
        controller._clean_up_inactive_load_import(  # pylint: disable=protected-access
            release_version)

        # Assert directory removal calls
        expected_dirs = [
            f"{constants.DC_VAULT_PLAYBOOK_DIR}/{release_version}",
            f"{constants.DC_VAULT_LOADS_DIR}/{release_version}"
        ]
        mock_rmtree.assert_any_call(expected_dirs[0], ignore_errors=True)
        mock_rmtree.assert_any_call(expected_dirs[1], ignore_errors=True)

        expected_remove_calls = [
            unittest.mock.call('/opt/software/metadata/unavailable/component-22.12-metadata.xml'),
            unittest.mock.call('/opt/software/metadata/committed/component_22.12_PATCH_001-metadata.xml'),
            unittest.mock.call('/opt/software/metadata/committed/component_22.12_PATCH_002-metadata.xml')
        ]
        mock_remove.assert_has_calls(expected_remove_calls)

    @unittest.mock.patch('software.software_controller.PatchController.__init__', return_value=None)
    @unittest.mock.patch('software.software_controller.is_system_deploy_in_progress', return_value=False)
    @unittest.mock.patch('software.software_controller.get_active_k8s_ver', return_value="v1.34.1")
    @unittest.mock.patch('software.software_controller.DeployState.get_deploy_state',
                         return_value=DEPLOY_STATES.HOST_DONE)
    def test_abort_blocked_when_k8s_version_changed(self,
                                                    mock_get_deploy_state,   # pylint: disable=unused-argument
                                                    mock_get_k8s_ver,   # pylint: disable=unused-argument
                                                    mock_system_deploy,   # pylint: disable=unused-argument
                                                    mock_init):   # pylint: disable=unused-argument
        """Abort should raise SoftwareServiceError when K8s version changed."""
        controller = PatchController()
        controller.db_api_instance = unittest.mock.MagicMock()
        controller.db_api_instance.get_current_deploy.return_value = {
            "from_release": "26.03.0",
            "to_release": "26.09.0",
            "initial_kube_version": "v1.32.2",
        }

        with self.assertRaises(SoftwareServiceError) as ctx:
            controller.software_deploy_abort_api()

        self.assertIn("Cannot rollback", ctx.exception.error)
        self.assertIn("v1.32.2", ctx.exception.error)
        self.assertIn("v1.34.1", ctx.exception.error)

    @unittest.mock.patch('software.software_controller.PatchController.__init__', return_value=None)
    @unittest.mock.patch('software.software_controller.is_system_deploy_in_progress', return_value=False)
    @unittest.mock.patch('software.software_controller.get_active_k8s_ver', return_value="v1.32.2")
    @unittest.mock.patch('software.software_controller.ReleaseState')
    @unittest.mock.patch('software.software_controller.DeployState.get_instance')
    @unittest.mock.patch('software.software_controller.DeployHostState')
    @unittest.mock.patch('software.software_controller.get_SWReleaseCollection')
    @unittest.mock.patch('software.software_controller.DeployState.get_deploy_state',
                         return_value=DEPLOY_STATES.HOST_DONE)
    def test_abort_allowed_when_k8s_version_unchanged(self,
                                                      mock_get_deploy_state,   # pylint: disable=unused-argument
                                                      mock_get_swrc,
                                                      mock_deploy_host_state,   # pylint: disable=unused-argument
                                                      mock_deploy_state,
                                                      mock_release_state,   # pylint: disable=unused-argument
                                                      mock_get_k8s_ver,   # pylint: disable=unused-argument
                                                      mock_system_deploy,   # pylint: disable=unused-argument
                                                      mock_init):   # pylint: disable=unused-argument
        """Abort should proceed when K8s version has not changed."""
        controller = PatchController()
        controller.db_api_instance = unittest.mock.MagicMock()
        controller.db_api_instance.get_current_deploy.return_value = {
            "from_release": "26.03.0",
            "to_release": "26.09.0",
            "initial_kube_version": "v1.32.2",
            "metapackages": None,
            "pre_upgrade_deploy": False,
        }
        controller.db_api_instance.get_deploy_host.return_value = []

        mock_release_collection = unittest.mock.MagicMock()
        mock_release_collection.get_release_id_by_sw_release.return_value = \
            "starlingx-26.03.0"
        mock_release_collection.get_release_by_id.return_value = \
            unittest.mock.MagicMock(commit_id="abc123", sw_version="26.03")
        mock_get_swrc.return_value = mock_release_collection

        mock_deploy_state.return_value = unittest.mock.MagicMock()

        result = controller.software_deploy_abort_api()
        self.assertIn("info", result)
        self.assertIn("Deployment has been aborted", result["info"])

    @unittest.mock.patch('software.software_controller.PatchController.__init__', return_value=None)
    @unittest.mock.patch('software.software_controller.is_system_deploy_in_progress', return_value=True)
    @unittest.mock.patch('software.software_controller.get_active_k8s_ver')
    @unittest.mock.patch('software.software_controller.ReleaseState')
    @unittest.mock.patch('software.software_controller.DeployState.get_instance')
    @unittest.mock.patch('software.software_controller.DeployHostState')
    @unittest.mock.patch('software.software_controller.get_SWReleaseCollection')
    @unittest.mock.patch('software.software_controller.DeployState.get_deploy_state',
                         return_value=DEPLOY_STATES.HOST_DONE)
    def test_abort_skips_check_when_system_deploy_active(self,
                                                         mock_get_deploy_state,   # pylint: disable=unused-argument
                                                         mock_get_swrc,
                                                         mock_deploy_host_state,   # pylint: disable=unused-argument
                                                         mock_deploy_state,
                                                         mock_release_state,   # pylint: disable=unused-argument
                                                         mock_get_k8s_ver,
                                                         mock_system_deploy,   # pylint: disable=unused-argument
                                                         mock_init):   # pylint: disable=unused-argument
        """Abort should skip K8s check when system-deploy is active."""
        controller = PatchController()
        controller.db_api_instance = unittest.mock.MagicMock()
        controller.db_api_instance.get_current_deploy.return_value = {
            "from_release": "26.03.0",
            "to_release": "26.09.0",
            "initial_kube_version": "v1.32.2",
            "metapackages": None,
            "pre_upgrade_deploy": False,
        }
        controller.db_api_instance.get_deploy_host.return_value = []

        mock_release_collection = unittest.mock.MagicMock()
        mock_release_collection.get_release_id_by_sw_release.return_value = \
            "starlingx-26.03.0"
        mock_release_collection.get_release_by_id.return_value = \
            unittest.mock.MagicMock(commit_id="abc123", sw_version="26.03")
        mock_get_swrc.return_value = mock_release_collection

        mock_deploy_state.return_value = unittest.mock.MagicMock()

        result = controller.software_deploy_abort_api()
        self.assertIn("info", result)
        self.assertIn("Deployment has been aborted", result["info"])

        # get_active_k8s_ver should NOT be called since check was bypassed
        mock_get_k8s_ver.assert_not_called()

    @unittest.mock.patch('software.software_controller.PatchController.__init__', return_value=None)
    @unittest.mock.patch('software.software_controller.is_system_deploy_in_progress', return_value=False)
    @unittest.mock.patch('software.software_controller.get_active_k8s_ver',
                         side_effect=Exception("K8s API unavailable"))
    @unittest.mock.patch('software.software_controller.ReleaseState')
    @unittest.mock.patch('software.software_controller.DeployState.get_instance')
    @unittest.mock.patch('software.software_controller.DeployHostState')
    @unittest.mock.patch('software.software_controller.get_SWReleaseCollection')
    @unittest.mock.patch('software.software_controller.DeployState.get_deploy_state',
                         return_value=DEPLOY_STATES.HOST_DONE)
    def test_abort_fails_open_when_k8s_api_unavailable(self,
                                                       mock_get_deploy_state,   # pylint: disable=unused-argument
                                                       mock_get_swrc,
                                                       mock_deploy_host_state,   # pylint: disable=unused-argument
                                                       mock_deploy_state,
                                                       mock_release_state,   # pylint: disable=unused-argument
                                                       mock_get_k8s_ver,   # pylint: disable=unused-argument
                                                       mock_system_deploy,   # pylint: disable=unused-argument
                                                       mock_init):   # pylint: disable=unused-argument
        """Abort should proceed (fail open) when K8s API is unavailable."""
        controller = PatchController()
        controller.db_api_instance = unittest.mock.MagicMock()
        controller.db_api_instance.get_current_deploy.return_value = {
            "from_release": "26.03.0",
            "to_release": "26.09.0",
            "initial_kube_version": "v1.32.2",
            "metapackages": None,
            "pre_upgrade_deploy": False,
        }
        controller.db_api_instance.get_deploy_host.return_value = []

        mock_release_collection = unittest.mock.MagicMock()
        mock_release_collection.get_release_id_by_sw_release.return_value = \
            "starlingx-26.03.0"
        mock_release_collection.get_release_by_id.return_value = \
            unittest.mock.MagicMock(commit_id="abc123", sw_version="26.03")
        mock_get_swrc.return_value = mock_release_collection

        mock_deploy_state.return_value = unittest.mock.MagicMock()

        # Should NOT raise - fails open
        result = controller.software_deploy_abort_api()
        self.assertIn("info", result)


class TestCreateSwReleasesIt(unittest.TestCase):
    """Tests for PatchController.create_sw_releases_it, which creates the
    ostree branch/commit for each uploaded product release.
    """

    @staticmethod
    def _patch_info(*release_ids):
        """Build a patch_info list mirroring what _process_upload_patch_files
        accumulates: a list of single-key dicts {filename: {id, sw_release,
        is_product_release}}.
        """
        patch_info = []
        for rel_id in release_ids:
            sw_release = rel_id.split("-", 1)[1]  # 'starlingx-13.0.1' -> '13.0.1'
            patch_info.append({
                f"{sw_release}.patch": {
                    "id": rel_id,
                    "sw_release": sw_release,
                    "is_product_release": True,
                }
            })
        return patch_info

    def _make_release(self, rel_id):
        """A release whose .metapackages is a dict keyed by metapackage id,
        matching the real ReleaseData shape.
        """
        sw_release = rel_id.split("-", 1)[1]
        release = unittest.mock.MagicMock()
        release.metapackages = {
            f"distcloud_{sw_release}": {},
            f"infra_{sw_release}": {},
            f"k8s-common_{sw_release}": {},
        }
        release.requires_release_ids = []
        release.kernel_patch = False
        return release

    def _run(self, controller, patch_info):
        # create_sw_releases_it is @threaded and returns the Thread; join it so
        # the body completes before we assert.
        thread = controller.create_sw_releases_it(patch_info)
        if thread is not None:
            thread.join()

    @unittest.mock.patch('software.software_controller.PatchController.__init__', return_value=None)
    @unittest.mock.patch('software.software_controller.SW_VERSION', '13.0')
    @unittest.mock.patch('software.software_controller.ReleaseState')
    @unittest.mock.patch('software.software_controller.MetapackageDeploymentSet')
    @unittest.mock.patch('software.software_controller.SoftwareInventoryManager')
    @unittest.mock.patch('software.software_controller.get_SWReleaseCollection')
    def test_metapackage_filter_is_scoped_list(self,
                                               mock_get_swrc,
                                               mock_sim_cls,
                                               mock_mp_set,   # pylint: disable=unused-argument
                                               mock_rel_state,   # pylint: disable=unused-argument
                                               mock_init):   # pylint: disable=unused-argument
        # get_ordered_metapackages must be called with filter_by_ids as a LIST
        # of this release's metapackage ids (a dict is silently ignored by the
        # filter, which previously pulled in metapackages of all releases).
        controller = PatchController()
        controller.pre_bootstrap = False
        controller.software_sync = unittest.mock.MagicMock()
        controller._set_original_commit = unittest.mock.MagicMock()  # pylint: disable=protected-access
        controller.update_ostree_commit_id = unittest.mock.MagicMock()

        # release_collection is a property returning get_SWReleaseCollection(),
        # so this single mock backs both get_release_by_id and
        # get_ordered_metapackages.
        release = self._make_release("starlingx-13.0.1")
        swrc = mock_get_swrc.return_value
        swrc.get_release_by_id.return_value = release

        # SoftwareInventoryManager instance with a resolvable base
        sim = mock_sim_cls.return_value
        sim.get_deployed_commit.return_value = "deployed-commit"
        sim.get_release_by_commit.return_value = "starlingx-13.0.0"

        patch_info = self._patch_info("starlingx-13.0.1")
        self._run(controller, patch_info)

        swrc.get_ordered_metapackages.assert_called_once()
        _, kwargs = swrc.get_ordered_metapackages.call_args
        filter_by_ids = kwargs.get("filter_by_ids")
        self.assertIsInstance(filter_by_ids, list)
        self.assertEqual(
            sorted(filter_by_ids),
            ["distcloud_13.0.1", "infra_13.0.1", "k8s-common_13.0.1"])

    @unittest.mock.patch('software.software_controller.PatchController.__init__', return_value=None)
    @unittest.mock.patch('software.software_controller.SW_VERSION', '13.0')
    @unittest.mock.patch('software.software_controller.ReleaseState')
    @unittest.mock.patch('software.software_controller.MetapackageDeploymentSet')
    @unittest.mock.patch('software.software_controller.SoftwareInventoryManager')
    @unittest.mock.patch('software.software_controller.get_SWReleaseCollection')
    def test_releases_processed_in_ascending_version_order(self,
                                                           mock_get_swrc,
                                                           mock_sim_cls,
                                                           mock_mp_set,   # pylint: disable=unused-argument
                                                           mock_rel_state,   # pylint: disable=unused-argument
                                                           mock_init):   # pylint: disable=unused-argument
        # Given a batch in arbitrary order (3, 1, 2), branches must be created
        # in ascending version order so an in-batch dependency (e.g. .2
        # requires .1) finds its base branch already created.
        controller = PatchController()
        controller.pre_bootstrap = False
        controller.software_sync = unittest.mock.MagicMock()
        controller._set_original_commit = unittest.mock.MagicMock()  # pylint: disable=protected-access
        controller.update_ostree_commit_id = unittest.mock.MagicMock()

        releases = {
            rid: self._make_release(rid)
            for rid in ("starlingx-13.0.1", "starlingx-13.0.2", "starlingx-13.0.3")
        }
        swrc = mock_get_swrc.return_value
        swrc.get_release_by_id.side_effect = lambda rid: releases[rid]

        sim = mock_sim_cls.return_value
        sim.get_deployed_commit.return_value = "deployed-commit"
        sim.get_release_by_commit.return_value = "starlingx-13.0.0"

        patch_info = self._patch_info(
            "starlingx-13.0.3", "starlingx-13.0.1", "starlingx-13.0.2")
        self._run(controller, patch_info)

        # Capture the order of new_branch (2nd positional arg) passed to
        # create_sw_release_branch(base_branch, new_branch, packages, pre_bootstrap)
        created_order = [
            call.args[1] for call in sim.create_sw_release_branch.call_args_list]
        self.assertEqual(
            created_order,
            ["starlingx-13.0.1", "starlingx-13.0.2", "starlingx-13.0.3"])

    @unittest.mock.patch('software.software_controller.PatchController.__init__', return_value=None)
    @unittest.mock.patch('software.software_controller.SW_VERSION', '13.0')
    @unittest.mock.patch('software.software_controller.constants.COMPONENT_SOFTWARE_STORAGE_DIR',
                         '/opt/software/releases')
    @unittest.mock.patch('software.software_controller.ReleaseState')
    @unittest.mock.patch('software.software_controller.MetapackageDeploymentSet')
    @unittest.mock.patch('software.software_controller.SoftwareInventoryManager')
    @unittest.mock.patch('software.software_controller.get_SWReleaseCollection')
    def test_kernel_patch_uses_prebuilt_commit_branch(self,
                                                      mock_get_swrc,
                                                      mock_sim_cls,
                                                      mock_mp_set,   # pylint: disable=unused-argument
                                                      mock_rel_state,   # pylint: disable=unused-argument
                                                      mock_init):   # pylint: disable=unused-argument
        # A kernel patch ships a pre-built ostree commit in extra.tar, so its
        # branch is created via create_kernel_release_branch (pulling that
        # commit) rather than create_sw_release_branch (assembling from debs).
        controller = PatchController()
        controller.pre_bootstrap = False
        controller.software_sync = unittest.mock.MagicMock()
        controller._set_original_commit = unittest.mock.MagicMock()  # pylint: disable=protected-access
        controller.update_ostree_commit_id = unittest.mock.MagicMock()

        release = self._make_release("starlingx-13.0.1")
        release.kernel_patch = True
        swrc = mock_get_swrc.return_value
        swrc.get_release_by_id.return_value = release

        # No <requires>: the parent is resolved from the deployed commit
        sim = mock_sim_cls.return_value
        sim.get_deployed_commit.return_value = "deployed-commit"
        sim.get_release_by_commit.return_value = "starlingx-13.0.0"

        patch_info = self._patch_info("starlingx-13.0.1")
        self._run(controller, patch_info)

        # The kernel path is taken; the deb-assembly path is not
        sim.create_sw_release_branch.assert_not_called()
        sim.create_kernel_release_branch.assert_called_once_with(
            "starlingx-13.0.0",
            "starlingx-13.0.1",
            "/opt/software/releases/13.0.1/extra/ostree_repo")


class _FakeMetapackage:
    """Minimal metapackage release stand-in for span-logic tests."""

    def __init__(self, component, sw_release, state, product):
        self.id = f"{component}_{sw_release}"
        self.component = component
        self.sw_release = sw_release
        self.state = state
        self.product = product
        self.reboot_required = False


class _FakeProductRelease:
    """Minimal product release stand-in. metapackages is a dict keyed by
    metapackage id (matching the real ReleaseData shape). deps is the list of
    lower product releases (its full requires closure), highest-first order not
    assumed.
    """

    def __init__(self, rel_id, sw_release, metapackages, deps):
        self.id = rel_id
        self.sw_release = sw_release
        self.metapackages = {mp.id: mp for mp in metapackages}
        self._deps = deps
        self.version_obj = version.parse(sw_release)

    @property
    def state(self):
        # Product state derived from its metapackages: DEPLOYED only when all
        # are deployed, DEPLOYED_PARTIAL when some are, else AVAILABLE.
        mp_states = {mp.state for mp in self.metapackages.values()}
        if mp_states == {states.DEPLOYED}:
            return states.DEPLOYED
        if states.DEPLOYED in mp_states:
            return states.DEPLOYED_PARTIAL
        return states.AVAILABLE

    def get_all_dependencies(self):
        return list(self._deps)

    # sortable by version (used by _get_target_component_versions)
    def __lt__(self, other):
        return self.version_obj < other.version_obj


class _FakeCollection:
    """Fake SWReleaseCollection exposing only what the span-logic helpers use."""

    def __init__(self, product_releases, highest_release=None):
        self._products = {r.id: r for r in product_releases}
        self._metapackages = {}
        for r in product_releases:
            self._metapackages.update(r.metapackages)
        self.highest_release = highest_release

    def get_product_release_by_id(self, rel_id):
        return self._products.get(rel_id)

    def get_release_by_id(self, rel_id):
        return self._products.get(rel_id) or self._metapackages.get(rel_id)

    def get_metapackage_release_by_id(self, mp_id):
        return self._metapackages.get(mp_id)

    def get_metapackages_id_by_product_id(self, product_id):
        product = self._products.get(product_id)
        if product is None:
            return None
        return list(product.metapackages)


class TestSpanHelpers(unittest.TestCase):
    """Tests for the deploy-span helper logic in PatchController:
    _collect_span_metapackage_ids, _get_metapackages_to_remove,
    _get_target_component_versions and _resolve_target_product_id.
    """

    COMPONENTS = ("distcloud", "infra", "k8s-common")

    def _build_chain(self, spec):
        """Build a linear release chain from a spec.

        :param spec: ordered list (lowest-first) of (sw_release, {component:
            state}) describing each product release and the state of each of
            its metapackages.
        :return: (collection, {sw_release: product_release})
        """
        products = []
        by_version = {}
        deps_so_far = []
        for sw_release, comp_states in spec:
            rel_id = f"starlingx-{sw_release}"
            mps = [_FakeMetapackage(c, sw_release, st, rel_id)
                   for c, st in comp_states.items()]
            # deps = every lower release already built (full requires closure)
            product = _FakeProductRelease(rel_id, sw_release, mps, list(deps_so_far))
            products.append(product)
            by_version[sw_release] = product
            deps_so_far.append(product)
        return _FakeCollection(products), by_version

    def _controller(self):
        # release_collection is a property returning get_SWReleaseCollection();
        # tests patch that property to return the fake collection.
        return PatchController()

    # ---- _collect_span_metapackage_ids ----------------------------------

    @unittest.mock.patch('software.software_controller.PatchController.__init__',
                         return_value=None)
    def test_collect_span_all_lower_available(self, _mock_init):
        # .0 deployed, .1/.2 fully available; target .3 available.
        # Span should collect all of .1 and .2's metapackages (not .3's own).
        collection, _ = self._build_chain([
            ("13.0.0", {c: states.DEPLOYED for c in self.COMPONENTS}),
            ("13.0.1", {c: states.AVAILABLE for c in self.COMPONENTS}),
            ("13.0.2", {c: states.AVAILABLE for c in self.COMPONENTS}),
            ("13.0.3", {c: states.AVAILABLE for c in self.COMPONENTS}),
        ])
        controller = self._controller()
        with unittest.mock.patch.object(
                type(controller), 'release_collection',
                new_callable=unittest.mock.PropertyMock,
                return_value=collection):
            span = controller._collect_span_metapackage_ids("starlingx-13.0.3")
        self.assertEqual(
            sorted(span),
            sorted([f"{c}_13.0.1" for c in self.COMPONENTS]
                   + [f"{c}_13.0.2" for c in self.COMPONENTS]))

    @unittest.mock.patch('software.software_controller.PatchController.__init__',
                         return_value=None)
    def test_collect_span_skips_deployed_of_partial_lower(self, _mock_init):
        # .1 is deployed-partial: infra deployed, others available.
        # Only .1's not-deployed metapackages join the span.
        collection, _ = self._build_chain([
            ("13.0.0", {c: states.DEPLOYED for c in self.COMPONENTS}),
            ("13.0.1", {"distcloud": states.AVAILABLE,
                        "infra": states.DEPLOYED,
                        "k8s-common": states.AVAILABLE}),
            ("13.0.2", {c: states.AVAILABLE for c in self.COMPONENTS}),
            ("13.0.3", {c: states.AVAILABLE for c in self.COMPONENTS}),
        ])
        controller = self._controller()
        with unittest.mock.patch.object(
                type(controller), 'release_collection',
                new_callable=unittest.mock.PropertyMock,
                return_value=collection):
            span = controller._collect_span_metapackage_ids("starlingx-13.0.3")
        self.assertNotIn("infra_13.0.1", span)  # already deployed
        self.assertIn("distcloud_13.0.1", span)
        self.assertIn("k8s-common_13.0.1", span)
        for c in self.COMPONENTS:
            self.assertIn(f"{c}_13.0.2", span)

    # ---- _get_metapackages_to_remove ------------------------------------

    @unittest.mock.patch('software.software_controller.PatchController.__init__',
                         return_value=None)
    def test_remove_excludes_target_closure(self, _mock_init):
        # All of .0-.3 deployed, remove back to .1: only .2 and .3 removed,
        # .0/.1 kept (target + its requires closure).
        collection, by_ver = self._build_chain([
            ("13.0.0", {c: states.DEPLOYED for c in self.COMPONENTS}),
            ("13.0.1", {c: states.DEPLOYED for c in self.COMPONENTS}),
            ("13.0.2", {c: states.DEPLOYED for c in self.COMPONENTS}),
            ("13.0.3", {c: states.DEPLOYED for c in self.COMPONENTS}),
        ])
        collection.highest_release = by_ver["13.0.3"]
        controller = self._controller()
        with unittest.mock.patch.object(
                type(controller), 'release_collection',
                new_callable=unittest.mock.PropertyMock,
                return_value=collection):
            removed = controller._get_metapackages_to_remove("starlingx-13.0.1")
        self.assertEqual(
            sorted(removed),
            sorted([f"{c}_13.0.2" for c in self.COMPONENTS]
                   + [f"{c}_13.0.3" for c in self.COMPONENTS]))

    @unittest.mock.patch('software.software_controller.PatchController.__init__',
                         return_value=None)
    def test_remove_skips_available_of_partial_release(self, _mock_init):
        # .2 is deployed-partial (infra available); removing back to .1 must
        # only remove .2's DEPLOYED metapackages, not the available infra.
        collection, by_ver = self._build_chain([
            ("13.0.0", {c: states.DEPLOYED for c in self.COMPONENTS}),
            ("13.0.1", {c: states.DEPLOYED for c in self.COMPONENTS}),
            ("13.0.2", {"distcloud": states.DEPLOYED,
                        "infra": states.AVAILABLE,
                        "k8s-common": states.DEPLOYED}),
        ])
        collection.highest_release = by_ver["13.0.2"]
        controller = self._controller()
        with unittest.mock.patch.object(
                type(controller), 'release_collection',
                new_callable=unittest.mock.PropertyMock,
                return_value=collection):
            removed = controller._get_metapackages_to_remove("starlingx-13.0.1")
        self.assertEqual(
            sorted(removed),
            ["distcloud_13.0.2", "k8s-common_13.0.2"])
        self.assertNotIn("infra_13.0.2", removed)

    # ---- _get_target_component_versions ---------------------------------

    @unittest.mock.patch('software.software_controller.PatchController.__init__',
                         return_value=None)
    def test_target_component_versions_highest_wins(self, _mock_init):
        # A component shipped by two lower releases (distcloud in .0 and .1)
        # must resolve to the highest of them (.1). The target (.2) ships only
        # infra, so distcloud comes solely from the deps -> the version sort is
        # what disambiguates.
        collection, by_ver = self._build_chain([
            ("13.0.0", {"distcloud": states.DEPLOYED}),
            ("13.0.1", {"distcloud": states.DEPLOYED}),
            ("13.0.2", {"infra": states.DEPLOYED}),
        ])
        # Present the deps in DESCENDING order: if the code did not sort by
        # version, a last-wins walk would pick distcloud .0 instead of .1.
        target = by_ver["13.0.2"]
        target.get_all_dependencies = lambda filter_states=None: [
            by_ver["13.0.1"], by_ver["13.0.0"]]
        controller = self._controller()
        with unittest.mock.patch.object(
                type(controller), 'release_collection',
                new_callable=unittest.mock.PropertyMock,
                return_value=collection):
            versions = controller._get_target_component_versions("starlingx-13.0.2")
        self.assertEqual(versions["distcloud"], "13.0.1")
        self.assertEqual(versions["infra"], "13.0.2")

    @unittest.mock.patch('software.software_controller.PatchController.__init__',
                         return_value=None)
    def test_target_component_versions_omits_orphan(self, _mock_init):
        # A component introduced only above the target is absent from the map.
        collection, _ = self._build_chain([
            ("13.0.0", {"base": states.DEPLOYED}),
            ("13.0.1", {"base": states.DEPLOYED}),
        ])
        controller = self._controller()
        with unittest.mock.patch.object(
                type(controller), 'release_collection',
                new_callable=unittest.mock.PropertyMock,
                return_value=collection):
            versions = controller._get_target_component_versions("starlingx-13.0.1")
        self.assertEqual(versions, {"base": "13.0.1"})

    # ---- _resolve_target_product_id -------------------------------------

    @unittest.mock.patch('software.software_controller.PatchController.__init__',
                         return_value=None)
    def test_resolve_target_product_id_highest(self, _mock_init):
        collection, _ = self._build_chain([
            ("13.0.1", {c: states.AVAILABLE for c in self.COMPONENTS}),
            ("13.0.2", {c: states.AVAILABLE for c in self.COMPONENTS}),
        ])
        controller = self._controller()
        with unittest.mock.patch.object(
                type(controller), 'release_collection',
                new_callable=unittest.mock.PropertyMock,
                return_value=collection):
            # Higher version listed FIRST: a naive "last id wins" would return
            # .1; the result must still be the highest (.2).
            target = controller._resolve_target_product_id(
                ["distcloud_13.0.2", "infra_13.0.1"])
        self.assertEqual(target, "starlingx-13.0.2")

    @unittest.mock.patch('software.software_controller.PatchController.__init__',
                         return_value=None)
    def test_resolve_target_product_id_empty(self, _mock_init):
        collection, _ = self._build_chain([
            ("13.0.1", {c: states.AVAILABLE for c in self.COMPONENTS}),
        ])
        controller = self._controller()
        with unittest.mock.patch.object(
                type(controller), 'release_collection',
                new_callable=unittest.mock.PropertyMock,
                return_value=collection):
            self.assertIsNone(controller._resolve_target_product_id([]))


class _FakeScriptRelease:
    """Minimal metapackage release stand-in for _build_metapackage_scripts:
    only sw_release, path_component and activation_scripts are used.
    """

    def __init__(self, sw_release, component, scripts):
        self.sw_release = sw_release
        self.path_component = component
        self.activation_scripts = scripts


class TestBuildMetapackageScripts(unittest.TestCase):
    """Tests for PatchController._build_metapackage_scripts, which builds the
    --metapackages payload passed to software-deploy-action.
    """

    def test_same_component_across_releases_not_overwritten(self):
        # A span where two releases both ship a 'base' metapackage: keying by
        # release then component must preserve both, not collide on 'base'.
        mp_releases = [
            _FakeScriptRelease("13.0.1", "base", ["b1.py"]),
            _FakeScriptRelease("13.0.2", "base", ["b2.py"]),
            _FakeScriptRelease("13.0.2", "infra", ["i2.py"]),
        ]
        result = PatchController._build_metapackage_scripts(mp_releases)  # pylint: disable=protected-access
        self.assertEqual(result, {
            "13.0.1": {"base": ["b1.py"]},
            "13.0.2": {"base": ["b2.py"], "infra": ["i2.py"]},
        })

    def test_ascending_order_when_forward(self):
        # Forward (activate/apply): releases ordered low to high
        mp_releases = [
            _FakeScriptRelease("13.0.3", "k8s-common", []),
            _FakeScriptRelease("13.0.1", "base", []),
            _FakeScriptRelease("13.0.2", "infra", []),
        ]
        result = PatchController._build_metapackage_scripts(mp_releases)  # pylint: disable=protected-access
        self.assertEqual(list(result), ["13.0.1", "13.0.2", "13.0.3"])

    def test_descending_order_when_unwinding(self):
        # Reverse (activate-rollback/remove): releases ordered high to low
        mp_releases = [
            _FakeScriptRelease("13.0.1", "base", []),
            _FakeScriptRelease("13.0.3", "k8s-common", []),
            _FakeScriptRelease("13.0.2", "infra", []),
        ]
        result = PatchController._build_metapackage_scripts(  # pylint: disable=protected-access
            mp_releases, descending=True)
        self.assertEqual(list(result), ["13.0.3", "13.0.2", "13.0.1"])


class TestEnsureReleaseBranch(unittest.TestCase):
    """Tests for PatchController._ensure_release_branch, which recreates a
    release's ostree branch (and its <requires> chain) when it is missing.
    """

    def _make_controller(self):
        # release_collection is a read-only property returning
        # get_SWReleaseCollection(); patch that so it returns our fake
        with unittest.mock.patch.object(PatchController, "__init__", return_value=None):
            controller = PatchController()
        controller.pre_bootstrap = False
        controller.software_sync = unittest.mock.MagicMock()
        controller.remove_tags_from_metadata = unittest.mock.MagicMock()
        controller.update_ostree_commit_id = unittest.mock.MagicMock()
        controller._set_original_commit = unittest.mock.MagicMock()  # pylint: disable=protected-access
        return controller

    @staticmethod
    def _make_release(rel_id, sw_release, requires=None, kernel_patch=False, metapackages=None):
        release = unittest.mock.MagicMock()
        release.id = rel_id
        release.sw_release = sw_release
        release.requires_release_ids = requires or []
        release.kernel_patch = kernel_patch
        release.metapackages = metapackages or {}
        return release

    @unittest.mock.patch("software.software_controller.get_SWReleaseCollection")
    def test_noop_when_branch_exists(self, _mock_swrc):
        # If the branch is already present, nothing is rebuilt
        controller = self._make_controller()
        sim = unittest.mock.MagicMock()
        sim.branch_exists.return_value = True

        controller._ensure_release_branch("starlingx-13.0.1", sim)  # pylint: disable=protected-access

        sim.create_sw_release_branch.assert_not_called()
        sim.create_kernel_release_branch.assert_not_called()

    @unittest.mock.patch("software.software_controller.get_SWReleaseCollection")
    def test_missing_release_record_is_hard_error(self, mock_swrc):
        # A missing branch whose release record is also gone cannot be rebuilt
        controller = self._make_controller()
        mock_swrc.return_value.get_release_by_id.return_value = None
        sim = unittest.mock.MagicMock()
        sim.branch_exists.return_value = False

        with self.assertRaises(SoftwareServiceError):
            controller._ensure_release_branch("starlingx-13.0.1", sim)  # pylint: disable=protected-access

    @unittest.mock.patch("software.software_controller.get_SWReleaseCollection")
    @unittest.mock.patch("software.software_controller.reload_release_data")
    @unittest.mock.patch("software.software_controller.utils.get_highest_required_release")
    def test_recursive_chain_rebuild(self, mock_highest_req, _mock_reload, mock_swrc):
        # .2 branch is missing and requires .1, whose branch is ALSO missing:
        # the required .1 must be rebuilt first (bottom-up), then .2
        controller = self._make_controller()

        rel1 = self._make_release("starlingx-13.0.1", "13.0.1", requires=[])
        rel2 = self._make_release("starlingx-13.0.2", "13.0.2",
                                  requires=["starlingx-13.0.1"])
        releases = {"starlingx-13.0.1": rel1, "starlingx-13.0.2": rel2}

        swrc = mock_swrc.return_value
        swrc.get_release_by_id.side_effect = releases.get
        swrc.get_ordered_metapackages.return_value = []

        # .1 requires nothing -> base resolved from deployed commit
        mock_highest_req.side_effect = lambda reqs: (
            "starlingx-13.0.1" if reqs else None)

        sim = unittest.mock.MagicMock()
        # Both target branches are missing; the deployed base and the rebuilt
        # branches resolve after creation. branch_exists: False for the two
        # release branches so both get rebuilt.
        sim.branch_exists.return_value = False
        sim.get_deployed_commit.return_value = "deployed-commit"
        sim.get_release_by_commit.return_value = "starlingx-13.0.0"
        sim.get_branch_commit.return_value = "rebuilt-commit"

        controller._ensure_release_branch("starlingx-13.0.2", sim)  # pylint: disable=protected-access

        # Both branches rebuilt, required (.1) before target (.2)
        built = [c.args[1] for c in sim.create_sw_release_branch.call_args_list]
        self.assertEqual(built, ["starlingx-13.0.1", "starlingx-13.0.2"])

    @unittest.mock.patch("software.software_controller.get_SWReleaseCollection")
    @unittest.mock.patch("software.software_controller.os.path.isdir", return_value=False)
    @unittest.mock.patch("software.software_controller.utils.get_highest_required_release",
                         return_value=None)
    def test_kernel_patch_missing_extra_repo_is_hard_error(self, _mock_req, _mock_isdir, mock_swrc):
        # A kernel patch rebuild needs the shipped extra ostree repo; if it is
        # gone the rebuild is a hard error asking to re-upload
        controller = self._make_controller()
        release = self._make_release("starlingx-13.0.1", "13.0.1",
                                     kernel_patch=True)
        swrc = mock_swrc.return_value
        swrc.get_release_by_id.return_value = release
        swrc.get_ordered_metapackages.return_value = []

        sim = unittest.mock.MagicMock()
        sim.branch_exists.return_value = False
        sim.get_deployed_commit.return_value = "deployed-commit"
        sim.get_release_by_commit.return_value = "starlingx-13.0.0"

        with self.assertRaises(SoftwareServiceError):
            controller._ensure_release_branch("starlingx-13.0.1", sim)  # pylint: disable=protected-access
        sim.create_kernel_release_branch.assert_not_called()

    @unittest.mock.patch("software.software_controller.get_SWReleaseCollection")
    @unittest.mock.patch("software.software_controller.os.path.exists", return_value=True)
    @unittest.mock.patch("software.software_controller.reload_release_data")
    @unittest.mock.patch("software.software_controller.utils.get_highest_required_release",
                         return_value=None)
    def test_rebuild_wipes_contents_before_writing_commit1(self, _mock_req, _mock_reload,
                                                           _mock_exists, mock_swrc):
        # A regular rebuild must clear stale metadata contents (e.g. leftover
        # commitN) before writing a fresh commit1, and refresh original_commit
        controller = self._make_controller()

        mp = unittest.mock.MagicMock()
        mp.component = "base"
        mp.state = states.DEPLOYED
        mp.metadata_filename = "base_13.0.1-metadata.xml"

        release = self._make_release("starlingx-13.0.1", "13.0.1",
                                     metapackages={"base_13.0.1": {}})
        swrc = mock_swrc.return_value
        swrc.get_release_by_id.return_value = release
        swrc.get_ordered_metapackages.return_value = [mp]

        sim = unittest.mock.MagicMock()
        sim.branch_exists.return_value = False
        sim.get_deployed_commit.return_value = "deployed-commit"
        sim.get_release_by_commit.return_value = "starlingx-13.0.0"
        sim.get_branch_commit.return_value = "new-commit"

        controller._ensure_release_branch("starlingx-13.0.1", sim)  # pylint: disable=protected-access

        # Regular (non-kernel) build path used
        sim.create_sw_release_branch.assert_called_once()
        sim.create_kernel_release_branch.assert_not_called()
        # Stale contents wiped before a fresh commit1 is written
        controller.remove_tags_from_metadata.assert_called_once_with(mp, constants.CONTENTS_TAG)
        controller.update_ostree_commit_id.assert_called_once()
        # Product original_commit refreshed with the rebuilt commit
        controller._set_original_commit.assert_called_once_with(  # pylint: disable=protected-access
            "starlingx-13.0.1", "new-commit")


class TestValidateInformedReleasesPrecheck(unittest.TestCase):
    """Tests for PatchController._validate_informed_releases: a deployed-partial
    release must be a valid precheck target (it can be continued or removed),
    while the fully-deployed running release is still rejected.
    """

    def _make_controller(self, highest_release):
        controller = PatchController.__new__(PatchController)
        swrc = unittest.mock.MagicMock()
        swrc.highest_release = highest_release
        patcher = unittest.mock.patch(
            "software.software_controller.get_SWReleaseCollection", return_value=swrc)
        patcher.start()
        self.addCleanup(patcher.stop)
        return controller, swrc

    @staticmethod
    def _product(rel_id, state):
        p = unittest.mock.MagicMock()
        p.id = rel_id
        p.state = state
        p.is_metapackage_release = False
        p.is_product_release = True
        return p

    def test_deployed_partial_target_is_allowed(self):
        # Targeting a deployed-partial product release (e.g. VIM removing back
        # to it) must not be rejected as the current release
        target = self._product("starlingx-26.10.1", states.DEPLOYED_PARTIAL)
        target.metapackages = {"infra_26.10.1": {}}
        controller, swrc = self._make_controller(highest_release=target)
        mp = unittest.mock.MagicMock()
        swrc.get_release_by_id.side_effect = lambda rid: (
            target if rid == "starlingx-26.10.1" else mp)

        result = controller._validate_informed_releases(["starlingx-26.10.1"])  # pylint: disable=protected-access

        self.assertEqual(result, [mp])

    def test_fully_deployed_running_release_is_rejected(self):
        # The fully-deployed running release cannot be a precheck target
        target = self._product("starlingx-26.10.1", states.DEPLOYED)
        target.metapackages = {"infra_26.10.1": {}}
        controller, swrc = self._make_controller(highest_release=target)
        swrc.get_release_by_id.return_value = target

        with self.assertRaises(ReleasePrecheckInvalidRequest):
            controller._validate_informed_releases(["starlingx-26.10.1"])  # pylint: disable=protected-access


class TestRemoveCommitFromMetadata(unittest.TestCase):
    """Tests for PatchController.remove_commit_from_metadata, which removes a
    single commitN entry and renumbers the remaining commits so the positional
    commit1..commitN invariant is preserved.
    """

    def setUp(self):
        # remove_commit_from_metadata/append_commit_to_metadata only use
        # add_text_tag_to_xml on self; no heavy controller init needed
        self.controller = PatchController.__new__(PatchController)
        fd, self.md_file = tempfile.mkstemp(suffix="-metadata.xml")
        os.close(fd)
        root = ET.Element("patch")
        ET.SubElement(root, "id").text = "starlingx-13.0.1"
        ET.ElementTree(root).write(self.md_file)

    def tearDown(self):
        if os.path.exists(self.md_file):
            os.remove(self.md_file)

    def _commits(self):
        """Return the ordered list of commit values under contents/ostree, and
        the number_of_commits value (or None if contents is absent).
        """
        root = ET.parse(self.md_file).getroot()
        ostree = root.find("contents/ostree")
        if ostree is None:
            return None, None
        num = ostree.findtext("number_of_commits")
        commits = []
        i = 1
        while True:
            el = ostree.find("commit%s" % i)
            if el is None:
                break
            commits.append(el.findtext("commit"))
            i += 1
        return commits, num

    def test_remove_middle_commit_renumbers_remaining(self):
        # Three commits appended; removing the middle one must renumber the
        # third to commit2 so readers iterating commit1..commitN don't skip it
        self.controller.append_commit_to_metadata(self.md_file, "c1", base_commit_id="base")
        self.controller.append_commit_to_metadata(self.md_file, "c2")
        self.controller.append_commit_to_metadata(self.md_file, "c3")

        self.controller.remove_commit_from_metadata(self.md_file, "c2")

        commits, num = self._commits()
        self.assertEqual(commits, ["c1", "c3"])
        self.assertEqual(num, "2")

    def test_remove_last_remaining_commit_drops_contents(self):
        # Removing the only commit leaves no commits, so the whole contents
        # block is dropped (matches a release with no commits)
        self.controller.append_commit_to_metadata(self.md_file, "c1", base_commit_id="base")

        self.controller.remove_commit_from_metadata(self.md_file, "c1")

        root = ET.parse(self.md_file).getroot()
        self.assertIsNone(root.find("contents"))

    def test_remove_absent_commit_is_noop(self):
        # Removing a commit that is not present leaves the metadata untouched
        self.controller.append_commit_to_metadata(self.md_file, "c1", base_commit_id="base")
        self.controller.append_commit_to_metadata(self.md_file, "c2")

        self.controller.remove_commit_from_metadata(self.md_file, "does-not-exist")

        commits, num = self._commits()
        self.assertEqual(commits, ["c1", "c2"])
        self.assertEqual(num, "2")

    def test_repeated_append_remove_does_not_accumulate(self):
        # Simulates repeated prestage/restore cycles: each cycle appends a
        # commit then removes it; the metadata must not accumulate stale commits
        self.controller.append_commit_to_metadata(self.md_file, "base-commit", base_commit_id="base")
        for i in range(3):
            prestage_commit = "prestage-%d" % i
            self.controller.append_commit_to_metadata(self.md_file, prestage_commit)
            self.controller.remove_commit_from_metadata(self.md_file, prestage_commit)

        commits, num = self._commits()
        self.assertEqual(commits, ["base-commit"])
        self.assertEqual(num, "1")


class TestPrestageBranchReuse(unittest.TestCase):
    """Tests for the reuse-vs-rebuild decision in software_deploy_prestage_api:
    reuse the prestage branch only when it exists and its tip matches the
    commit recorded for the metapackage set, else rebuild (stripping stale).
    """

    def _make_controller(self):
        controller = PatchController.__new__(PatchController)
        controller.pre_bootstrap = False
        controller.software_sync = unittest.mock.MagicMock()
        controller.append_commit_to_metadata = unittest.mock.MagicMock()
        controller.remove_commit_from_metadata = unittest.mock.MagicMock()
        return controller

    @staticmethod
    def _fake_mp():
        mp = unittest.mock.MagicMock()
        mp.id = "infra_26.10.3"
        mp.component = "infra"
        mp.metadata_filename = "infra_26.10.3-metadata.xml"
        return mp

    def _run(self, controller, sim, branch_commit, expected_commit):
        """Drive the metapackage-overrides prestage path with the reuse check
        resolved by (branch_commit, expected_commit).
        """
        mp = self._fake_mp()
        running_release = unittest.mock.MagicMock()
        running_release.sw_version = "26.10"
        target_release = "starlingx-26.10.3"

        deploy_set = unittest.mock.MagicMock()
        deploy_set.metapackages = [mp]
        deploy_set.sw_version = "26.10"
        deploy_set.sw_release = "26.10.3"

        swrc = unittest.mock.MagicMock()
        swrc.find_commit_for_metapackages.return_value = expected_commit

        sim.branch_exists.return_value = branch_commit is not None
        sim.get_branch_commit.return_value = branch_commit or "new-commit"
        sim.get_branch_original_commit.return_value = "base-commit"

        patches = [
            unittest.mock.patch.object(
                PatchController, "_validate_parameters_for_prestage",
                return_value=(running_release, [mp], target_release)),
            unittest.mock.patch(
                "software.software_controller.get_SWReleaseCollection", return_value=swrc),
            unittest.mock.patch(
                "software.software_controller.SoftwareInventoryManager", return_value=sim),
            unittest.mock.patch(
                "software.software_controller.MetapackageDeploymentSet", return_value=deploy_set),
            unittest.mock.patch("software.software_controller.apt_utils"),
            unittest.mock.patch("software.software_controller.ostree_utils"),
            unittest.mock.patch("software.software_controller.reload_release_data"),
            unittest.mock.patch("software.software_controller.audit_log_info"),
        ]
        for p in patches:
            p.start()
        self.addCleanup(unittest.mock.patch.stopall)

        return controller.software_deploy_prestage_api(
            release=target_release, metapackage_overrides=["infra_26.10.3"])

    def test_reuse_when_commit_matches(self):
        # Branch exists and its tip equals the recorded commit -> reuse, no
        # branch creation and no reinstall
        controller = self._make_controller()
        sim = unittest.mock.MagicMock()
        self._run(controller, sim, branch_commit="c1", expected_commit="c1")

        sim.create_branch.assert_not_called()
        sim.delete_ref.assert_not_called()
        controller.append_commit_to_metadata.assert_not_called()

    def test_rebuild_when_commit_mismatches(self):
        # Branch exists but tip differs from the recorded commit -> delete,
        # rebuild, strip the stale commit and append the fresh one
        controller = self._make_controller()
        sim = unittest.mock.MagicMock()
        self._run(controller, sim, branch_commit="old", expected_commit="recorded")

        sim.delete_ref.assert_called_once()
        sim.create_branch.assert_called_once()
        controller.remove_commit_from_metadata.assert_called_once_with(
            unittest.mock.ANY, "recorded")
        controller.append_commit_to_metadata.assert_called_once()

    def test_create_when_branch_missing(self):
        # Branch does not exist -> create and install, nothing stale to strip
        controller = self._make_controller()
        sim = unittest.mock.MagicMock()
        self._run(controller, sim, branch_commit=None, expected_commit=None)

        sim.create_branch.assert_called_once()
        controller.remove_commit_from_metadata.assert_not_called()
        controller.append_commit_to_metadata.assert_called_once()
