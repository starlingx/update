#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#

# This import has to be first
import subprocess
from software.tests import base  # pylint: disable=unused-import # noqa: F401
from software.software_controller import PatchController
from software.software_controller import AgentNeighbour
from software.exceptions import HostIpNotFound
from software.exceptions import HostNotFound
from software.exceptions import UpgradeNotSupported
import unittest
from unittest.mock import MagicMock
from unittest.mock import mock_open
from unittest.mock import PropertyMock
from unittest.mock import patch
from unittest.mock import call
from software import constants
from software import states
from socket import gaierror


class TestSoftwareController(unittest.TestCase):

    def setUp(self):
        self.upgrade_files = {
            constants.ISO_EXTENSION: "test.iso",
            constants.SIG_EXTENSION: "test.sig"
        }

    def tearDown(self):
        pass

    @patch('software.software_controller.PatchController.__init__', return_value=None)
    @patch('software.software_controller.PatchController.major_release_upload_check')
    @patch('software.software_controller.SW_VERSION', '1.0.0')
    @patch('software.software_controller.PatchController._run_load_import')
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
        result = controller._process_upload_upgrade_files(  # pylint: disable=protected-access
            from_release, to_release, iso_mount_dir, supported_from_releases, upgrade_files)

        self.assertEqual(result, "Load import successful")

    @patch('software.software_controller.PatchController.__init__', return_value=None)
    @patch('software.software_controller.PatchController.major_release_upload_check')
    @patch('software.software_controller.SW_VERSION', '1.0.0')
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
                from_release, to_release, iso_mount_dir, supported_from_releases, upgrade_files)
        except UpgradeNotSupported as e:
            self.assertEqual(e.message, 'Current release 1.0.0 not supported to upgrade to 2.0.0')

    @patch('software.software_controller.PatchController.__init__', return_value=None)
    @patch('software.software_controller.PatchController.major_release_upload_check')
    @patch('software.software_controller.read_upgrade_support_versions')
    @patch('software.software_controller.SW_VERSION', '4.0.0')
    @patch('software.software_controller.PatchController._run_load_import')
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

    @patch('software.software_controller.PatchController.__init__', return_value=None)
    @patch('software.software_controller.PatchController.major_release_upload_check')
    @patch('software.software_controller.read_upgrade_support_versions')
    @patch('software.software_controller.SW_VERSION', '4.0.0')
    @patch('software.software_controller.PatchController._run_load_import')
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

    @patch('software.software_controller.PatchController.__init__', return_value=None)
    @patch('os.path.isfile', return_value=False)
    @patch('os.path.join', return_value="/usr/sbin/software-deploy/major-release-upload")
    @patch('software.software_controller.reload_release_data')
    @patch('shutil.copyfile')
    @patch('subprocess.run')
    @patch('os.path.exists')
    def test_run_load_import_success_without_usm_script(self,
                                                        mock_path_exists,
                                                        mock_subprocess_run,
                                                        mock_copyfile,     # pylint: disable=unused-argument
                                                        mock_reload_release_data,      # pylint: disable=unused-argument
                                                        mock_join,    # pylint: disable=unused-argument
                                                        mock_isfile,   # pylint: disable=unused-argument
                                                        mock_init):    # pylint: disable=unused-argument
        # Setup
        mock_path_exists.return_value = True
        mock_subprocess_run.return_value = MagicMock(returncode=0, stdout="Load import successful")

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

    @patch('software.software_controller.PatchController.__init__', return_value=None)
    @patch('os.path.isfile', return_value=True)
    @patch('software.software_controller.PatchController.get_release_meta_info')
    @patch('software.software_controller.reload_release_data')
    @patch('shutil.copyfile')
    @patch('subprocess.run')
    @patch('shutil.copytree')
    @patch('shutil.rmtree')
    @patch('os.path.exists')
    def test_run_load_import_success_with_usm_script(self,
                                                     mock_path_exists,
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
        mock_subprocess_run.return_value = MagicMock(returncode=0, stdout="Load import successful")
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
            "/mnt/iso/upgrades/software-deploy", "/opt/software/rel-2.0.0/bin")

    @patch('software.software_controller.PatchController.__init__', return_value=None)
    @patch('os.path.isfile', return_value=True)
    @patch('software.software_controller.PatchController.get_release_meta_info')
    @patch('software.software_controller.reload_release_data')
    @patch('shutil.copyfile')
    @patch('subprocess.run')
    @patch('shutil.copytree')
    @patch('shutil.rmtree')
    @patch('os.path.exists')
    def test_run_load_import_script_with_usm_script_failure(self,
                                                            mock_path_exists,
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
        mock_subprocess_run.return_value = MagicMock(returncode=1, stdout="Load import failed")
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
            "/mnt/iso/upgrades/software-deploy", "/opt/software/rel-2.0.0/bin")

    @patch('software.software_controller.PatchController.__init__', return_value=None)
    @patch('os.path.isfile', return_value=True)
    @patch('software.software_controller.PatchController.get_release_meta_info')
    @patch('software.software_controller.reload_release_data')
    @patch('shutil.copyfile')
    @patch('subprocess.run')
    @patch('shutil.copytree')
    @patch('shutil.rmtree')
    @patch('os.path.exists')
    def test_run_load_import_script_with_usm_script_exception(self,
                                                              mock_path_exists,
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
            "/mnt/iso/upgrades/software-deploy", "/opt/software/rel-2.0.0/bin")

    @patch('software.software_controller.json.load')
    @patch('software.software_controller.open', new_callable=mock_open)
    @patch('software.software_controller.utils.get_platform_conf', return_value='simplex')
    @patch('software.software_controller.open', new_callable=mock_open)
    def test_get_software_host_upgrade_deployed(self,
                                                mock_dummy_open_config,  # pylint: disable=unused-argument
                                                mock_dummy,  # pylint: disable=unused-argument
                                                mock_dummy_open,  # pylint: disable=unused-argument
                                                mock_json_load,  # pylint: disable=unused-argument
                                                ):
        controller = PatchController()
        controller._get_software_upgrade = MagicMock(return_value={  # pylint: disable=protected-access
            "from_release": "1.0.0",
            "to_release": "2.0.0"
        })
        controller.db_api_instance.get_deploy_host = MagicMock(return_value=[
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

    @patch('software.software_controller.json.load')
    @patch('software.software_controller.open', new_callable=mock_open)
    @patch('software.software_controller.utils.get_platform_conf', return_value='simplex')
    @patch('software.software_controller.open', new_callable=mock_open)
    def test_get_software_host_upgrade_deploying(self,
                                                 mock_dummy_open_config,  # pylint: disable=unused-argument
                                                 mock_dummy,  # pylint: disable=unused-argument
                                                 mock_dummy_open,  # pylint: disable=unused-argument
                                                 mock_json_load,  # pylint: disable=unused-argument
                                                 ):
        controller = PatchController()
        controller._get_software_upgrade = MagicMock(return_value={  # pylint: disable=protected-access
            "from_release": "1.0.0",
            "to_release": "2.0.0"
        })
        controller.db_api_instance.get_deploy_host = MagicMock(return_value=[
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

    @patch('software.software_controller.json.load')
    @patch('software.software_controller.open', new_callable=mock_open)
    @patch('software.software_controller.utils.get_platform_conf', return_value='simplex')
    @patch('software.software_controller.open', new_callable=mock_open)
    def test_get_all_software_host_upgrade_deploying(self,
                                                     mock_dummy_open_config,  # pylint: disable=unused-argument
                                                     mock_dummy,  # pylint: disable=unused-argument
                                                     mock_dummy_open,  # pylint: disable=unused-argument
                                                     mock_json_load,  # pylint: disable=unused-argument
                                                     ):
        controller = PatchController()
        controller._get_software_upgrade = MagicMock(return_value={  # pylint: disable=protected-access
            "from_release": "1.0.0",
            "to_release": "2.0.0"
        })
        controller.db_api_instance.get_deploy_host = MagicMock(return_value=[
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

    @patch('software.software_controller.json.load')
    @patch('software.software_controller.open', new_callable=mock_open)
    @patch('software.software_controller.utils.get_platform_conf', return_value='simplex')
    @patch('software.software_controller.open', new_callable=mock_open)
    def test_get_software_host_upgrade_none_state(self,
                                                  mock_dummy_open_config,  # pylint: disable=unused-argument
                                                  mock_dummy,  # pylint: disable=unused-argument
                                                  mock_dummy_open,  # pylint: disable=unused-argument
                                                  mock_json_load,  # pylint: disable=unused-argument
                                                  ):
        controller = PatchController()

        # Test when the deploy or deploy_hosts is None
        controller._get_software_upgrade = MagicMock(  # pylint: disable=protected-access
            return_value=None)
        controller.db_api_instance.get_deploy_host.return_value = None
        result = controller.get_one_software_host_upgrade("host1")
        self.assertIsNone(result)

    @patch('software.software_controller.json.load')
    @patch('software.software_controller.open', new_callable=mock_open)
    @patch('software.software_controller.utils.get_platform_conf', return_value='simplex')
    @patch('software.software_controller.open', new_callable=mock_open)
    def test_get_software_upgrade_get_deploy_all(self,
                                                 mock_dummy_open_config,  # pylint: disable=unused-argument
                                                 mock_dummy,  # pylint: disable=unused-argument
                                                 mock_dummy_open,  # pylint: disable=unused-argument
                                                 mock_json_load,  # pylint: disable=unused-argument
                                                 ):

        controller = PatchController()

        # Create a mock instance of the db_api
        db_api_instance_mock = MagicMock()
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
            "state": "start"
        }
        self.assertEqual(result, expected_result)

    @patch('software.software_controller.json.load')
    @patch('software.software_controller.open', new_callable=mock_open)
    @patch('software.software_controller.utils.get_platform_conf', return_value='simplex')
    @patch('software.software_controller.open', new_callable=mock_open)
    def test_get_software_upgrade_get_deploy_all_none(self,
                                                      mock_dummy_open_config,  # pylint: disable=unused-argument
                                                      mock_dummy,  # pylint: disable=unused-argument
                                                      mock_dummy_open,  # pylint: disable=unused-argument
                                                      mock_json_load,  # pylint: disable=unused-argument
                                                      ):

        controller = PatchController()

        # Create a mock instance of the db_api
        db_api_instance_mock = MagicMock()
        controller.db_api_instance = db_api_instance_mock

        # Create a mock return value for the get_deploy_all method
        db_api_instance_mock.get_deploy_all.return_value = None

        # Call the method being tested
        result = controller._get_software_upgrade()  # pylint: disable=protected-access

        # Verify that the expected methods were called
        db_api_instance_mock.get_deploy_all.assert_called_once()

        self.assertIsNone(result)

    @patch('software.software_controller.PatchController.__init__', return_value=None)
    @patch('software.software_controller.utils.gethostbyname', side_effect=gaierror)
    def test_deploy_host_hostname_not_found(self,
                                            mock_gethostbyname,     # pylint: disable=unused-argument
                                            mock_init):  # pylint: disable=unused-argument
        controller = PatchController()
        hostname = "nonexistent_host"
        force = False
        async_req = False
        rollback = False

        result = controller._deploy_host(hostname, force, async_req, rollback)  # pylint: disable=protected-access

        self.assertIn("Host %s not found" % hostname, result['error'])
        self.assertEqual(result['info'], "")
        self.assertEqual(result['warning'], "")

    @patch('software.software_controller.PatchController.__init__', return_value=None)
    @patch('software.software_controller.utils.gethostbyname', return_value='192.168.1.1')
    def test_deploy_host_raises_HostIpNotFound(self,
                                               mock_gethostbyname,  # pylint: disable=unused-argument
                                               mock_init):  # pylint: disable=unused-argument
        controller = PatchController()
        controller.hosts = {}

        with self.assertRaises(HostIpNotFound):
            controller._deploy_host('test-hostname', force=True)    # pylint: disable=protected-access

    @patch('software.software_controller.PatchController.__init__', return_value=None)
    @patch('software.software_controller.utils.gethostbyname', return_value='192.168.1.1')
    @patch('software.software_controller.AgentNeighbour.is_alive', new_callable=PropertyMock)
    def test_deploy_host_raises_host_not_found(self,
                                               mock_is_alive,
                                               mock_gethostbyname,  # pylint: disable=unused-argument
                                               mock_init):  # pylint: disable=unused-argument

        mock_is_alive.return_value = True

        controller = PatchController()
        agent_neighbor = AgentNeighbour('192.168.1.1')
        controller.db_api_instance = MagicMock()
        controller.socket_lock = MagicMock()
        controller.sock_out = MagicMock()
        controller.db_api_instance.get_deploy_host_by_hostname.return_value = None
        controller.hosts = {'192.168.1.1': agent_neighbor}

        with self.assertRaises(HostNotFound):
            controller._deploy_host('test-host', force=True)    # pylint: disable=protected-access

    @patch('software.software_controller.PatchController.__init__', return_value=None)
    @patch('software.software_controller.utils.gethostbyname', return_value='192.168.1.1')
    @patch('software.software_controller.DeployState.get_instance')
    @patch('software.software_controller.DeployHostState')
    @patch('software.software_controller.set_host_target_load',
           side_effect=subprocess.CalledProcessError(returncode=1, cmd='ls'))
    @patch('software.software_controller.AgentNeighbour.is_alive', new_callable=PropertyMock)
    def test_deploy_host_set_host_target_load_exception(self,
                                                        mock_is_alive,
                                                        mock_set_host_target_load,  # pylint: disable=unused-argument
                                                        mock_deploy_host_state,
                                                        mock_deploy_state,
                                                        mock_gethostbyname,     # pylint: disable=unused-argument
                                                        mock_patch_controller_init):    # pylint: disable=unused-argument
        mock_is_alive.return_value = True
        mock_deploy_state_instance = MagicMock()
        mock_deploy_state.return_value = mock_deploy_state_instance
        mock_deploy_host_state_instance = MagicMock()
        mock_deploy_host_state.return_value = mock_deploy_host_state_instance

        controller = PatchController()
        agent_neighbor = AgentNeighbour('192.168.1.1')
        controller.hosts = {'192.168.1.1': agent_neighbor}
        controller.hosts_lock = MagicMock()
        controller.socket_lock = MagicMock()
        controller.sock_out = MagicMock()
        controller.db_api_instance = MagicMock()
        controller.db_api_instance.get_deploy_host_by_hostname.return_value = MagicMock()
        controller.db_api_instance.get_deploy_all.return_value = [
            {'to_release': '2.1.1', 'commit_id': 'commit_1'}]
        controller.allow_insvc_patching = False
        controller.install_local = True
        controller.check_upgrade_in_progress = MagicMock(return_value=True)
        controller.get_software_upgrade = MagicMock(return_value={'to_release': '2.1.1'})
        controller.manage_software_alarm = MagicMock()

        with self.assertRaises(subprocess.CalledProcessError):
            controller._deploy_host('hostname', force=False, async_req=False)    # pylint: disable=protected-access
            assert mock_deploy_host_state.assert_called_once()

    @patch('software.software_controller.PatchController.__init__', return_value=None)
    @patch('software.software_controller.utils.gethostbyname', return_value='192.168.1.1')
    @patch('software.software_controller.DeployState.get_instance')
    @patch('software.software_controller.DeployHostState')
    @patch('software.software_controller.set_host_target_load')
    @patch('software.software_controller.copy_pxeboot_update_file', side_effect=FileNotFoundError)
    @patch('software.software_controller.AgentNeighbour.is_alive', new_callable=PropertyMock)
    def test_copy_pxeboot_update_file_exception(self,
                                                mock_is_alive,
                                                mock_copy_pxeboot_update_file,  # pylint: disable=unused-argument
                                                mock_set_host_target_load,  # pylint: disable=unused-argument
                                                mock_deploy_host_state,
                                                mock_deploy_state,
                                                mock_gethostbyname,     # pylint: disable=unused-argument
                                                mock_patch_controller_init):    # pylint: disable=unused-argument
        mock_is_alive.return_value = True
        mock_deploy_state_instance = MagicMock()
        mock_deploy_state.return_value = mock_deploy_state_instance
        mock_deploy_host_state_instance = MagicMock()
        mock_deploy_host_state.return_value = mock_deploy_host_state_instance

        controller = PatchController()
        agent_neighbor = AgentNeighbour('192.168.1.1')
        controller.hosts = {'192.168.1.1': agent_neighbor}
        controller.hosts_lock = MagicMock()
        controller.socket_lock = MagicMock()
        controller.sock_out = MagicMock()
        controller.db_api_instance = MagicMock()
        controller.db_api_instance.get_deploy_host_by_hostname.return_value = MagicMock()
        controller.db_api_instance.get_deploy_all.return_value = [
            {'to_release': '2.1.1', 'commit_id': 'commit_1'}]
        controller.allow_insvc_patching = False
        controller.install_local = True
        controller.check_upgrade_in_progress = MagicMock(return_value=True)
        controller.get_software_upgrade = MagicMock(return_value={'to_release': '2.1.1'})
        controller.manage_software_alarm = MagicMock()

        with self.assertRaises(FileNotFoundError):
            controller._deploy_host('hostname', force=False, async_req=False)    # pylint: disable=protected-access
            assert mock_deploy_host_state.assert_called_once()

    @patch('software.software_controller.PatchController.__init__', return_value=None)
    @patch('os.path.exists')
    @patch('shutil.rmtree')
    @patch('os.remove')
    @patch('software.utils.find_file_by_regex')
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
            call('/opt/software/metadata/unavailable/component-22.12-metadata.xml'),
            call('/opt/software/metadata/committed/component_22.12_PATCH_001-metadata.xml'),
            call('/opt/software/metadata/committed/component_22.12_PATCH_002-metadata.xml')
        ]
        mock_remove.assert_has_calls(expected_remove_calls)
