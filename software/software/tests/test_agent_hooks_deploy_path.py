#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import subprocess
import unittest
from unittest import mock

from software.tests import base as test_base  # noqa: F401
from software.agent_hooks import BaseHook
from software.agent_hooks import CopyPxeFilesHook
from software.agent_hooks import KubeletUpgradeHook
from software.agent_hooks import DeleteControllerFeedRemoteHook
from software.agent_hooks import EnableNewServicesHook
from software.agent_hooks import EtcMerger
from software.agent_hooks import FixedEtcMergeHook
from software.agent_hooks import FixedEtcMergeRollBackHook
from software.agent_hooks import HookManager
from software.agent_hooks import ReconfigureKernelHook
from software.agent_hooks import UpdateKernelParametersHook
from software.agent_hooks import UsmInitHook

mock.patch('logging.basicConfig').start()

ATTRS = {
    "major_release": "10.0",
    "from_release": "9.0",
    "to_release": "10.0",
    "hook_action": "major_release_upgrade",
    "additional_data": {
        "to_commit_id": "abc123",
        "from_commit_id": "def456",
    },
}


class TestBaseHookGetPlatformConf(unittest.TestCase):

    @mock.patch("builtins.open", mock.mock_open(
        read_data="sw_version=10.0\nnodetype=controller\n"))
    def test_get_platform_conf(self):
        result = BaseHook.get_platform_conf("nodetype")
        self.assertEqual(result, "controller")

    @mock.patch("builtins.open", side_effect=FileNotFoundError)
    def test_get_platform_conf_file_missing(self, _mock_open):
        self.assertRaises(FileNotFoundError,
                          BaseHook.get_platform_conf, "nodetype")


class TestBaseHookGetNewDeployPath(unittest.TestCase):

    def test_get_new_deploy_path(self):
        result = BaseHook.get_new_deploy_path("/etc/foo")
        self.assertEqual(result, "/ostree/1/etc/foo")

    def test_get_new_deploy_path_no_leading_slash(self):
        result = BaseHook.get_new_deploy_path("etc/foo")
        self.assertEqual(result, "/ostree/1/etc/foo")


class TestUsmInitHook(unittest.TestCase):

    def setUp(self):
        self.hook = UsmInitHook(ATTRS)

    @mock.patch.object(UsmInitHook, "enable_service")
    @mock.patch.object(UsmInitHook, "get_platform_conf",
                       return_value="controller")
    def test_run_controller(self, _conf, mock_enable):
        self.hook.run()
        calls = [c[0][0] for c in mock_enable.call_args_list]
        self.assertIn("usm-initialize.service", calls)
        self.assertIn("software-controller.service", calls)


class TestEtcMerger(unittest.TestCase):

    def setUp(self):
        self.hook = EtcMerger(ATTRS)

    def test_init_attrs(self):
        self.assertEqual(self.hook._to_release, "10.0")

    @mock.patch("shutil.copyfile", side_effect=PermissionError("denied"))
    @mock.patch("os.walk", return_value=[
        ("/ostree/1/usr/share/starlingx/usm/etc", [], ["bad.conf"]),
    ])
    def test_copy_files_other_exception(self, _walk, _copy):
        self.assertRaises(PermissionError, self.hook.copy_files)


class TestEnableNewServicesHook(unittest.TestCase):

    def setUp(self):
        self.hook = EnableNewServicesHook(ATTRS)

    @mock.patch("builtins.open")
    @mock.patch("os.readlink", return_value="/etc/preset.conf")
    @mock.patch("os.listdir", return_value=["10-stx.preset"])
    def test_find_new_services(self, _listdir, _readlink, mock_open):
        from_data = "enable svcA.service\nenable svcB.service\n"
        to_data = (
            "enable svcA.service\n"
            "enable svcB.service\n"
            "enable svcC.service\n")
        mock_open.side_effect = [
            mock.mock_open(read_data=from_data).return_value,
            mock.mock_open(read_data=to_data).return_value,
        ]
        result = self.hook.find_new_services()
        self.assertEqual(result, ["svcC.service"])

    @mock.patch("os.listdir", return_value=["99-other.preset"])
    def test_find_new_services_no_preset(self, _listdir):
        self.assertRaises(FileNotFoundError, self.hook.find_new_services)

    @mock.patch.object(EnableNewServicesHook, "enable_service")
    def test_enable_new_services(self, mock_enable):
        self.hook.enable_new_services(["a.service", "b.service"])
        self.assertEqual(mock_enable.call_count, 2)


class TestCopyPxeFilesHook(unittest.TestCase):

    def setUp(self):
        self.hook = CopyPxeFilesHook(ATTRS)

    @mock.patch("subprocess.run")
    @mock.patch.object(CopyPxeFilesHook, "get_platform_conf",
                       return_value="controller")
    def test_run_controller_success(self, _conf, mock_run):
        self.hook.run()
        self.assertEqual(mock_run.call_count, 2)

    @mock.patch("subprocess.run",
                side_effect=subprocess.CalledProcessError(
                    1, "rsync", stderr=b"fail"))
    @mock.patch.object(CopyPxeFilesHook, "get_platform_conf",
                       return_value="controller")
    def test_run_controller_rsync_error(self, _conf, _run):
        self.assertRaises(subprocess.CalledProcessError, self.hook.run)


class TestUpdateKernelParametersHook(unittest.TestCase):

    def setUp(self):
        self.hook = UpdateKernelParametersHook(ATTRS)

    @mock.patch("subprocess.check_output",
                return_value=b"kernel_params=isolcpus=1-3 quiet\n")
    def test_read_kernel_parameters(self, _check):
        result = self.hook.read_kernel_parameters()
        self.assertEqual(result, "isolcpus=1-3 quiet")

    @mock.patch("subprocess.check_output",
                return_value=b"other_var=foo\n")
    def test_read_kernel_parameters_no_match(self, _check):
        result = self.hook.read_kernel_parameters()
        self.assertEqual(result, "")

    @mock.patch("subprocess.check_output",
                side_effect=RuntimeError("cmd fail"))
    def test_read_kernel_parameters_error(self, _check):
        self.assertRaises(RuntimeError, self.hook.read_kernel_parameters)

    def test_read_isolcpus_found(self):
        result = self.hook.read_isolcpus("isolcpus=1-3 quiet")
        self.assertEqual(result, "isolcpus=1-3")

    def test_read_isolcpus_not_found(self):
        result = self.hook.read_isolcpus("quiet splash")
        self.assertEqual(result, "")

    @mock.patch("subprocess.run")
    def test_update_isolcpus_with_ranges(self, mock_run):
        self.hook.update_isolcpus("isolcpus=1-3")
        self.assertEqual(mock_run.call_count, 2)

    def test_read_kthread_prio_found(self):
        result = self.hook.read_kthread_prio(
            "quiet rcutree.kthread_prio=21")
        self.assertEqual(result, "rcutree.kthread_prio=21")

    def test_read_kthread_prio_not_found(self):
        result = self.hook.read_kthread_prio("quiet splash")
        self.assertEqual(result, "")

    def test_read_intel_idle_found(self):
        result = self.hook.read_intel_idle(
            "quiet intel_idle.max_cstate=0")
        self.assertEqual(result, "intel_idle.max_cstate=0")

    def test_read_intel_idle_not_found(self):
        result = self.hook.read_intel_idle("quiet")
        self.assertEqual(result, "")

    @mock.patch("subprocess.run",
                side_effect=subprocess.CalledProcessError(
                    1, "cmd", stderr=b"err"))
    def test_remove_intel_idle_subprocess_error(self, _run):
        self.assertRaises(subprocess.CalledProcessError,
                          self.hook.remove_intel_idle_if_set,
                          "intel_idle.max_cstate=0")

    @mock.patch.object(UpdateKernelParametersHook, "get_platform_conf",
                       return_value="controller,worker")
    def test_check_subfunction_worker_true(self, _conf):
        self.assertTrue(self.hook.check_subfunction_worker())

    @mock.patch.object(UpdateKernelParametersHook, "get_platform_conf",
                       return_value="controller")
    def test_check_subfunction_worker_false(self, _conf):
        self.assertFalse(self.hook.check_subfunction_worker())


class TestKernelParamsBackupRestore(unittest.TestCase):

    def setUp(self):
        self.hook = UpdateKernelParametersHook(ATTRS)

    @mock.patch("builtins.open",
                mock.mock_open(read_data="params"))
    @mock.patch("subprocess.run",
                side_effect=subprocess.CalledProcessError(
                    1, "cmd", stderr="err"))
    def test_restore_kernel_params_subprocess_error(self, _run):
        self.assertRaises(subprocess.CalledProcessError,
                          self.hook.restore_kernel_params)


class TestMountUnmountPlatformDir(unittest.TestCase):

    def setUp(self):
        self.hook = UpdateKernelParametersHook(ATTRS)

    @mock.patch("subprocess.run",
                side_effect=subprocess.CalledProcessError(
                    1, "cmd", stderr=b"err"))
    @mock.patch("os.makedirs")
    def test_mount_platform_dir_error(self, _mkdirs, _run):
        self.assertRaises(subprocess.CalledProcessError,
                          self.hook.mount_platform_dir)

    @mock.patch("subprocess.run",
                side_effect=subprocess.CalledProcessError(
                    1, "cmd", stderr=b"err"))
    def test_umount_platform_dir_error(self, _run):
        self.assertRaises(subprocess.CalledProcessError,
                          self.hook.umount_platform_dir)


class TestGetHieradataFile(unittest.TestCase):

    def setUp(self):
        self.hook = UpdateKernelParametersHook(ATTRS)

    @mock.patch("builtins.open",
                mock.mock_open(read_data="myhost\n"))
    def test_get_hieradata_file(self):
        result = self.hook.get_hieradata_file()
        self.assertIn("myhost.yaml", result)

    @mock.patch("builtins.open", side_effect=FileNotFoundError)
    def test_get_hieradata_file_missing(self, _open):
        self.assertRaises(FileNotFoundError,
                          self.hook.get_hieradata_file)


class TestCheckBiosCstate(unittest.TestCase):

    def setUp(self):
        self.hook = UpdateKernelParametersHook(ATTRS)

    @mock.patch.object(UpdateKernelParametersHook,
                       "get_hieradata_file",
                       return_value="/opt/platform/puppet"
                       "/10.0/hieradata/h.yaml")
    @mock.patch("os.path.exists", return_value=True)
    @mock.patch("subprocess.check_output",
                return_value=b"platform::bios_cstate: true\n")
    def test_check_bios_cstate_true(self, _check, _exists, _hiera):
        self.assertTrue(self.hook.check_bios_cstate())

    @mock.patch.object(UpdateKernelParametersHook,
                       "get_hieradata_file",
                       return_value="/opt/platform/puppet"
                       "/10.0/hieradata/h.yaml")
    @mock.patch("os.path.exists", return_value=True)
    @mock.patch("subprocess.check_output",
                side_effect=subprocess.CalledProcessError(1, "grep"))
    def test_check_bios_cstate_not_found(self, _check, _exists, _hiera):
        self.assertFalse(self.hook.check_bios_cstate())


class TestCheckPowerManagement(unittest.TestCase):

    def setUp(self):
        self.hook = UpdateKernelParametersHook(ATTRS)

    @mock.patch.object(UpdateKernelParametersHook,
                       "get_hieradata_file",
                       return_value="/opt/platform/puppet"
                       "/10.0/hieradata/h.yaml")
    @mock.patch("os.path.exists", return_value=True)
    @mock.patch("subprocess.check_output",
                return_value=b"power-management: enabled\n")
    def test_check_power_management_enabled(self, _check, _exists, _hiera):
        self.assertTrue(self.hook.check_power_management())

    @mock.patch.object(UpdateKernelParametersHook,
                       "get_hieradata_file",
                       return_value="/opt/platform/puppet"
                       "/10.0/hieradata/h.yaml")
    @mock.patch("os.path.exists", return_value=True)
    @mock.patch("subprocess.check_output",
                side_effect=subprocess.CalledProcessError(1, "grep"))
    def test_check_power_management_not_found(self, _check, _exists, _hiera):
        self.assertFalse(self.hook.check_power_management())


class TestReconfigureKernelHook(unittest.TestCase):

    def setUp(self):
        self.hook = ReconfigureKernelHook(ATTRS)

    @mock.patch("subprocess.run",
                side_effect=subprocess.CalledProcessError(
                    1, "cmd", stderr=b"err"))
    @mock.patch("glob.glob", return_value=["/boot/1/vmlinuz-5.10-amd64"])
    @mock.patch("filecmp.cmp", return_value=True)
    @mock.patch.object(ReconfigureKernelHook, "get_platform_conf",
                       return_value="controller")
    def test_run_subprocess_error(self, _conf, _cmp, _glob, _run):
        self.assertRaises(subprocess.CalledProcessError, self.hook.run)


class TestKubeletUpgradeHook(unittest.TestCase):

    @mock.patch("builtins.open", side_effect=OSError("fail"))
    def test_run_write_error(self, _open):
        attrs = dict(ATTRS)
        attrs["additional_data"]["to_kubelet_version"] = "1.29.0"
        hook = KubeletUpgradeHook(attrs)
        self.assertRaises(OSError, hook.run)


class TestDeleteControllerFeedRemoteHook(unittest.TestCase):

    @mock.patch("subprocess.run",
                side_effect=subprocess.CalledProcessError(
                    1, "ostree", output="err"))
    @mock.patch.object(DeleteControllerFeedRemoteHook,
                       "get_platform_conf", return_value="worker")
    def test_run_error(self, _conf, _run):
        hook = DeleteControllerFeedRemoteHook(ATTRS)
        self.assertRaises(subprocess.CalledProcessError, hook.run)


class TestFixedEtcMergeHook(unittest.TestCase):

    @mock.patch("os.remove")
    @mock.patch("os.path.exists", return_value=True)
    def test_run_deletes_files(self, _exists, mock_rm):
        hook = FixedEtcMergeHook(ATTRS)
        hook.run()
        self.assertEqual(
            mock_rm.call_count, len(
                FixedEtcMergeHook.DELETE_FILES))


class TestFixedEtcMergeRollBackHook(unittest.TestCase):

    @mock.patch("os.remove")
    @mock.patch("os.path.exists", return_value=True)
    def test_run(self, _exists, mock_rm):
        hook = FixedEtcMergeRollBackHook(ATTRS)
        hook.run()
        self.assertEqual(mock_rm.call_count,
                         len(FixedEtcMergeRollBackHook.DELETE_FILES))


class TestHookManager(unittest.TestCase):

    def test_init_upgrade(self):
        mgr = HookManager(HookManager.MAJOR_RELEASE_UPGRADE, attrs=ATTRS)
        self.assertEqual(mgr._action, HookManager.MAJOR_RELEASE_UPGRADE)
        self.assertIsNotNone(mgr._hooks)

    def test_init_rollback(self):
        mgr = HookManager(HookManager.MAJOR_RELEASE_ROLLBACK, attrs=ATTRS)
        self.assertIsNotNone(mgr._hooks)

    def test_init_unknown_action(self):
        mgr = HookManager("unknown")
        self.assertIsNone(mgr._hooks)

    @mock.patch.object(BaseHook, "get_platform_conf",
                       return_value="9.0")
    def test_create_hook_manager_upgrade(self, _conf):
        mgr = HookManager.create_hook_manager("10.0")
        self.assertEqual(mgr._action, HookManager.MAJOR_RELEASE_UPGRADE)

    @mock.patch.object(BaseHook, "get_platform_conf",
                       return_value="10.0")
    def test_create_hook_manager_rollback(self, _conf):
        mgr = HookManager.create_hook_manager("9.0")
        self.assertEqual(mgr._action, HookManager.MAJOR_RELEASE_ROLLBACK)

    @mock.patch.object(BaseHook, "get_platform_conf",
                       return_value="10.0")
    def test_create_hook_manager_with_additional_data(self, _conf):
        mgr = HookManager.create_hook_manager(
            "11.0", additional_data={"to_commit_id": "abc"})
        self.assertEqual(mgr._attrs["additional_data"]["to_commit_id"],
                         "abc")


class TestKubeletUpgradeHookRun(unittest.TestCase):
    """Tests for KubeletUpgradeHook.run() file writing logic."""

    def setUp(self):
        self.attrs = {
            "major_release": "FAKE_MAJOR_RELEASE",
            "from_release": "STX12",
            "to_release": "STX13",
            "hook_action": "FAKE_ACTION",
            "additional_data": {
                "from_commit_id": "FAKE_COMMIT_ID",
                "to_commit_id": "FAKE_COMMIT_ID"
            }
        }

    def test_writes_version_details_to_correct_path(self):
        """The version file is written under the to-release ostree dir."""
        self.attrs["additional_data"]["to_kubelet_version"] = "v1.34.1"
        hook = KubeletUpgradeHook(self.attrs)

        mocked_open = mock.mock_open()
        p = mock.patch('builtins.open', mocked_open)
        p.start()
        self.addCleanup(p.stop)

        hook.run()

        expected_path = "%s/%s" % (KubeletUpgradeHook.TO_RELEASE_OSTREE_DIR,
                                   KubeletUpgradeHook.KUBELET_VERSION_FILE)
        mocked_open.assert_called_once_with(expected_path, "w")

    def test_writes_expected_version_payload(self):
        """The JSON payload carries both releases and the kubelet version."""
        self.attrs["additional_data"]["to_kubelet_version"] = "v1.34.1"
        hook = KubeletUpgradeHook(self.attrs)

        mocked_open = mock.mock_open()
        p = mock.patch('builtins.open', mocked_open)
        p.start()
        self.addCleanup(p.stop)

        captured = {}

        def fake_dump(data, _file):
            captured.update(data)

        p = mock.patch('json.dump', fake_dump)
        p.start()
        self.addCleanup(p.stop)

        hook.run()

        self.assertEqual(captured["from_release"], "STX12")
        self.assertEqual(captured["to_release"], "STX13")
        self.assertEqual(captured["to_kubelet_version"], "v1.34.1")

    def test_absent_version_writes_nothing(self):
        """With no to_kubelet_version, run() returns without writing."""
        hook = KubeletUpgradeHook(self.attrs)

        mocked_open = mock.mock_open()
        p = mock.patch('builtins.open', mocked_open)
        p.start()
        self.addCleanup(p.stop)

        hook.run()

        self.assertEqual(mocked_open.call_count, 0)

    def test_empty_version_writes_nothing(self):
        """An empty to_kubelet_version is treated as absent."""
        self.attrs["additional_data"]["to_kubelet_version"] = ""
        hook = KubeletUpgradeHook(self.attrs)

        mocked_open = mock.mock_open()
        p = mock.patch('builtins.open', mocked_open)
        p.start()
        self.addCleanup(p.stop)

        hook.run()

        self.assertEqual(mocked_open.call_count, 0)

    def test_write_failure_propagates(self):
        """A failure while writing is re-raised to the caller."""
        self.attrs["additional_data"]["to_kubelet_version"] = "v1.34.1"
        hook = KubeletUpgradeHook(self.attrs)

        p = mock.patch('builtins.open',
                       side_effect=PermissionError("read-only fs"))
        p.start()
        self.addCleanup(p.stop)

        with self.assertRaises(PermissionError):
            hook.run()

    def test_serialization_failure_propagates(self):
        """A failure serializing the payload is re-raised, and the file is
        still opened first.
        """
        self.attrs["additional_data"]["to_kubelet_version"] = "v1.34.1"
        hook = KubeletUpgradeHook(self.attrs)

        mocked_open = mock.mock_open()
        p = mock.patch('builtins.open', mocked_open)
        p.start()
        self.addCleanup(p.stop)

        p = mock.patch('json.dump', side_effect=TypeError("not serializable"))
        mock_dump = p.start()
        self.addCleanup(p.stop)

        with self.assertRaises(TypeError):
            hook.run()

        mocked_open.assert_called_once()
        mock_dump.assert_called_once()
