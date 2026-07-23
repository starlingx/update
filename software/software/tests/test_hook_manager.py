#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for agent_hooks.py and more software_functions.py coverage."""

import logging
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from unittest.mock import MagicMock

from software.tests import base as test_base  # noqa: F401

# basicConfig must be patched before importing agent_hooks, which calls it at
# module scope and would otherwise try to open /var/log/software.log.
patch.object(logging, 'basicConfig').start()

from software.agent_hooks import BaseHook  # noqa: E402
from software.agent_hooks import UpdateKernelParametersHook
from software.agent_hooks import HookManager
from software.software_functions import PatchFile
from software.software_functions import PatchMetadata
from software.exceptions import MetadataFail

# Mock logging file handler for agent_hooks import
_orig_fh = logging.FileHandler
try:
    logging.FileHandler = lambda *a, **kw: logging.StreamHandler()
except Exception:
    pass
finally:
    logging.FileHandler = _orig_fh


class TestBaseHookGetNewDeployPath(unittest.TestCase):
    def test_returns_path(self):
        result = BaseHook.get_new_deploy_path("/etc/config")
        self.assertIn("etc/config", result)


class TestReadKthreadPrio(unittest.TestCase):
    def test_found(self):
        hook = UpdateKernelParametersHook.__new__(UpdateKernelParametersHook)
        result = hook.read_kthread_prio("isolcpus=1-3 rcutree.kthread_prio=21")
        self.assertEqual(result, "rcutree.kthread_prio=21")

    def test_not_found(self):
        hook = UpdateKernelParametersHook.__new__(UpdateKernelParametersHook)
        result = hook.read_kthread_prio("isolcpus=1-3")
        self.assertEqual(result, "")


class TestBackupKernelParams(unittest.TestCase):
    def test_backup(self):
        hook = UpdateKernelParametersHook.__new__(UpdateKernelParametersHook)
        with tempfile.TemporaryDirectory() as tmpdir:
            hook.BACKUP_DIR = tmpdir
            hook.KERNEL_PARAMS_BACKUP = os.path.join(tmpdir, "params.bak")
            hook.backup_kernel_params("isolcpus=1-3")
            with open(hook.KERNEL_PARAMS_BACKUP) as f:
                self.assertEqual(f.read(), "isolcpus=1-3")


class TestHookManagerCreate(unittest.TestCase):
    def test_upgrade(self):
        with patch.object(BaseHook, 'get_platform_conf', return_value='24.09'):
            hm = HookManager.create_hook_manager("25.03")
            self.assertIsNotNone(hm)

    def test_rollback(self):
        with patch.object(BaseHook, 'get_platform_conf', return_value='25.03'):
            hm = HookManager.create_hook_manager("24.09")
            self.assertIsNotNone(hm)


class TestPatchFileGenPatch(unittest.TestCase):
    def test_gen_patch_empty_raises(self):
        pf = PatchFile()
        pf.meta = PatchMetadata()
        with self.assertRaises(MetadataFail):
            pf.gen_patch("/output")

    @patch('subprocess.check_call',
           side_effect=subprocess.CalledProcessError(1, 'sign-rpms'))
    @patch('shutil.copy')
    @patch('os.chdir')
    @patch('os.getcwd', return_value='/orig')
    @patch('tempfile.mkdtemp', return_value='/tmp/sw_test')
    @patch('shutil.rmtree')
    def test_gen_patch_sign_fails(self, _mock_rm, _mock_mkdtemp, _mock_getcwd,
                                  _mock_chdir, _mock_copy, _mock_call):
        pf = PatchFile()
        pf.meta = PatchMetadata()
        pf.meta.id = "P1"
        with tempfile.NamedTemporaryFile(suffix=".rpm", delete=False) as f:
            f.write(b"fake")
            rpm = f.name
        try:
            pf.rpmlist = {rpm: True}
            with self.assertRaises(SystemExit):
                pf.gen_patch("/output")
        finally:
            if os.path.exists(rpm):
                os.unlink(rpm)


class TestAddKthreadPrio(unittest.TestCase):
    """add_kthread_prio_if_not_set has three branches: already set,
    standard kernel, and lowlatency (which shells out to grub).
        """

    def _hook(self, subfunction):
        hook = UpdateKernelParametersHook.__new__(UpdateKernelParametersHook)
        hook.get_platform_conf = MagicMock(return_value=subfunction)
        return hook

    @patch('software.agent_hooks.subprocess.run')
    def test_already_set_does_not_touch_grub(self, mock_run):
        """A value already present short-circuits before reading conf."""
        hook = self._hook("controller,lowlatency")
        hook.add_kthread_prio_if_not_set("rcutree.kthread_prio=21")
        mock_run.assert_not_called()
        hook.get_platform_conf.assert_not_called()

    @patch('software.agent_hooks.subprocess.run')
    def test_standard_kernel_does_not_set_param(self, mock_run):
        """Without lowlatency the parameter is deliberately not added."""
        hook = self._hook("controller,worker")
        hook.add_kthread_prio_if_not_set("")
        mock_run.assert_not_called()

    @patch('software.agent_hooks.subprocess.run')
    def test_lowlatency_adds_default_priority(self, mock_run):
        """A lowlatency node gets rcutree.kthread_prio=21 added via grub."""
        hook = self._hook("controller,lowlatency")
        hook.add_kthread_prio_if_not_set("")
        self.assertEqual(mock_run.call_count, 1)
        cmd = mock_run.call_args[0][0]
        self.assertIn("--add-kernelparams", cmd)
        self.assertIn("rcutree.kthread_prio=21", cmd)

    @patch('software.agent_hooks.subprocess.run',
           side_effect=subprocess.CalledProcessError(1, "cmd", stderr=b"err"))
    def test_grub_failure_is_contained(self, mock_run):
        """A grub failure is logged, not propagated to the caller."""
        hook = self._hook("controller,lowlatency")
        hook.add_kthread_prio_if_not_set("")
        mock_run.assert_called_once()


class TestRestoreKernelParams(unittest.TestCase):
    """restore_kernel_params reads a backup, applies it via grub-editenv,
    then deletes the backup. A missing backup is tolerated.
        """

    def _hook(self, backup_path):
        hook = UpdateKernelParametersHook.__new__(UpdateKernelParametersHook)
        hook.KERNEL_PARAMS_BACKUP = backup_path
        hook.BOOT_ENV = "/boot/efi/EFI/BOOT/boot.env"
        return hook

    @patch('software.agent_hooks.subprocess.run')
    def test_restores_params_from_backup(self, mock_run):
        """The backed-up params are passed to grub-editenv verbatim."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup = os.path.join(tmpdir, "params.bak")
            with open(backup, "w") as f:
                f.write("isolcpus=1-3 nohz_full=1-3")
            hook = self._hook(backup)

            hook.restore_kernel_params()

            cmd = mock_run.call_args[0][0]
            self.assertEqual(cmd[0], "grub-editenv")
            self.assertEqual(cmd[1], hook.BOOT_ENV)
            self.assertIn("kernel_params=isolcpus=1-3 nohz_full=1-3", cmd)

    @patch('software.agent_hooks.subprocess.run')
    def test_backup_deleted_after_restore(self, _mock_run):
        """The backup file is removed once successfully applied."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup = os.path.join(tmpdir, "params.bak")
            with open(backup, "w") as f:
                f.write("isolcpus=1-3")
            hook = self._hook(backup)

            hook.restore_kernel_params()

            self.assertFalse(os.path.exists(backup))

    @patch('software.agent_hooks.subprocess.run')
    def test_missing_backup_is_tolerated(self, mock_run):
        """A missing backup logs a warning and skips grub entirely."""
        hook = self._hook("/nonexistent/params.bak")
        hook.restore_kernel_params()
        mock_run.assert_not_called()

    @patch('software.agent_hooks.subprocess.run',
           side_effect=subprocess.CalledProcessError(1, "cmd", stderr="fail"))
    def test_grub_failure_propagates_and_keeps_backup(self, _mock_run):
        """If grub fails the error is raised and the backup is retained."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backup = os.path.join(tmpdir, "params.bak")
            with open(backup, "w") as f:
                f.write("isolcpus=1-3")
            hook = self._hook(backup)

            with self.assertRaises(subprocess.CalledProcessError):
                hook.restore_kernel_params()

            # Backup must survive so a retry is possible
            self.assertTrue(os.path.exists(backup))


class TestHookManagerRunHooks(unittest.TestCase):
    """_run_hooks instantiates each hook class with the shared attrs
    and runs it.
        """

    def test_each_hook_constructed_with_attrs_and_run(self):
        """Every registered hook is built with _attrs and then run."""
        hm = HookManager.__new__(HookManager)
        attrs = {"to_release": "25.03", "from_release": "24.09"}
        first, second = MagicMock(), MagicMock()
        hm._hooks = [first, second]
        hm._attrs = attrs
        hm._action = "upgrade"

        hm._run_hooks()

        first.assert_called_once_with(attrs)
        second.assert_called_once_with(attrs)
        first.return_value.run.assert_called_once()
        second.return_value.run.assert_called_once()

    def test_empty_hook_list_is_a_noop(self):
        """No registered hooks means nothing runs and nothing raises."""
        hm = HookManager.__new__(HookManager)
        hm._hooks = []
        hm._attrs = {}
        hm._action = "upgrade"
        hm._run_hooks()
        self.assertEqual(hm._hooks, [])

    def test_hook_failure_propagates(self):
        """A failing hook aborts the run rather than being swallowed."""
        hm = HookManager.__new__(HookManager)
        bad = MagicMock()
        bad.return_value.run.side_effect = RuntimeError("hook blew up")
        hm._hooks = [bad]
        hm._attrs = {}
        hm._action = "upgrade"

        with self.assertRaises(RuntimeError):
            hm._run_hooks()
