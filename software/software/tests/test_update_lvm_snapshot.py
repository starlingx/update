#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import datetime
import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

from software.tests import base as test_base  # noqa: F401
from software.lvm_snapshot import LVMSnapshot
from software.lvm_snapshot import LVMSnapshotManager
from software.lvm_snapshot import PlatformSnapshot
from software.lvm_snapshot import VarSnapshot
from software.lvm_snapshot import main


class TestLVMSnapshotInit(unittest.TestCase):

    def test_init_stores_attributes(self):
        snap = LVMSnapshot("cgts-vg", "docker-lv", "12G")
        self.assertEqual(snap._vg_name, "cgts-vg")
        self.assertEqual(snap._lv_name, "docker-lv")
        self.assertEqual(snap._lv_size, "12G")
        self.assertEqual(snap._name, "docker-lv_snapshot")

    def test_init_default_size_none(self):
        snap = LVMSnapshot("cgts-vg", "etcd-lv")
        self.assertIsNone(snap._lv_size)

    def test_lv_name_property(self):
        snap = LVMSnapshot("cgts-vg", "docker-lv")
        self.assertEqual(snap.lv_name, "docker-lv")

    def test_name_property(self):
        snap = LVMSnapshot("cgts-vg", "docker-lv")
        self.assertEqual(snap.name, "docker-lv_snapshot")


class TestLVMSnapshotStaticMethods(unittest.TestCase):

    def test_get_command_abs_path(self):
        result = LVMSnapshot.get_command_abs_path("lvcreate")
        self.assertEqual(result, pathlib.Path("/usr/sbin/lvcreate"))

    def test_get_major_release_version(self):
        self.assertEqual(
            LVMSnapshot.get_major_release_version("10.0.1"), "10.0")

    def test_get_major_release_version_two_parts(self):
        self.assertEqual(
            LVMSnapshot.get_major_release_version("9.0"), "9.0")

    def test_get_major_release_version_none(self):
        self.assertIsNone(LVMSnapshot.get_major_release_version(None))

    def test_get_major_release_version_empty(self):
        self.assertIsNone(LVMSnapshot.get_major_release_version(""))

    def test_get_major_release_version_invalid(self):
        self.assertIsNone(LVMSnapshot.get_major_release_version("bad"))

    def test_read_file(self):
        data = {"key": "value"}
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            f.write(json.dumps(data))
            f.flush()
            result = LVMSnapshot.read_file(f.name)
        self.assertEqual(result, data)


class TestLVMSnapshotRunCommand(unittest.TestCase):

    @mock.patch("software.lvm_snapshot.subprocess.run")
    def test_run_command_success(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["ls"], returncode=0, stdout="ok", stderr="")
        result = LVMSnapshot.run_command(["ls"])
        mock_run.assert_called_once_with(
            ["ls"], shell=False, check=True, text=True, capture_output=True)
        self.assertEqual(result.stdout, "ok")

    @mock.patch("software.lvm_snapshot.subprocess.run")
    def test_run_command_called_process_error(self, mock_run):
        mock_run.side_effect = subprocess.CalledProcessError(
            1, "cmd", stderr="fail")
        with self.assertRaises(subprocess.CalledProcessError):
            LVMSnapshot.run_command(["cmd"])

    @mock.patch("software.lvm_snapshot.subprocess.run")
    def test_run_command_generic_exception(self, mock_run):
        mock_run.side_effect = OSError("no such file")
        with self.assertRaises(OSError):
            LVMSnapshot.run_command(["bad"])


class TestLVMSnapshotToJson(unittest.TestCase):

    @mock.patch.object(LVMSnapshot, "get_id_from_tag", return_value="abc123")
    def test_to_json(self, _mock_tag):
        snap = LVMSnapshot("cgts-vg", "docker-lv", "12G")
        result = snap.to_json()
        self.assertEqual(result, {
            "name": "docker-lv_snapshot",
            "vg_name": "cgts-vg",
            "lv_name": "docker-lv",
            "lv_size": "12G",
            "tag_id": "abc123",
        })


class TestLVMSnapshotGetDevPath(unittest.TestCase):

    def test_get_dev_path(self):
        snap = LVMSnapshot("cgts-vg", "docker-lv")
        self.assertEqual(
            snap.get_dev_path(),
            pathlib.Path("/dev/cgts-vg/docker-lv_snapshot"))


class TestLVMSnapshotExists(unittest.TestCase):

    @mock.patch.object(LVMSnapshot, "run_command")
    def test_exists_true(self, mock_cmd):
        mock_cmd.return_value = subprocess.CompletedProcess(
            args="", returncode=0, stdout="docker-lv_snapshot", stderr="")
        snap = LVMSnapshot("cgts-vg", "docker-lv")
        self.assertTrue(snap.exists())

    @mock.patch.object(LVMSnapshot, "run_command")
    def test_exists_false(self, mock_cmd):
        mock_cmd.return_value = subprocess.CompletedProcess(
            args="", returncode=1, stdout="", stderr="")
        snap = LVMSnapshot("cgts-vg", "docker-lv")
        self.assertFalse(snap.exists())


class TestLVMSnapshotCreate(unittest.TestCase):

    @mock.patch.object(LVMSnapshot, "run_command")
    def test_create_with_tag(self, mock_cmd):
        snap = LVMSnapshot("cgts-vg", "docker-lv", "12G")
        snap.create("deploy-123")
        args = mock_cmd.call_args[0][0]
        self.assertIn("-s", args)
        self.assertIn("-n", args)
        self.assertIn("docker-lv_snapshot", args)
        self.assertIn("--addtag", args)
        self.assertIn("id=deploy-123", args)

    @mock.patch.object(LVMSnapshot, "run_command")
    def test_create_without_tag(self, mock_cmd):
        snap = LVMSnapshot("cgts-vg", "docker-lv", "12G")
        snap.create(None)
        args = mock_cmd.call_args[0][0]
        self.assertNotIn("--addtag", args)


class TestLVMSnapshotGetIdFromTag(unittest.TestCase):

    @mock.patch.object(LVMSnapshot, "run_command")
    def test_get_id_from_tag_found(self, mock_cmd):
        mock_cmd.return_value = subprocess.CompletedProcess(
            args="", returncode=0, stdout="  id=deploy-123  ", stderr="")
        snap = LVMSnapshot("cgts-vg", "docker-lv")
        self.assertEqual(snap.get_id_from_tag(), "deploy-123")

    @mock.patch.object(LVMSnapshot, "run_command")
    def test_get_id_from_tag_multiple_tags(self, mock_cmd):
        mock_cmd.return_value = subprocess.CompletedProcess(
            args="", returncode=0,
            stdout="  other_tag,id=deploy-456  ", stderr="")
        snap = LVMSnapshot("cgts-vg", "docker-lv")
        self.assertEqual(snap.get_id_from_tag(), "deploy-456")

    @mock.patch.object(LVMSnapshot, "run_command")
    def test_get_id_from_tag_not_found(self, mock_cmd):
        mock_cmd.return_value = subprocess.CompletedProcess(
            args="", returncode=0, stdout="  other_tag  ", stderr="")
        snap = LVMSnapshot("cgts-vg", "docker-lv")
        self.assertIsNone(snap.get_id_from_tag())

    @mock.patch.object(LVMSnapshot, "run_command")
    def test_get_id_from_tag_empty(self, mock_cmd):
        mock_cmd.return_value = subprocess.CompletedProcess(
            args="", returncode=0, stdout="  ", stderr="")
        snap = LVMSnapshot("cgts-vg", "docker-lv")
        self.assertIsNone(snap.get_id_from_tag())


class TestLVMSnapshotValidateForRollback(unittest.TestCase):

    @mock.patch.object(LVMSnapshot, "get_attributes")
    def test_validate_invalid_state(self, mock_attrs):
        mock_attrs.return_value = (
            datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc),
            False)
        snap = LVMSnapshot("cgts-vg", "docker-lv")
        with self.assertRaises(ValueError) as ctx:
            snap.validate_for_rollback("deploy-123")
        self.assertIn("invalid", str(ctx.exception).lower())

    @mock.patch.object(LVMSnapshot, "get_id_from_tag",
                       return_value="deploy-999")
    @mock.patch.object(LVMSnapshot, "get_attributes")
    def test_validate_id_mismatch(self, mock_attrs, _mock_tag):
        mock_attrs.return_value = (
            datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc),
            True)
        snap = LVMSnapshot("cgts-vg", "docker-lv")
        with self.assertRaises(ValueError) as ctx:
            snap.validate_for_rollback("deploy-123")
        self.assertIn("mismatch", str(ctx.exception).lower())


class TestLVMSnapshotRestore(unittest.TestCase):

    @mock.patch.object(LVMSnapshot, "run_command")
    def test_restore(self, mock_cmd):
        snap = LVMSnapshot("cgts-vg", "docker-lv")
        snap.restore()
        args = mock_cmd.call_args[0][0]
        self.assertIn("--merge", args)
        self.assertEqual(
            args[0], pathlib.Path("/usr/sbin/lvconvert"))


class TestLVMSnapshotDelete(unittest.TestCase):

    @mock.patch.object(LVMSnapshot, "run_command")
    def test_delete(self, mock_cmd):
        snap = LVMSnapshot("cgts-vg", "docker-lv")
        snap.delete()
        args = mock_cmd.call_args[0][0]
        self.assertIn("-f", args)
        self.assertEqual(
            args[0], pathlib.Path("/usr/sbin/lvremove"))


class TestLVMSnapshotGetAttributes(unittest.TestCase):

    @mock.patch.object(LVMSnapshot, "run_command")
    def test_get_attributes_valid(self, mock_cmd):
        mock_cmd.return_value = subprocess.CompletedProcess(
            args="", returncode=0,
            stdout="  2025-01-15 10:30:00 +0000,active  ", stderr="")
        snap = LVMSnapshot("cgts-vg", "docker-lv")
        create_date, valid = snap.get_attributes()
        self.assertIsInstance(create_date, datetime.datetime)
        self.assertEqual(create_date.year, 2025)
        self.assertTrue(valid)

    @mock.patch.object(LVMSnapshot, "run_command")
    def test_get_attributes_invalid(self, mock_cmd):
        mock_cmd.return_value = subprocess.CompletedProcess(
            args="", returncode=0,
            stdout="  2025-01-15 10:30:00 +0000,snapshot INVALID  ",
            stderr="")
        snap = LVMSnapshot("cgts-vg", "docker-lv")
        _, valid = snap.get_attributes()
        self.assertFalse(valid)


class TestLVMSnapshotMount(unittest.TestCase):

    @mock.patch.object(LVMSnapshot, "run_command")
    @mock.patch("software.lvm_snapshot.shutil.rmtree")
    @mock.patch("software.lvm_snapshot.tempfile.mkdtemp",
                return_value="/tmp/docker-lv-xyz")
    def test_mount_context_manager(self, _mock_mkd, _mock_rm, mock_cmd):
        snap = LVMSnapshot("cgts-vg", "docker-lv")
        with snap.mount() as mount_dir:
            self.assertEqual(mount_dir, "/tmp/docker-lv-xyz")
        self.assertEqual(mock_cmd.call_count, 2)
        mount_call = mock_cmd.call_args_list[0][0][0]
        self.assertIn("/usr/bin/mount", mount_call)
        umount_call = mock_cmd.call_args_list[1][0][0]
        self.assertIn("/usr/bin/umount", umount_call)

    @mock.patch.object(LVMSnapshot, "run_command")
    @mock.patch("software.lvm_snapshot.shutil.rmtree")
    @mock.patch("software.lvm_snapshot.tempfile.mkdtemp",
                return_value="/tmp/docker-lv-xyz")
    def test_mount_error_still_unmounts(self, _mock_mkd, _mock_rm, mock_cmd):
        mock_cmd.side_effect = [OSError("mount fail"), mock.DEFAULT]
        snap = LVMSnapshot("cgts-vg", "docker-lv")
        with self.assertRaises(OSError):
            with snap.mount():
                pass


class TestVarSnapshot(unittest.TestCase):

    @mock.patch("software.lvm_snapshot.shutil.copy2")
    @mock.patch.object(VarSnapshot, "run_command")
    @mock.patch.object(VarSnapshot, "mount")
    def test_update_deployment_data(
        self, mock_mount, _mock_cmd, _mock_copy
    ):
        software_data = {
            "deploy_host": [{"state": "deployed"}],
            "deploy": [{
                "state": "deploying",
                "from_release": "9.0.0",
                "to_release": "10.0.0",
            }],
        }
        m_open = mock.mock_open(read_data=json.dumps(software_data))
        mock_mount.return_value.__enter__ = mock.Mock(
            return_value="/tmp/var-lv-xyz")
        mock_mount.return_value.__exit__ = mock.Mock(return_value=False)

        snap = VarSnapshot("cgts-vg", "var-lv", "3G")
        with mock.patch("builtins.open", m_open):
            snap._update_deployment_data()

        written = m_open().write.call_args[0][0]
        written_data = json.loads(written)
        self.assertEqual(
            written_data["deploy_host"][0]["state"], "rollback-deployed")
        self.assertEqual(
            written_data["deploy"][0]["state"], "host-rollback-done")
        self.assertEqual(
            written_data["deploy"][0]["from_release"], "10.0.0")
        self.assertEqual(
            written_data["deploy"][0]["to_release"], "9.0.0")

    @mock.patch("software.lvm_snapshot.shutil.copy2")
    @mock.patch.object(VarSnapshot, "run_command")
    @mock.patch.object(VarSnapshot, "mount")
    def test_update_deployment_data_no_swap_when_downgrade(
        self, mock_mount, _mock_cmd, _mock_copy
    ):
        software_data = {
            "deploy_host": [{"state": "deployed"}],
            "deploy": [{
                "state": "deploying",
                "from_release": "10.0.0",
                "to_release": "9.0.0",
            }],
        }
        m_open = mock.mock_open(read_data=json.dumps(software_data))
        mock_mount.return_value.__enter__ = mock.Mock(
            return_value="/tmp/var-lv-xyz")
        mock_mount.return_value.__exit__ = mock.Mock(return_value=False)

        snap = VarSnapshot("cgts-vg", "var-lv", "3G")
        with mock.patch("builtins.open", m_open):
            snap._update_deployment_data()

        written = m_open().write.call_args[0][0]
        written_data = json.loads(written)
        self.assertEqual(
            written_data["deploy"][0]["from_release"], "10.0.0")
        self.assertEqual(
            written_data["deploy"][0]["to_release"], "9.0.0")

    @mock.patch.object(VarSnapshot, "mount")
    def test_update_deployment_data_error_raises(self, mock_mount):
        mock_mount.return_value.__enter__ = mock.Mock(
            side_effect=OSError("mount fail"))
        mock_mount.return_value.__exit__ = mock.Mock(return_value=False)
        snap = VarSnapshot("cgts-vg", "var-lv", "3G")
        with self.assertRaises(OSError):
            snap._update_deployment_data()


class TestPlatformSnapshot(unittest.TestCase):

    @mock.patch("software.lvm_snapshot.time.sleep")
    @mock.patch("software.lvm_snapshot.subprocess.run")
    def test_wait_for_vim_ready_success(self, mock_run, _mock_sleep):
        mock_run.return_value = subprocess.CompletedProcess(
            args="", returncode=0, stdout="", stderr="")
        result = PlatformSnapshot._wait_for_vim_ready(timeout=5)
        self.assertTrue(result)

    @mock.patch("software.lvm_snapshot.time.sleep")
    @mock.patch("software.lvm_snapshot.time.time")
    @mock.patch("software.lvm_snapshot.subprocess.run")
    def test_wait_for_vim_ready_timeout(
        self, mock_run, mock_time, _mock_sleep
    ):
        mock_run.side_effect = Exception("not ready")
        mock_time.side_effect = [0, 0, 5, 10, 15, 25]
        result = PlatformSnapshot._wait_for_vim_ready(timeout=20)
        self.assertFalse(result)

    @mock.patch.object(PlatformSnapshot, "_wait_for_vim_ready",
                       return_value=True)
    @mock.patch.object(PlatformSnapshot, "run_command")
    @mock.patch("software.lvm_snapshot.shutil.rmtree")
    @mock.patch("software.lvm_snapshot.tempfile.mkdtemp",
                return_value="/tmp/platform-lv-xyz")
    @mock.patch("software.lvm_snapshot.tempfile.NamedTemporaryFile")
    @mock.patch("software.lvm_snapshot.configparser.ConfigParser")
    def test_replace_vim_db_full(
        self, mock_config, mock_tmpfile, _mock_mkd,
        _mock_rmtree, mock_cmd, _mock_vim
    ):
        software_data = {
            "deploy": [{
                "from_release": "9.0.1",
                "to_release": "10.0.0",
            }],
        }
        dump_data = {
            "tables": {"sw_updates": [{"id": 1}]},
        }
        mock_tmpfile.return_value.name = "/tmp/dump123"
        mock_config_inst = mock_config.return_value

        m_open = mock.mock_open(read_data=json.dumps(dump_data))
        snap = PlatformSnapshot("cgts-vg", "platform-lv", "2G")

        with mock.patch.object(
            snap, "read_file", return_value=software_data
        ):
            with mock.patch("builtins.open", m_open):
                with mock.patch("pathlib.Path.mkdir"):
                    snap._replace_vim_db()

        self.assertTrue(mock_cmd.call_count >= 3)
        mock_config_inst.read.assert_called_once()
        mock_config_inst.set.assert_called_once_with(
            "database", "database_dir", mock.ANY)

    @mock.patch.object(PlatformSnapshot, "run_command")
    @mock.patch("software.lvm_snapshot.tempfile.NamedTemporaryFile")
    def test_replace_vim_db_empty_sw_updates(
        self, mock_tmpfile, mock_cmd
    ):
        software_data = {
            "deploy": [{
                "from_release": "9.0.1",
                "to_release": "10.0.0",
            }],
        }
        dump_data = {
            "tables": {"sw_updates": []},
        }
        mock_tmpfile.return_value.name = "/tmp/dump123"

        m_open = mock.mock_open(read_data=json.dumps(dump_data))
        snap = PlatformSnapshot("cgts-vg", "platform-lv", "2G")

        with mock.patch.object(
            snap, "read_file", return_value=software_data
        ):
            with mock.patch("builtins.open", m_open):
                snap._replace_vim_db()

        # Should return early, only db-dump-data command called
        self.assertEqual(mock_cmd.call_count, 1)

    @mock.patch.object(PlatformSnapshot, "run_command")
    def test_replace_vim_db_error_raises(self, _mock_cmd):
        snap = PlatformSnapshot("cgts-vg", "platform-lv", "2G")
        with mock.patch.object(
            snap, "read_file", side_effect=FileNotFoundError("read fail")
        ):
            with self.assertRaises(FileNotFoundError):
                snap._replace_vim_db()


class TestLVMSnapshotManager(unittest.TestCase):

    def test_init_defaults(self):
        mgr = LVMSnapshotManager()
        self.assertEqual(mgr.vg_name, "cgts-vg")
        self.assertIn("docker-lv", mgr.lvs)

    def test_init_custom(self):
        mgr = LVMSnapshotManager(
            vg_name="test-vg", lvs={"lv1": "1G"})
        self.assertEqual(mgr.vg_name, "test-vg")
        self.assertEqual(mgr.lvs, {"lv1": "1G"})

    def test_create_instance_var(self):
        mgr = LVMSnapshotManager()
        snap = mgr.create_instance("var-lv")
        self.assertIsInstance(snap, VarSnapshot)

    def test_create_instance_platform(self):
        mgr = LVMSnapshotManager()
        snap = mgr.create_instance("platform-lv")
        self.assertIsInstance(snap, PlatformSnapshot)

    def test_create_instance_generic(self):
        mgr = LVMSnapshotManager()
        snap = mgr.create_instance("docker-lv")
        self.assertIsInstance(snap, LVMSnapshot)
        self.assertNotIsInstance(snap, VarSnapshot)
        self.assertNotIsInstance(snap, PlatformSnapshot)

    @mock.patch.object(LVMSnapshot, "create")
    @mock.patch.object(LVMSnapshot, "delete")
    @mock.patch.object(LVMSnapshot, "exists", return_value=False)
    def test_create_snapshots_success(
        self, _mock_exists, _mock_del, mock_create
    ):
        mgr = LVMSnapshotManager(
            lvs={"lv1": "1G", "lv2": "2G"})
        result = mgr.create_snapshots("tag-1")
        self.assertTrue(result)
        self.assertEqual(mock_create.call_count, 2)

    @mock.patch.object(LVMSnapshot, "create")
    @mock.patch.object(LVMSnapshot, "delete")
    @mock.patch.object(LVMSnapshot, "exists", return_value=True)
    def test_create_snapshots_deletes_existing(
        self, _mock_exists, mock_del, _mock_create
    ):
        mgr = LVMSnapshotManager(lvs={"lv1": "1G"})
        result = mgr.create_snapshots("tag-1")
        self.assertTrue(result)
        mock_del.assert_called_once()

    @mock.patch.object(LVMSnapshotManager, "delete_snapshots")
    @mock.patch.object(LVMSnapshot, "create",
                       side_effect=Exception("fail"))
    @mock.patch.object(LVMSnapshot, "exists", return_value=False)
    def test_create_snapshots_failure_cleans_up(
        self, _mock_exists, _mock_create, mock_delete
    ):
        mgr = LVMSnapshotManager(lvs={"lv1": "1G"})
        result = mgr.create_snapshots("tag-1")
        self.assertFalse(result)
        mock_delete.assert_called_once()

    @mock.patch.object(LVMSnapshot, "exists", return_value=True)
    def test_list_snapshots(self, _mock_exists):
        mgr = LVMSnapshotManager(lvs={"lv1": "1G", "lv2": "2G"})
        result = mgr.list_snapshots()
        self.assertEqual(len(result), 2)

    @mock.patch.object(LVMSnapshot, "exists", return_value=False)
    def test_list_snapshots_empty(self, _mock_exists):
        mgr = LVMSnapshotManager(lvs={"lv1": "1G"})
        result = mgr.list_snapshots()
        self.assertEqual(len(result), 0)

    @mock.patch.object(LVMSnapshotManager, "_save_restore_progress")
    @mock.patch.object(LVMSnapshot, "restore")
    @mock.patch.object(LVMSnapshot, "exists", return_value=True)
    @mock.patch.object(LVMSnapshot, "validate_for_rollback")
    @mock.patch.object(LVMSnapshotManager, "list_snapshots")
    @mock.patch.object(LVMSnapshotManager, "_load_restore_progress",
                       return_value=set())
    def test_restore_snapshots_success(
        self, _mock_progress, mock_list, _mock_validate,
        _mock_exists, _mock_restore, _mock_save
    ):
        snap1 = LVMSnapshot("cgts-vg", "lv1", "1G")
        mock_list.return_value = [snap1]
        mgr = LVMSnapshotManager(lvs={"lv1": "1G"})
        result = mgr.restore_snapshots("tag-1")
        self.assertTrue(result)

    @mock.patch.object(LVMSnapshotManager, "list_snapshots")
    @mock.patch.object(LVMSnapshotManager, "_load_restore_progress",
                       return_value=set())
    def test_restore_snapshots_missing(self, _mock_progress, mock_list):
        mock_list.return_value = []
        mgr = LVMSnapshotManager(lvs={"lv1": "1G"})
        result = mgr.restore_snapshots("tag-1")
        # With empty list and empty progress, pending is empty -> returns True
        self.assertTrue(result)

    @mock.patch.object(LVMSnapshot, "validate_for_rollback",
                       side_effect=ValueError("mismatch"))
    @mock.patch.object(LVMSnapshotManager, "list_snapshots")
    def test_restore_snapshots_invalid(self, mock_list, _mock_validate):
        snap1 = LVMSnapshot("cgts-vg", "lv1", "1G")
        mock_list.return_value = [snap1]
        mgr = LVMSnapshotManager(lvs={"lv1": "1G"})
        result = mgr.restore_snapshots("tag-1")
        self.assertFalse(result)

    @mock.patch.object(LVMSnapshot, "restore",
                       side_effect=Exception("fail"))
    @mock.patch.object(LVMSnapshot, "exists", return_value=True)
    @mock.patch.object(LVMSnapshot, "validate_for_rollback")
    @mock.patch.object(LVMSnapshotManager, "list_snapshots")
    def test_restore_snapshots_restore_error(
        self, mock_list, _mock_val, _mock_exists, _mock_restore
    ):
        snap1 = LVMSnapshot("cgts-vg", "lv1", "1G")
        mock_list.return_value = [snap1]
        mgr = LVMSnapshotManager(lvs={"lv1": "1G"})
        result = mgr.restore_snapshots("tag-1")
        self.assertFalse(result)


class TestMain(unittest.TestCase):

    @mock.patch.object(LVMSnapshotManager, "create_snapshots",
                       return_value=True)
    def test_main_create(self, mock_create):
        with mock.patch("sys.argv", ["prog", "--create", "--tag-id", "t1"]):
            rc = main()
        self.assertEqual(rc, 0)
        mock_create.assert_called_once_with("t1")

    @mock.patch.object(LVMSnapshotManager, "restore_snapshots",
                       return_value=True)
    def test_main_restore(self, mock_restore):
        with mock.patch("sys.argv", ["prog", "--restore", "--tag-id", "t1"]):
            rc = main()
        self.assertEqual(rc, 0)
        mock_restore.assert_called_once_with("t1")

    @mock.patch.object(LVMSnapshotManager, "delete_snapshots")
    def test_main_delete(self, mock_delete):
        with mock.patch("sys.argv", ["prog", "--delete"]):
            rc = main()
        self.assertEqual(rc, 0)
        mock_delete.assert_called_once()

    @mock.patch.object(LVMSnapshotManager, "list_snapshots",
                       return_value=[])
    def test_main_list_empty(self, _mock_list):
        with mock.patch("sys.argv", ["prog", "--list"]):
            rc = main()
        self.assertEqual(rc, 1)

    @mock.patch.object(LVMSnapshotManager, "create_snapshots",
                       return_value=False)
    def test_main_create_failure(self, _mock_create):
        with mock.patch("sys.argv", ["prog", "--create"]):
            rc = main()
        self.assertEqual(rc, 1)

    def test_main_no_args(self):
        with mock.patch("sys.argv", ["prog"]):
            rc = main()
        self.assertEqual(rc, 0)
