#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for software.ostree_utils module."""

import subprocess
import unittest
from unittest.mock import MagicMock
from unittest.mock import mock_open
from unittest.mock import patch

import sh as sh_mod

from software import constants
from software.exceptions import OSTreeCommandFail
from software.ostree_utils import add_aux_remote
from software.ostree_utils import add_gpg_verify_false
from software.ostree_utils import add_ostree_remote
from software.ostree_utils import add_tombstone_commit_if_prepatched
from software.ostree_utils import check_commit_id
from software.ostree_utils import checkout_commit_to_dir
from software.ostree_utils import checkout_latest_ostree_commit
from software.ostree_utils import create_bind_mount
from software.ostree_utils import create_deployment
from software.ostree_utils import delete_older_deployments
from software.ostree_utils import delete_ostree_ref
from software.ostree_utils import delete_ostree_remote
from software.ostree_utils import delete_ostree_repo_commit
from software.ostree_utils import delete_temporary_refs_and_remotes
from software.ostree_utils import fetch_active_deployment
from software.ostree_utils import fetch_pending_deployment
from software.ostree_utils import get_all_feed_commits
from software.ostree_utils import get_feed_latest_commit
from software.ostree_utils import get_latest_deployment_commit
from software.ostree_utils import get_ostree_latest_commit
from software.ostree_utils import get_sysroot_latest_commit
from software.ostree_utils import pull_aux_remote
from software.ostree_utils import pull_ostree_from_remote
from software.ostree_utils import reset_ostree_repo_head
from software.ostree_utils import update_repo_summary_file
from software.ostree_utils import write_to_feed_ostree
import fcntl

from software.ostree_utils import mount_new_deployment
from software.ostree_utils import with_ostree_lock
from software.tests import base as test_base  # noqa: F401


def _make_completed(stdout=b"", returncode=0):
    return subprocess.CompletedProcess(args="", returncode=returncode,
                                       stdout=stdout, stderr=b"")


def _make_cpe(returncode=1, stderr=b"error"):
    return subprocess.CalledProcessError(returncode, "cmd",
                                         stderr=stderr)


class TestGetOstreeLatestCommit(unittest.TestCase):
    """Tests for get_ostree_latest_commit."""

    @patch('software.ostree_utils.subprocess.run')
    def test_success(self, mock_run):
        mock_run.return_value = _make_completed(
            b"commit abc123def\nContentChecksum: xyz\n")
        result = get_ostree_latest_commit("starlingx", "/repo")
        self.assertEqual(result, "abc123def")
        mock_run.assert_called_once_with(
            "ostree log starlingx --repo=/repo",
            shell=True, check=True, capture_output=True)

    @patch('software.ostree_utils.subprocess.run',
           side_effect=_make_cpe())
    def test_failure(self, _mock_run):
        self.assertRaises(OSTreeCommandFail,
                          get_ostree_latest_commit, "starlingx", "/repo")


class TestAddGpgVerifyFalse(unittest.TestCase):
    """Tests for add_gpg_verify_false."""

    @patch('software.ostree_utils.os.path.exists', return_value=False)
    def test_missing_config(self, _mock_exists):
        self.assertRaises(OSTreeCommandFail,
                          add_gpg_verify_false, "/sysroot/ostree/repo")


class TestAddAuxRemote(unittest.TestCase):
    """Tests for add_aux_remote."""

    @patch('software.ostree_utils.add_gpg_verify_false')
    @patch('software.ostree_utils.subprocess.run')
    def test_success(self, mock_run, mock_gpg):
        mock_run.return_value = _make_completed()
        add_aux_remote("/ostree/repo", "22.06")
        self.assertEqual(mock_gpg.call_count, 2)

    @patch('software.ostree_utils.add_gpg_verify_false')
    @patch('software.ostree_utils.subprocess.run',
           side_effect=_make_cpe())
    def test_failure(self, _mock_run, _mock_gpg):
        self.assertRaises(OSTreeCommandFail,
                          add_aux_remote, "/ostree/repo", "22.06")


class TestPullAuxRemote(unittest.TestCase):
    """Tests for pull_aux_remote."""

    @patch('software.ostree_utils.subprocess.run',
           side_effect=_make_cpe())
    def test_failure(self, _mock_run):
        self.assertRaises(OSTreeCommandFail,
                          pull_aux_remote, "/ostree/repo")


class TestGetFeedLatestCommit(unittest.TestCase):
    """Tests for get_feed_latest_commit."""

    @patch('software.ostree_utils.get_ostree_latest_commit',
           return_value="feedcommit123")
    def test_default_path(self, _mock_get):
        result = get_feed_latest_commit("22.06")
        self.assertEqual(result, "feedcommit123")

    @patch('software.ostree_utils.get_ostree_latest_commit',
           return_value="auxcommit456")
    @patch('software.ostree_utils.pull_aux_remote')
    @patch('software.ostree_utils.subprocess.run')
    def test_aux_remote_path_exists(self, mock_run, _mock_pull, _mock_get):
        mock_run.return_value = _make_completed()
        result = get_feed_latest_commit(
            "22.06", constants.OSTREE_AUX_REMOTE_PATH)
        self.assertEqual(result, "auxcommit456")

    @patch('software.ostree_utils.get_ostree_latest_commit',
           return_value="auxcommit789")
    @patch('software.ostree_utils.pull_aux_remote')
    @patch('software.ostree_utils.add_aux_remote')
    @patch('software.ostree_utils.subprocess.run',
           side_effect=_make_cpe())
    def test_aux_remote_path_not_exists(self, _mock_run, mock_add,
                                        _mock_pull, _mock_get):
        result = get_feed_latest_commit(
            "22.06", constants.OSTREE_AUX_REMOTE_PATH)
        mock_add.assert_called_once()
        self.assertEqual(result, "auxcommit789")


class TestGetSysrootLatestCommit(unittest.TestCase):
    """Tests for get_sysroot_latest_commit."""

    @patch('software.ostree_utils.get_ostree_latest_commit',
           return_value="sysrootcommit")
    def test_success(self, _mock_get):
        result = get_sysroot_latest_commit()
        self.assertEqual(result, "sysrootcommit")


class TestGetAllFeedCommits(unittest.TestCase):
    """Tests for get_all_feed_commits."""

    @patch('software.ostree_utils.subprocess.run')
    def test_success(self, mock_run):
        mock_run.return_value = _make_completed(
            b"commit abc123\ncommit def456\n")
        result = get_all_feed_commits("22.06")
        self.assertEqual(result, ["abc123", "def456"])

    @patch('software.ostree_utils.subprocess.run',
           side_effect=_make_cpe())
    def test_failure(self, _mock_run):
        self.assertRaises(OSTreeCommandFail,
                          get_all_feed_commits, "22.06")


class TestGetLatestDeploymentCommit(unittest.TestCase):
    """Tests for get_latest_deployment_commit."""

    @patch('software.ostree_utils.subprocess.run')
    def test_success_pending(self, mock_run):
        output = (b"debian 0658a628.0 (pending)\n"
                  b"  origin refspec: starlingx\n"
                  b"* debian a5d8f8ca.0\n"
                  b"  origin refspec: starlingx\n")
        mock_run.return_value = _make_completed(output)
        result = get_latest_deployment_commit()
        self.assertEqual(result, "0658a628")

    @patch('software.ostree_utils.subprocess.run')
    def test_no_match(self, mock_run):
        mock_run.return_value = _make_completed(b"")
        result = get_latest_deployment_commit()
        self.assertIsNone(result)

    @patch('software.ostree_utils.subprocess.run',
           side_effect=_make_cpe())
    def test_failure(self, _mock_run):
        self.assertRaises(OSTreeCommandFail,
                          get_latest_deployment_commit)


class TestUpdateRepoSummaryFile(unittest.TestCase):
    """Tests for update_repo_summary_file."""

    @patch('software.ostree_utils.subprocess.run',
           side_effect=_make_cpe())
    def test_failure(self, _mock_run):
        self.assertRaises(OSTreeCommandFail,
                          update_repo_summary_file, "/repo")


class TestResetOstreeRepoHead(unittest.TestCase):
    """Tests for reset_ostree_repo_head."""

    @patch('software.ostree_utils.subprocess.run',
           side_effect=_make_cpe())
    def test_failure(self, _mock_run):
        self.assertRaises(OSTreeCommandFail,
                          reset_ostree_repo_head, "abc123", "/repo")


class TestPullOstreeFromRemote(unittest.TestCase):
    """Tests for pull_ostree_from_remote."""

    @patch('software.ostree_utils.add_gpg_verify_false')
    @patch('software.ostree_utils.subprocess.run')
    def test_success_no_remote(self, mock_run, _mock_gpg):
        mock_run.return_value = _make_completed()
        pull_ostree_from_remote()
        self.assertEqual(mock_run.call_count, 1)

    @patch('software.ostree_utils.add_gpg_verify_false')
    @patch('software.ostree_utils.subprocess.run')
    def test_success_with_remote(self, mock_run, _mock_gpg):
        mock_run.return_value = _make_completed()
        pull_ostree_from_remote("myremote")
        # pull + refs command
        self.assertEqual(mock_run.call_count, 2)

    @patch('software.ostree_utils.add_gpg_verify_false')
    @patch('software.ostree_utils.subprocess.run',
           side_effect=_make_cpe())
    def test_pull_failure(self, _mock_run, _mock_gpg):
        self.assertRaises(OSTreeCommandFail,
                          pull_ostree_from_remote)

    @patch('software.ostree_utils.add_gpg_verify_false')
    @patch('software.ostree_utils.subprocess.run')
    def test_ref_cmd_failure(self, mock_run, _mock_gpg):
        mock_run.side_effect = [
            _make_completed(),
            _make_cpe()
        ]
        self.assertRaises(OSTreeCommandFail,
                          pull_ostree_from_remote, "myremote")


class TestDeleteOstreeRepoCommit(unittest.TestCase):
    """Tests for delete_ostree_repo_commit."""

    @patch('software.ostree_utils.subprocess.run',
           side_effect=_make_cpe())
    def test_failure(self, _mock_run):
        self.assertRaises(OSTreeCommandFail,
                          delete_ostree_repo_commit, "abc123", "/repo")


class TestAddTombstoneCommitIfPrepatched(unittest.TestCase):
    """Tests for add_tombstone_commit_if_prepatched."""

    @patch('software.ostree_utils.subprocess.run')
    def test_no_history_marker(self, mock_run):
        mock_run.return_value = _make_completed(
            b"commit abc123\nDate: 2024-01-01\n")
        result = add_tombstone_commit_if_prepatched("starlingx", "/repo")
        self.assertFalse(result)

    @patch('builtins.open', new_callable=mock_open)
    @patch('software.ostree_utils.os.path.exists', return_value=True)
    @patch('software.ostree_utils.os.path.isfile', return_value=False)
    @patch('software.ostree_utils.os.makedirs')
    @patch('software.ostree_utils.configparser.ConfigParser')
    @patch('software.ostree_utils.subprocess.run')
    def test_creates_tombstone(self, mock_run, mock_cfg_cls,
                               _mock_makedirs, _mock_isfile,
                               _mock_exists, _mock_file):
        log_output = (
            b"commit abc123\n"
            b"Parent: deadbeef1234567890\n"
            b"<< History beyond this commit not fetched >>\n"
        )
        mock_run.return_value = _make_completed(log_output)
        cfg = MagicMock()
        mock_cfg_cls.return_value = cfg
        result = add_tombstone_commit_if_prepatched("starlingx", "/repo")
        self.assertTrue(result)

    @patch('software.ostree_utils.subprocess.run')
    @patch('software.ostree_utils.os.path.isfile', return_value=True)
    def test_tombstone_already_exists(self, _mock_isfile, mock_run):
        log_output = (
            b"commit abc123\n"
            b"Parent: deadbeef1234567890\n"
            b"<< History beyond this commit not fetched >>\n"
        )
        mock_run.return_value = _make_completed(log_output)
        result = add_tombstone_commit_if_prepatched("starlingx", "/repo")
        self.assertFalse(result)

    @patch('software.ostree_utils.subprocess.run',
           side_effect=_make_cpe())
    def test_failure(self, _mock_run):
        self.assertRaises(OSTreeCommandFail,
                          add_tombstone_commit_if_prepatched,
                          "starlingx", "/repo")


class TestCreateDeployment(unittest.TestCase):
    """Tests for create_deployment."""

    @patch('software.ostree_utils.subprocess.run')
    @patch('software.ostree_utils.sync_boot_entries')
    def test_success(self, _mock_sync, mock_run):
        mock_run.return_value = _make_completed()
        create_deployment()
        self.assertEqual(mock_run.call_count, 2)

    @patch('software.ostree_utils.subprocess.run',
           side_effect=_make_cpe())
    @patch('software.ostree_utils.sync_boot_entries')
    def test_deploy_failure(self, _mock_sync, _mock_run):
        self.assertRaises(OSTreeCommandFail, create_deployment)

    @patch('software.ostree_utils.subprocess.run')
    @patch('software.ostree_utils.sync_boot_entries')
    def test_grub_failure(self, _mock_sync, mock_run):
        mock_run.side_effect = [
            _make_completed(),
            _make_cpe()
        ]
        self.assertRaises(subprocess.CalledProcessError,
                          create_deployment)

    @patch('software.ostree_utils.subprocess.run')
    @patch('software.ostree_utils.sync_boot_entries')
    def test_custom_ref(self, _mock_sync, mock_run):
        mock_run.return_value = _make_completed()
        create_deployment(ref="myref")
        call_args = mock_run.call_args_list[0]
        self.assertIn("myref", call_args[0][0])


class TestFetchPendingDeployment(unittest.TestCase):
    """Tests for fetch_pending_deployment."""

    @patch('software.ostree_utils.subprocess.run')
    def test_success(self, mock_run):
        mock_run.return_value = _make_completed(b"abc123.0")
        result = fetch_pending_deployment()
        self.assertEqual(result, "abc123.0")

    @patch('software.ostree_utils.subprocess.run',
           side_effect=_make_cpe())
    def test_failure(self, _mock_run):
        self.assertRaises(OSTreeCommandFail,
                          fetch_pending_deployment)


class TestFetchActiveDeployment(unittest.TestCase):
    """Tests for fetch_active_deployment."""

    @patch('software.ostree_utils.subprocess.run')
    def test_success(self, mock_run):
        mock_run.return_value = _make_completed(b"active123.0")
        result = fetch_active_deployment()
        self.assertEqual(result, "active123.0")

    @patch('software.ostree_utils.subprocess.run',
           side_effect=_make_cpe())
    def test_failure(self, _mock_run):
        self.assertRaises(OSTreeCommandFail,
                          fetch_active_deployment)


class TestCreateBindMount(unittest.TestCase):
    """Tests for create_bind_mount."""

    @patch('software.ostree_utils.time.sleep')
    @patch('software.ostree_utils.sh.mount')
    def test_retry_success(self, mock_mount, _mock_sleep):
        mock_mount.side_effect = [
            sh_mod.ErrorReturnCode_1("mount", b"", b"err"),
            None
        ]
        create_bind_mount("/src", "/tgt")
        self.assertEqual(mock_mount.call_count, 2)

    @patch('software.ostree_utils.time.sleep')
    @patch('software.ostree_utils.sh.mount')
    def test_retry_failure(self, mock_mount, _mock_sleep):
        err = sh_mod.ErrorReturnCode_1("mount", b"", b"err")
        mock_mount.side_effect = [err, err]
        self.assertRaises(OSTreeCommandFail,
                          create_bind_mount, "/src", "/tgt")


class TestDeleteOlderDeployments(unittest.TestCase):
    """Tests for delete_older_deployments."""

    @patch('software.ostree_utils.subprocess.run')
    def test_no_older(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args="", returncode=0,
            stdout="* debian abc123.0\n", stderr="")
        result = delete_older_deployments()
        self.assertTrue(result)

    @patch('software.ostree_utils.subprocess.run')
    def test_with_older(self, mock_run):
        status_out = ("* debian abc123.2\n"
                      "  debian abc123.1 (rollback)\n"
                      "  debian abc123.0\n")
        mock_run.return_value = subprocess.CompletedProcess(
            args="", returncode=0, stdout=status_out, stderr="")
        result = delete_older_deployments()
        self.assertTrue(result)

    @patch('software.ostree_utils.subprocess.run',
           side_effect=_make_cpe())
    def test_status_failure(self, _mock_run):
        self.assertRaises(OSTreeCommandFail,
                          delete_older_deployments)


class TestCheckoutCommitToDir(unittest.TestCase):
    """Tests for checkout_commit_to_dir."""

    @patch('software.ostree_utils.subprocess.run')
    def test_with_subpath(self, mock_run):
        mock_run.return_value = _make_completed()
        checkout_commit_to_dir("/repo", "abc123", "/dest",
                               sub_path="/usr")
        cmd = mock_run.call_args[0][0]
        self.assertIn("--subpath=/usr", cmd)

    @patch('software.ostree_utils.subprocess.run',
           side_effect=_make_cpe())
    def test_failure(self, _mock_run):
        self.assertRaises(OSTreeCommandFail,
                          checkout_commit_to_dir,
                          "/repo", "abc123", "/dest")


class TestAddOstreeRemote(unittest.TestCase):
    """Tests for add_ostree_remote."""

    @patch('software.ostree_utils.pull_ostree_from_remote')
    @patch('software.ostree_utils.add_gpg_verify_false')
    @patch('software.ostree_utils.subprocess.check_call')
    def test_success_controller(self, _mock_call, _mock_gpg, _mock_pull):
        result = add_ostree_remote("24.09", "controller")
        self.assertIsNotNone(result)

    @patch('software.ostree_utils.pull_ostree_from_remote')
    @patch('software.ostree_utils.add_gpg_verify_false')
    @patch('software.ostree_utils.subprocess.check_call')
    def test_success_worker(self, _mock_call, _mock_gpg, _mock_pull):
        result = add_ostree_remote("24.09", "worker")
        self.assertIsNotNone(result)

    @patch('software.ostree_utils.subprocess.check_call',
           side_effect=subprocess.CalledProcessError(1, "cmd"))
    def test_failure(self, _mock_call):
        result = add_ostree_remote("24.09", "controller")
        self.assertIsNone(result)

    @patch('software.ostree_utils.pull_ostree_from_remote')
    @patch('software.ostree_utils.add_gpg_verify_false')
    @patch('software.ostree_utils.subprocess.check_call')
    def test_replace_default(self, _mock_call, _mock_gpg, _mock_pull):
        result = add_ostree_remote("24.09", "controller",
                                   replace_default_remote=True)
        self.assertEqual(result, constants.OSTREE_REMOTE)


class TestDeleteOstreeRemote(unittest.TestCase):
    """Tests for delete_ostree_remote."""

    @patch('software.ostree_utils.subprocess.check_call',
           side_effect=subprocess.CalledProcessError(1, "cmd"))
    def test_failure(self, _mock_call):
        self.assertRaises(subprocess.CalledProcessError,
                          delete_ostree_remote, "myremote")


class TestDeleteOstreeRef(unittest.TestCase):
    """Tests for delete_ostree_ref."""

    @patch('software.ostree_utils.subprocess.check_call',
           side_effect=subprocess.CalledProcessError(1, "cmd"))
    def test_failure(self, _mock_call):
        self.assertRaises(subprocess.CalledProcessError,
                          delete_ostree_ref, "myref")


class TestCheckCommitId(unittest.TestCase):
    """Tests for check_commit_id."""

    @patch('software.ostree_utils.subprocess.check_output',
           return_value="abc123\n")
    @patch('software.ostree_utils.pull_ostree_from_remote')
    def test_match(self, _mock_pull, _mock_output):
        result = check_commit_id("myremote", "abc123")
        self.assertTrue(result)

    @patch('software.ostree_utils.subprocess.check_output',
           return_value="other456\n")
    @patch('software.ostree_utils.pull_ostree_from_remote')
    def test_no_match(self, _mock_pull, _mock_output):
        result = check_commit_id("myremote", "abc123")
        self.assertFalse(result)

    @patch('software.ostree_utils.subprocess.check_output',
           side_effect=subprocess.CalledProcessError(1, "cmd"))
    @patch('software.ostree_utils.pull_ostree_from_remote')
    def test_parse_failure(self, _mock_pull, _mock_output):
        result = check_commit_id("myremote", "abc123")
        self.assertFalse(result)


class TestDeleteTemporaryRefsAndRemotes(unittest.TestCase):
    """Tests for delete_temporary_refs_and_remotes."""

    @patch('software.ostree_utils.subprocess.check_output',
           return_value="starlingx\n")
    def test_nothing_to_delete(self, _mock_output):
        result = delete_temporary_refs_and_remotes()
        self.assertTrue(result)

    @patch('software.ostree_utils.delete_ostree_remote')
    @patch('software.ostree_utils.delete_ostree_ref')
    @patch('software.ostree_utils.subprocess.check_output')
    def test_deletes_rel_entries(self, mock_output, mock_del_ref,
                                 mock_del_remote):
        mock_output.side_effect = [
            "rel-24.09:starlingx\nstarlingx\n",
            "debian\nrel-24.09\n"
        ]
        result = delete_temporary_refs_and_remotes()
        self.assertTrue(result)
        mock_del_ref.assert_called_once()
        mock_del_remote.assert_called_once()

    @patch('software.ostree_utils.subprocess.check_output',
           side_effect=subprocess.CalledProcessError(1, "cmd"))
    def test_list_failure(self, _mock_output):
        result = delete_temporary_refs_and_remotes()
        self.assertFalse(result)


class TestCheckoutLatestOstreeCommit(unittest.TestCase):
    """Tests for checkout_latest_ostree_commit."""

    @patch('software.ostree_utils.os.close')
    @patch('software.ostree_utils.os.open', return_value=5)
    @patch('software.ostree_utils.GLib')
    @patch('software.ostree_utils.OSTree.Repo')
    def test_glib_error(self, mock_repo_cls, mock_glib, _mock_open,
                        _mock_close):
        mock_repo = MagicMock()
        mock_repo_cls.new.return_value = mock_repo
        mock_repo.open.side_effect = mock_glib.Error("fail")
        self.assertRaises(Exception,  # noqa: H202
                          checkout_latest_ostree_commit, "22.06")


class TestWriteToFeedOstree(unittest.TestCase):
    """Tests for write_to_feed_ostree."""

    @patch('software.ostree_utils.GLib')
    @patch('software.ostree_utils.OSTree.Repo')
    @patch('software.ostree_utils.Gio.File')
    def test_glib_error(self, _mock_gio_file, mock_repo_cls, mock_glib):
        mock_repo = MagicMock()
        mock_repo_cls.new.return_value = mock_repo
        mock_repo.open.side_effect = mock_glib.Error("fail")
        self.assertRaises(Exception,  # noqa: H202
                          write_to_feed_ostree, "patch1", "22.06")


class TestOstreeLock(unittest.TestCase):
    """Tests for ostree_lock decorator."""

    @patch('software.ostree_utils.fcntl.flock')
    @patch('builtins.open', new_callable=mock_open)
    @patch('software.ostree_utils.constants.OSTREE_LOCK', "/tmp/test.lock")
    def test_lock_acquired_and_released(self, _mock_file, mock_flock):

        @with_ostree_lock
        def dummy():
            return "ok"

        result = dummy()
        self.assertEqual(result, "ok")
        # LOCK_EX then LOCK_UN
        calls = mock_flock.call_args_list
        self.assertEqual(calls[0][0][1], fcntl.LOCK_EX)
        self.assertEqual(calls[1][0][1], fcntl.LOCK_UN)

    @patch('software.ostree_utils.fcntl.flock')
    @patch('builtins.open', new_callable=mock_open)
    @patch('software.ostree_utils.constants.OSTREE_LOCK', "/tmp/test.lock")
    def test_lock_released_on_exception(self, _mock_file, mock_flock):

        @with_ostree_lock
        def failing():
            raise ValueError("boom")

        self.assertRaises(ValueError, failing)
        calls = mock_flock.call_args_list
        self.assertEqual(calls[1][0][1], fcntl.LOCK_UN)


class TestMountNewDeployment(unittest.TestCase):
    """Tests for mount_new_deployment."""

    @patch('software.ostree_utils.os.path.isdir', return_value=False)
    @patch('software.ostree_utils.create_bind_mount')
    def test_success(self, mock_bind, _mock_isdir):
        mount_new_deployment("/pending", "/active")
        self.assertEqual(mock_bind.call_count, 4)

    @patch('software.ostree_utils.sh.mount')
    @patch('software.ostree_utils.os.path.isdir', return_value=True)
    @patch('software.ostree_utils.create_bind_mount')
    def test_with_k8s(self, _mock_bind, _mock_isdir, mock_sh_mount):
        mount_new_deployment("/pending", "/active")
        self.assertEqual(mock_sh_mount.call_count, 2)
