#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for software.ostree_utils.

Every function here runs an external command and parses its output, or
manipulates the filesystem. Tests mock ONLY those boundaries
(subprocess / sh / os / shutil) and assert on the parsed result, the
command that was built, or the exception raised.
"""

import configparser
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from software.tests import base  # noqa: F401
from software import constants
from software import ostree_utils
from software.exceptions import OSTreeCommandFail


def _completed(stdout=b"", returncode=0):
    """Build a fake CompletedProcess with bytes stdout."""
    return mock.MagicMock(stdout=stdout, returncode=returncode)


def _completed_text(stdout="", returncode=0):
    """Build a fake CompletedProcess with text stdout."""
    return mock.MagicMock(stdout=stdout, returncode=returncode)


def _cpe(returncode=1, stderr=b"boom"):
    """Build a CalledProcessError with bytes stderr."""
    return subprocess.CalledProcessError(returncode, "cmd", stderr=stderr)


OSTREE_LOG_SAMPLE = (
    b"commit 478bc21c1702b9b667b5a75fac62a3ef9203cc1767cbe95e89dface6dc7f205e\n"
    b"ContentChecksum:  61fc5bb4398d73027595a4d839daeb404200d0899f6e7cdb24bb\n"
    b"Date:  2022-04-28 18:58:57 +0000\n"
    b"\n"
    b"Commit-id: starlingx-intel-x86-64-20220428185802\n"
    b"\n"
    b"commit ad7057a94a1d06e38eaedee2ce3fe56826ae817497469bce5d5ac05bc506aaa7\n"
    b"ContentChecksum:  dc42a42427a4f9e4de1210327c12b12ea3ad6a5d232497a903cc\n"
    b"Date:  2022-04-28 18:05:43 +0000\n"
)


class TestGetOstreeLatestCommit(unittest.TestCase):
    """get_ostree_latest_commit — parses first commit hash from ostree log."""

    @mock.patch('software.ostree_utils.subprocess.run')
    def test_returns_first_commit(self, mock_run):
        """The first commit hash in the log is returned."""
        mock_run.return_value = _completed(OSTREE_LOG_SAMPLE)
        result = ostree_utils.get_ostree_latest_commit("starlingx", "/repo")
        self.assertEqual(
            result,
            "478bc21c1702b9b667b5a75fac62a3ef9203cc1767cbe95e89dface6dc7f205e")

    @mock.patch('software.ostree_utils.subprocess.run')
    def test_builds_correct_command(self, mock_run):
        """Command includes the ref and repo path."""
        mock_run.return_value = _completed(OSTREE_LOG_SAMPLE)
        ostree_utils.get_ostree_latest_commit("myref", "/my/repo")
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd, "ostree log myref --repo=/my/repo")

    @mock.patch('software.ostree_utils.subprocess.run', side_effect=_cpe())
    def test_command_failure_raises(self, _mock_run):
        """CalledProcessError is converted to OSTreeCommandFail."""
        with self.assertRaises(OSTreeCommandFail) as ctx:
            ostree_utils.get_ostree_latest_commit("starlingx", "/repo")
        self.assertIn("/repo", str(ctx.exception))


class TestGetAllFeedCommits(unittest.TestCase):
    """get_all_feed_commits — parses every commit hash from grepped log."""

    @mock.patch('software.ostree_utils.subprocess.run')
    def test_returns_all_commits(self, mock_run):
        """All commit hashes are returned in order."""
        mock_run.return_value = _completed(
            b"commit aaa111\ncommit bbb222\ncommit ccc333\n")
        result = ostree_utils.get_all_feed_commits("24.09")
        self.assertEqual(result, ["aaa111", "bbb222", "ccc333"])

    @mock.patch('software.ostree_utils.subprocess.run')
    def test_single_commit(self, mock_run):
        """A single commit produces a one-element list."""
        mock_run.return_value = _completed(b"commit onlyone\n")
        self.assertEqual(ostree_utils.get_all_feed_commits("24.09"), ["onlyone"])

    @mock.patch('software.ostree_utils.subprocess.run')
    def test_blank_lines_skipped(self, mock_run):
        """Empty trailing lines do not produce entries."""
        mock_run.return_value = _completed(b"commit aaa\n\ncommit bbb\n\n")
        self.assertEqual(ostree_utils.get_all_feed_commits("24.09"),
                         ["aaa", "bbb"])

    @mock.patch('software.ostree_utils.subprocess.run')
    def test_repo_path_uses_release_version(self, mock_run):
        """Command targets the rel-<version> feed repo."""
        mock_run.return_value = _completed(b"commit aaa\n")
        ostree_utils.get_all_feed_commits("24.09")
        cmd = mock_run.call_args[0][0]
        self.assertIn("rel-24.09/ostree_repo", cmd)

    @mock.patch('software.ostree_utils.subprocess.run', side_effect=_cpe())
    def test_failure_raises(self, _mock_run):
        """Command failure raises OSTreeCommandFail."""
        with self.assertRaises(OSTreeCommandFail):
            ostree_utils.get_all_feed_commits("24.09")


class TestGetLatestDeploymentCommit(unittest.TestCase):
    """get_latest_deployment_commit — regex parse of ostree admin status."""

    @mock.patch('software.ostree_utils.subprocess.run')
    def test_extracts_commit_from_status(self, mock_run):
        """The deployment hash before '.N' is extracted."""
        mock_run.return_value = _completed(
            b"debian 0658a62854647b89caf5c0e9ed6ff62a6c98363ada137.0 (pending)\n"
            b"  origin refspec: starlingx\n")
        result = ostree_utils.get_latest_deployment_commit()
        self.assertEqual(result, "0658a62854647b89caf5c0e9ed6ff62a6c98363ada137")

    @mock.patch('software.ostree_utils.subprocess.run')
    def test_no_match_returns_none(self, mock_run):
        """Output without a deployment pattern returns None."""
        mock_run.return_value = _completed(b"no deployments here\n")
        self.assertIsNone(ostree_utils.get_latest_deployment_commit())

    @mock.patch('software.ostree_utils.subprocess.run')
    def test_empty_output_returns_none(self, mock_run):
        """Empty output returns None."""
        mock_run.return_value = _completed(b"")
        self.assertIsNone(ostree_utils.get_latest_deployment_commit())

    @mock.patch('software.ostree_utils.subprocess.run', side_effect=_cpe())
    def test_failure_raises(self, _mock_run):
        """Command failure raises OSTreeCommandFail."""
        with self.assertRaises(OSTreeCommandFail):
            ostree_utils.get_latest_deployment_commit()


class TestFetchDeployments(unittest.TestCase):
    """fetch_pending_deployment / fetch_active_deployment."""

    @mock.patch('software.ostree_utils.subprocess.run')
    def test_pending_returns_decoded_output(self, mock_run):
        """Pending deployment id is the decoded stdout."""
        mock_run.return_value = _completed(b"abc123.0")
        self.assertEqual(ostree_utils.fetch_pending_deployment(), "abc123.0")

    @mock.patch('software.ostree_utils.subprocess.run')
    def test_pending_empty_when_none(self, mock_run):
        """No pending deployment yields empty string."""
        mock_run.return_value = _completed(b"")
        self.assertEqual(ostree_utils.fetch_pending_deployment(), "")

    @mock.patch('software.ostree_utils.subprocess.run', side_effect=_cpe())
    def test_pending_failure_raises(self, _mock_run):
        """Command failure raises OSTreeCommandFail."""
        with self.assertRaises(OSTreeCommandFail):
            ostree_utils.fetch_pending_deployment()

    @mock.patch('software.ostree_utils.subprocess.run')
    def test_active_returns_decoded_output(self, mock_run):
        """Active deployment id is the decoded stdout."""
        mock_run.return_value = _completed(b"def456.1")
        self.assertEqual(ostree_utils.fetch_active_deployment(), "def456.1")

    @mock.patch('software.ostree_utils.subprocess.run', side_effect=_cpe())
    def test_active_failure_raises(self, _mock_run):
        """Command failure raises OSTreeCommandFail."""
        with self.assertRaises(OSTreeCommandFail):
            ostree_utils.fetch_active_deployment()


class TestSimpleOstreeCommands(unittest.TestCase):
    """update_repo_summary_file / reset_ostree_repo_head /
    delete_ostree_repo_commit / checkout_commit_to_dir — command building.
    """

    @mock.patch('software.ostree_utils.subprocess.run')
    def test_summary_command(self, mock_run):
        """Summary update targets the given repo."""
        ostree_utils.update_repo_summary_file("/my/repo")
        self.assertEqual(mock_run.call_args[0][0],
                         "ostree summary --update --repo=/my/repo")

    @mock.patch('software.ostree_utils.subprocess.run', side_effect=_cpe())
    def test_summary_failure_raises(self, _mock_run):
        """Summary failure raises OSTreeCommandFail."""
        with self.assertRaises(OSTreeCommandFail):
            ostree_utils.update_repo_summary_file("/my/repo")

    @mock.patch('software.ostree_utils.subprocess.run')
    def test_reset_head_command(self, mock_run):
        """Reset includes ref, commit and repo."""
        ostree_utils.reset_ostree_repo_head("commitX", "/my/repo")
        cmd = mock_run.call_args[0][0]
        self.assertIn(constants.OSTREE_REF, cmd)
        self.assertIn("commitX", cmd)
        self.assertIn("--repo=/my/repo", cmd)

    @mock.patch('software.ostree_utils.subprocess.run', side_effect=_cpe())
    def test_reset_head_failure_raises(self, _mock_run):
        """Reset failure raises OSTreeCommandFail."""
        with self.assertRaises(OSTreeCommandFail):
            ostree_utils.reset_ostree_repo_head("commitX", "/my/repo")

    @mock.patch('software.ostree_utils.subprocess.run')
    def test_delete_commit_command(self, mock_run):
        """Prune command deletes the given commit."""
        ostree_utils.delete_ostree_repo_commit("commitY", "/my/repo")
        cmd = mock_run.call_args[0][0]
        self.assertIn("prune --delete-commit commitY", cmd)
        self.assertIn("--repo=/my/repo", cmd)

    @mock.patch('software.ostree_utils.subprocess.run', side_effect=_cpe())
    def test_delete_commit_failure_raises(self, _mock_run):
        """Prune failure raises OSTreeCommandFail."""
        with self.assertRaises(OSTreeCommandFail):
            ostree_utils.delete_ostree_repo_commit("commitY", "/my/repo")

    @mock.patch('software.ostree_utils.subprocess.run')
    def test_checkout_without_subpath(self, mock_run):
        """Checkout without sub_path omits --subpath."""
        ostree_utils.checkout_commit_to_dir("/repo", "commitZ", "/dest")
        cmd = mock_run.call_args[0][0]
        self.assertIn("checkout --union --repo=/repo commitZ /dest", cmd)
        self.assertNotIn("--subpath", cmd)

    @mock.patch('software.ostree_utils.subprocess.run')
    def test_checkout_with_subpath(self, mock_run):
        """Checkout with sub_path appends --subpath."""
        ostree_utils.checkout_commit_to_dir("/repo", "commitZ", "/dest",
                                            sub_path="/usr/share")
        self.assertIn("--subpath=/usr/share", mock_run.call_args[0][0])

    @mock.patch('software.ostree_utils.subprocess.run', side_effect=_cpe())
    def test_checkout_failure_raises(self, _mock_run):
        """Checkout failure raises OSTreeCommandFail."""
        with self.assertRaises(OSTreeCommandFail):
            ostree_utils.checkout_commit_to_dir("/repo", "commitZ", "/dest")


class TestPullAuxRemote(unittest.TestCase):
    """pull_aux_remote — command building and error handling."""

    @mock.patch('software.ostree_utils.subprocess.run')
    def test_pull_command_targets_aux_remote(self, mock_run):
        """Pull references the aux remote and commit-metadata-only."""
        ostree_utils.pull_aux_remote("/ostree/repo")
        cmd = mock_run.call_args[0][0]
        self.assertIn(constants.OSTREE_AUX_REMOTE, cmd)
        self.assertIn("--commit-metadata-only", cmd)
        self.assertIn("--repo=/ostree/repo", cmd)

    @mock.patch('software.ostree_utils.subprocess.run', side_effect=_cpe())
    def test_pull_failure_raises(self, _mock_run):
        """Pull failure raises OSTreeCommandFail."""
        with self.assertRaises(OSTreeCommandFail):
            ostree_utils.pull_aux_remote("/ostree/repo")


class TestAddAuxRemote(unittest.TestCase):
    """add_aux_remote — command building, gpg disable calls."""

    @mock.patch('software.ostree_utils.add_gpg_verify_false')
    @mock.patch('software.ostree_utils.subprocess.run')
    def test_remote_add_command(self, mock_run, _mock_gpg):
        """Remote add uses the aux remote name and versioned feed URL."""
        ostree_utils.add_aux_remote("/ostree/repo", "24.09")
        cmd = mock_run.call_args[0][0]
        self.assertIn("remote add", cmd)
        self.assertIn(constants.OSTREE_AUX_REMOTE, cmd)
        self.assertIn("rel-24.09/ostree_repo", cmd)
        self.assertIn("--set=gpg-verify=false", cmd)

    @mock.patch('software.ostree_utils.add_gpg_verify_false')
    @mock.patch('software.ostree_utils.subprocess.run')
    def test_gpg_disabled_before_and_after(self, _mock_run, mock_gpg):
        """gpg-verify is disabled twice: before add and after."""
        ostree_utils.add_aux_remote("/ostree/repo", "24.09")
        self.assertEqual(mock_gpg.call_count, 2)

    @mock.patch('software.ostree_utils.add_gpg_verify_false')
    @mock.patch('software.ostree_utils.subprocess.run', side_effect=_cpe())
    def test_failure_raises(self, _mock_run, _mock_gpg):
        """Remote add failure raises OSTreeCommandFail."""
        with self.assertRaises(OSTreeCommandFail):
            ostree_utils.add_aux_remote("/ostree/repo", "24.09")


class TestGetFeedLatestCommit(unittest.TestCase):
    """get_feed_latest_commit — branches on aux-remote vs local feed."""

    @mock.patch('software.ostree_utils.get_ostree_latest_commit')
    def test_local_feed_path_built_from_version(self, mock_latest):
        """Non-aux path builds rel-<version> repo path and uses OSTREE_REF."""
        mock_latest.return_value = "commit1"
        result = ostree_utils.get_feed_latest_commit("24.09")
        self.assertEqual(result, "commit1")
        ref, path = mock_latest.call_args[0]
        self.assertEqual(ref, constants.OSTREE_REF)
        self.assertIn("rel-24.09/ostree_repo", path)

    @mock.patch('software.ostree_utils.get_ostree_latest_commit')
    @mock.patch('software.ostree_utils.pull_aux_remote')
    @mock.patch('software.ostree_utils.subprocess.run')
    def test_aux_remote_existing_skips_add(self, _mock_run, mock_pull, mock_latest):
        """When aux remote exists, add_aux_remote is not called."""
        mock_latest.return_value = "commit2"
        with mock.patch('software.ostree_utils.add_aux_remote') as mock_add:
            result = ostree_utils.get_feed_latest_commit(
                "24.09", repo_path=constants.OSTREE_AUX_REMOTE_PATH)
            mock_add.assert_not_called()
        self.assertEqual(result, "commit2")
        mock_pull.assert_called_once_with(constants.OSTREE_AUX_REMOTE_PATH)

    @mock.patch('software.ostree_utils.get_ostree_latest_commit')
    @mock.patch('software.ostree_utils.pull_aux_remote')
    @mock.patch('software.ostree_utils.add_aux_remote')
    @mock.patch('software.ostree_utils.subprocess.run', side_effect=_cpe())
    def test_aux_remote_missing_triggers_add(self, _mock_run, mock_add,
                                             _mock_pull, mock_latest):
        """When remote list check fails, the aux remote is added."""
        mock_latest.return_value = "commit3"
        ostree_utils.get_feed_latest_commit(
            "24.09", repo_path=constants.OSTREE_AUX_REMOTE_PATH)
        mock_add.assert_called_once_with(constants.OSTREE_AUX_REMOTE_PATH, "24.09")

    @mock.patch('software.ostree_utils.get_ostree_latest_commit')
    @mock.patch('software.ostree_utils.pull_aux_remote')
    @mock.patch('software.ostree_utils.subprocess.run')
    def test_aux_remote_uses_prefixed_ref(self, _mock_run, _mock_pull, mock_latest):
        """Aux path queries '<remote>:<ref>'."""
        mock_latest.return_value = "commit4"
        ostree_utils.get_feed_latest_commit(
            "24.09", repo_path=constants.OSTREE_AUX_REMOTE_PATH)
        ref, path = mock_latest.call_args[0]
        self.assertEqual(
            ref, "%s:%s" % (constants.OSTREE_AUX_REMOTE, constants.OSTREE_REF))
        self.assertEqual(path, constants.OSTREE_AUX_REMOTE_PATH)


class TestGetSysrootLatestCommit(unittest.TestCase):
    """get_sysroot_latest_commit — delegates with sysroot constants."""

    @mock.patch('software.ostree_utils.get_ostree_latest_commit')
    def test_uses_sysroot_ref_and_repo(self, mock_latest):
        """Sysroot ref and repo constants are passed through."""
        ostree_utils.get_sysroot_latest_commit()
        mock_latest.assert_called_once_with(constants.SYSROOT_OSTREE_REF,
                                            constants.SYSROOT_OSTREE)


class TestPullOstreeFromRemote(unittest.TestCase):
    """pull_ostree_from_remote — branches on remote given vs default."""

    @mock.patch('software.ostree_utils.add_gpg_verify_false')
    @mock.patch('software.ostree_utils.subprocess.run')
    def test_default_remote_no_mirror(self, mock_run, _mock_gpg):
        """Without a remote, pull uses OSTREE_REMOTE and no --mirror."""
        mock_run.return_value = _completed_text("done")
        ostree_utils.pull_ostree_from_remote()
        cmd = mock_run.call_args[0][0]
        self.assertIn(constants.OSTREE_REMOTE, cmd)
        self.assertNotIn("--mirror", cmd)
        # Only the pull command runs, no ref creation
        self.assertEqual(mock_run.call_count, 1)

    @mock.patch('software.ostree_utils.add_gpg_verify_false')
    @mock.patch('software.ostree_utils.subprocess.run')
    def test_named_remote_adds_mirror_and_ref(self, mock_run, _mock_gpg):
        """With a remote, pull adds --mirror and creates a ref."""
        mock_run.return_value = _completed_text("done")
        ostree_utils.pull_ostree_from_remote("rel-25.03")
        first_cmd = mock_run.call_args_list[0][0][0]
        second_cmd = mock_run.call_args_list[1][0][0]
        self.assertIn("--mirror", first_cmd)
        self.assertIn("rel-25.03:%s" % constants.OSTREE_REF, first_cmd)
        self.assertIn("refs --force --create=", second_cmd)
        self.assertEqual(mock_run.call_count, 2)

    @mock.patch('software.ostree_utils.add_gpg_verify_false')
    @mock.patch('software.ostree_utils.subprocess.run')
    def test_pull_failure_raises(self, mock_run, _mock_gpg):
        """Pull failure raises OSTreeCommandFail."""
        mock_run.side_effect = subprocess.CalledProcessError(
            1, "cmd", stderr="pull failed")
        with self.assertRaises(OSTreeCommandFail):
            ostree_utils.pull_ostree_from_remote()

    @mock.patch('software.ostree_utils.add_gpg_verify_false')
    @mock.patch('software.ostree_utils.subprocess.run')
    def test_ref_creation_failure_raises(self, mock_run, _mock_gpg):
        """Ref creation failure raises OSTreeCommandFail."""
        mock_run.side_effect = [
            _completed_text("pulled"),
            subprocess.CalledProcessError(1, "cmd", stderr="ref failed"),
        ]
        with self.assertRaises(OSTreeCommandFail):
            ostree_utils.pull_ostree_from_remote("rel-25.03")


class TestAddGpgVerifyFalse(unittest.TestCase):
    """add_gpg_verify_false — real configparser against a temp config."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _write_config(self, text):
        path = os.path.join(self.tmpdir, constants.OSTREE_CONFIG)
        with open(path, 'w') as f:
            f.write(text)
        return path

    def _read_config(self):
        cfg = configparser.ConfigParser()
        cfg.read(os.path.join(self.tmpdir, constants.OSTREE_CONFIG))
        return cfg

    def test_adds_gpg_verify_to_remote_section(self):
        """A remote section without gpg-verify gets it set to false."""
        self._write_config("[core]\nrepo_version=1\n\n[remote \"debian\"]\nurl=http://x\n")
        ostree_utils.add_gpg_verify_false(self.tmpdir)
        cfg = self._read_config()
        self.assertEqual(cfg['remote "debian"'][constants.OSTREE_GPG_VERIFY],
                         "false")

    def test_preserves_existing_gpg_verify(self):
        """An existing gpg-verify value is not overwritten."""
        self._write_config(
            "[remote \"debian\"]\nurl=http://x\ngpg-verify=true\n")
        ostree_utils.add_gpg_verify_false(self.tmpdir)
        cfg = self._read_config()
        self.assertEqual(cfg['remote "debian"'][constants.OSTREE_GPG_VERIFY],
                         "true")

    def test_non_remote_sections_untouched(self):
        """Sections not starting with 'remote ' are left alone."""
        self._write_config("[core]\nrepo_version=1\n")
        ostree_utils.add_gpg_verify_false(self.tmpdir)
        cfg = self._read_config()
        self.assertNotIn(constants.OSTREE_GPG_VERIFY, cfg["core"])

    def test_handles_multiple_remotes(self):
        """Every remote section gets gpg-verify=false."""
        self._write_config(
            "[remote \"debian\"]\nurl=http://a\n\n"
            "[remote \"rel-25.03\"]\nurl=http://b\n")
        ostree_utils.add_gpg_verify_false(self.tmpdir)
        cfg = self._read_config()
        self.assertEqual(cfg['remote "debian"'][constants.OSTREE_GPG_VERIFY],
                         "false")
        self.assertEqual(cfg['remote "rel-25.03"'][constants.OSTREE_GPG_VERIFY],
                         "false")

    def test_missing_config_raises(self):
        """A missing config file raises OSTreeCommandFail."""
        with self.assertRaises(OSTreeCommandFail) as ctx:
            ostree_utils.add_gpg_verify_false("/tmp/definitely_not_here_xyz")
        self.assertIn("does not exist", str(ctx.exception))


class TestAddOstreeRemote(unittest.TestCase):
    """add_ostree_remote — remote naming and URL scheme per nodetype."""

    @mock.patch('software.ostree_utils.pull_ostree_from_remote')
    @mock.patch('software.ostree_utils.add_gpg_verify_false')
    @mock.patch('software.ostree_utils.subprocess.check_call')
    def test_controller_uses_file_url(self, mock_call, _mock_gpg, _mock_pull):
        """Controller nodes get a file:// feed URL."""
        result = ostree_utils.add_ostree_remote("25.03", "controller")
        self.assertEqual(result, "rel-25.03")
        add_cmd = mock_call.call_args_list[1][0][0]
        self.assertIn("file://", " ".join(add_cmd))
        self.assertIn("rel-25.03", " ".join(add_cmd))

    @mock.patch('software.ostree_utils.pull_ostree_from_remote')
    @mock.patch('software.ostree_utils.add_gpg_verify_false')
    @mock.patch('software.ostree_utils.subprocess.check_call')
    def test_worker_uses_http_url(self, mock_call, _mock_gpg, _mock_pull):
        """Non-controller nodes get an http:// feed URL."""
        result = ostree_utils.add_ostree_remote("25.03", "worker")
        self.assertEqual(result, "rel-25.03")
        add_cmd = " ".join(mock_call.call_args_list[1][0][0])
        self.assertIn("http://", add_cmd)
        self.assertIn(constants.CONTROLLER_FLOATING_HOSTNAME, add_cmd)

    @mock.patch('software.ostree_utils.pull_ostree_from_remote')
    @mock.patch('software.ostree_utils.add_gpg_verify_false')
    @mock.patch('software.ostree_utils.subprocess.check_call')
    def test_replace_default_uses_default_remote_name(self, _mock_call,
                                                      _mock_gpg, _mock_pull):
        """replace_default_remote names the remote OSTREE_REMOTE."""
        result = ostree_utils.add_ostree_remote(
            "25.03", "controller", replace_default_remote=True)
        self.assertEqual(result, constants.OSTREE_REMOTE)

    @mock.patch('software.ostree_utils.pull_ostree_from_remote')
    @mock.patch('software.ostree_utils.add_gpg_verify_false')
    @mock.patch('software.ostree_utils.subprocess.check_call')
    def test_deletes_before_adding(self, mock_call, _mock_gpg, _mock_pull):
        """The remote is deleted first to work around an ostree bug."""
        ostree_utils.add_ostree_remote("25.03", "controller")
        delete_cmd = " ".join(mock_call.call_args_list[0][0][0])
        self.assertIn("remote delete --if-exists", delete_cmd)

    @mock.patch('software.ostree_utils.pull_ostree_from_remote')
    @mock.patch('software.ostree_utils.add_gpg_verify_false')
    @mock.patch('software.ostree_utils.subprocess.check_call',
                side_effect=subprocess.CalledProcessError(1, "cmd"))
    def test_failure_returns_none(self, _mock_call, _mock_gpg, _mock_pull):
        """Command failure returns None rather than raising."""
        self.assertIsNone(ostree_utils.add_ostree_remote("25.03", "controller"))

    @mock.patch('software.ostree_utils.pull_ostree_from_remote')
    @mock.patch('software.ostree_utils.add_gpg_verify_false')
    @mock.patch('software.ostree_utils.subprocess.check_call',
                side_effect=subprocess.CalledProcessError(1, "cmd"))
    def test_failure_skips_pull(self, _mock_call, _mock_gpg, mock_pull):
        """On failure the remote is not pulled."""
        ostree_utils.add_ostree_remote("25.03", "controller")
        mock_pull.assert_not_called()


class TestDeleteOstreeRemoteAndRef(unittest.TestCase):
    """delete_ostree_remote / delete_ostree_ref."""

    @mock.patch('software.ostree_utils.subprocess.check_call')
    def test_delete_remote_command(self, mock_call):
        """Delete remote passes --if-exists and the remote name."""
        ostree_utils.delete_ostree_remote("rel-25.03")
        self.assertEqual(mock_call.call_args[0][0],
                         ["ostree", "remote", "delete", "--if-exists",
                          "rel-25.03"])

    @mock.patch('software.ostree_utils.subprocess.check_call',
                side_effect=subprocess.CalledProcessError(1, "cmd"))
    def test_delete_remote_failure_reraises(self, _mock_call):
        """Delete remote failure propagates."""
        with self.assertRaises(subprocess.CalledProcessError):
            ostree_utils.delete_ostree_remote("rel-25.03")

    @mock.patch('software.ostree_utils.subprocess.check_call')
    def test_delete_ref_command(self, mock_call):
        """Delete ref passes --delete and the ref name."""
        ostree_utils.delete_ostree_ref("rel-25.03")
        self.assertEqual(mock_call.call_args[0][0],
                         ["ostree", "refs", "--delete", "rel-25.03"])

    @mock.patch('software.ostree_utils.subprocess.check_call',
                side_effect=subprocess.CalledProcessError(1, "cmd"))
    def test_delete_ref_failure_reraises(self, _mock_call):
        """Delete ref failure propagates."""
        with self.assertRaises(subprocess.CalledProcessError):
            ostree_utils.delete_ostree_ref("rel-25.03")


class TestCheckCommitId(unittest.TestCase):
    """check_commit_id — compares remote rev-parse output to expected."""

    @mock.patch('software.ostree_utils.pull_ostree_from_remote')
    @mock.patch('software.ostree_utils.subprocess.check_output')
    def test_matching_commit_returns_true(self, mock_out, _mock_pull):
        """Matching commit ids return True."""
        mock_out.return_value = "abc123\n"
        self.assertTrue(ostree_utils.check_commit_id("rel-25.03", "abc123"))

    @mock.patch('software.ostree_utils.pull_ostree_from_remote')
    @mock.patch('software.ostree_utils.subprocess.check_output')
    def test_mismatched_commit_returns_false(self, mock_out, _mock_pull):
        """Differing commit ids return False."""
        mock_out.return_value = "abc123\n"
        self.assertFalse(ostree_utils.check_commit_id("rel-25.03", "different"))

    @mock.patch('software.ostree_utils.pull_ostree_from_remote')
    @mock.patch('software.ostree_utils.subprocess.check_output')
    def test_rev_parse_target(self, mock_out, _mock_pull):
        """rev-parse targets '<remote>:<ref>'."""
        mock_out.return_value = "abc123"
        ostree_utils.check_commit_id("rel-25.03", "abc123")
        self.assertEqual(
            mock_out.call_args[0][0],
            ["ostree", "rev-parse", "rel-25.03:%s" % constants.OSTREE_REF])

    @mock.patch('software.ostree_utils.pull_ostree_from_remote')
    @mock.patch('software.ostree_utils.subprocess.check_output',
                side_effect=subprocess.CalledProcessError(1, "cmd"))
    def test_command_failure_returns_false(self, _mock_out, _mock_pull):
        """A rev-parse failure yields False, not an exception."""
        self.assertFalse(ostree_utils.check_commit_id("rel-25.03", "abc123"))

    @mock.patch('software.ostree_utils.pull_ostree_from_remote')
    @mock.patch('software.ostree_utils.subprocess.check_output')
    def test_pulls_before_checking(self, mock_out, mock_pull):
        """Remote metadata is pulled before comparing."""
        mock_out.return_value = "abc123"
        ostree_utils.check_commit_id("rel-25.03", "abc123")
        mock_pull.assert_called_once_with("rel-25.03")


class TestDeleteTemporaryRefsAndRemotes(unittest.TestCase):
    """delete_temporary_refs_and_remotes — filters by RELEASE_PREFIX."""

    @mock.patch('software.ostree_utils.delete_ostree_remote')
    @mock.patch('software.ostree_utils.delete_ostree_ref')
    @mock.patch('software.ostree_utils.subprocess.check_output')
    def test_deletes_only_prefixed_entries(self, mock_out, mock_del_ref,
                                           mock_del_remote):
        """Only refs/remotes containing the release prefix are deleted."""
        mock_out.side_effect = ["starlingx\nrel-25.03\n", "debian\nrel-25.03\n"]
        result = ostree_utils.delete_temporary_refs_and_remotes()
        self.assertTrue(result)
        mock_del_ref.assert_called_once_with("rel-25.03")
        mock_del_remote.assert_called_once_with("rel-25.03")

    @mock.patch('software.ostree_utils.delete_ostree_remote')
    @mock.patch('software.ostree_utils.delete_ostree_ref')
    @mock.patch('software.ostree_utils.subprocess.check_output')
    def test_nothing_to_delete_returns_true(self, mock_out, mock_del_ref,
                                            mock_del_remote):
        """No prefixed entries means nothing deleted, still True."""
        mock_out.side_effect = ["starlingx\n", "debian\n"]
        self.assertTrue(ostree_utils.delete_temporary_refs_and_remotes())
        mock_del_ref.assert_not_called()
        mock_del_remote.assert_not_called()

    @mock.patch('software.ostree_utils.delete_ostree_remote')
    @mock.patch('software.ostree_utils.delete_ostree_ref')
    @mock.patch('software.ostree_utils.subprocess.check_output',
                side_effect=subprocess.CalledProcessError(1, "cmd"))
    def test_listing_failure_returns_false(self, _mock_out, _mock_del_ref,
                                           _mock_del_remote):
        """Failure listing refs/remotes returns False."""
        self.assertFalse(ostree_utils.delete_temporary_refs_and_remotes())

    @mock.patch('software.ostree_utils.delete_ostree_remote')
    @mock.patch('software.ostree_utils.delete_ostree_ref',
                side_effect=Exception("nope"))
    @mock.patch('software.ostree_utils.subprocess.check_output')
    def test_ref_delete_failure_returns_false(self, mock_out, _mock_del_ref,
                                              _mock_del_remote):
        """A failed ref deletion makes the overall result False."""
        mock_out.side_effect = ["rel-25.03\n", "debian\n"]
        self.assertFalse(ostree_utils.delete_temporary_refs_and_remotes())

    @mock.patch('software.ostree_utils.delete_ostree_remote',
                side_effect=Exception("nope"))
    @mock.patch('software.ostree_utils.delete_ostree_ref')
    @mock.patch('software.ostree_utils.subprocess.check_output')
    def test_remote_delete_failure_returns_false(self, mock_out,
                                                 _mock_del_ref,
                                                 _mock_del_remote):
        """A failed remote deletion makes the overall result False."""
        mock_out.side_effect = ["starlingx\n", "rel-25.03\n"]
        self.assertFalse(ostree_utils.delete_temporary_refs_and_remotes())


class TestDeleteOlderDeployments(unittest.TestCase):
    """delete_older_deployments — parses status, picks indices to undeploy."""

    @mock.patch('software.ostree_utils.subprocess.run')
    def test_no_older_deployments_returns_true(self, mock_run):
        """Only an active deployment means nothing to delete."""
        mock_run.return_value = _completed_text("* debian aaa.0\n")
        self.assertTrue(ostree_utils.delete_older_deployments())
        self.assertEqual(mock_run.call_count, 1)

    @mock.patch('software.ostree_utils.subprocess.run')
    def test_deletes_after_active_skipping_rollback(self, mock_run):
        """Deployments after the active one are undeployed, rollback kept."""
        status = "* debian aaa.2\n  debian aaa.1 (rollback)\n  debian aaa.0\n"
        mock_run.side_effect = [
            _completed_text(status),
            _completed_text("undeployed"),
        ]
        self.assertTrue(ostree_utils.delete_older_deployments())
        undeploy_cmd = mock_run.call_args_list[1][0][0]
        self.assertIn("undeploy 2", undeploy_cmd)

    @mock.patch('software.ostree_utils.subprocess.run')
    def test_delete_pending_includes_pending_entry(self, mock_run):
        """delete_pending=True also undeploys the pending entry."""
        status = "  debian aaa.1 (pending)\n* debian aaa.0\n"
        mock_run.side_effect = [
            _completed_text(status),
            _completed_text("undeployed"),
        ]
        self.assertTrue(ostree_utils.delete_older_deployments(delete_pending=True))
        undeploy_cmd = mock_run.call_args_list[1][0][0]
        self.assertIn("undeploy 0", undeploy_cmd)

    @mock.patch('software.ostree_utils.subprocess.run')
    def test_status_failure_raises(self, mock_run):
        """Failure reading admin status raises OSTreeCommandFail."""
        mock_run.side_effect = _cpe()
        with self.assertRaises(OSTreeCommandFail):
            ostree_utils.delete_older_deployments()

    @mock.patch('software.ostree_utils.subprocess.run')
    def test_undeploy_failure_raises(self, mock_run):
        """Failure during undeploy raises OSTreeCommandFail."""
        status = "* debian aaa.1\n  debian aaa.0\n"
        mock_run.side_effect = [
            _completed_text(status),
            subprocess.CalledProcessError(1, "cmd", stderr="undeploy failed"),
        ]
        with self.assertRaises(OSTreeCommandFail):
            ostree_utils.delete_older_deployments()


class TestCreateDeployment(unittest.TestCase):
    """create_deployment — deploy command plus grub default update."""

    @mock.patch('software.ostree_utils.sync_boot_entries')
    @mock.patch('software.ostree_utils.subprocess.run')
    def test_default_ref_used(self, mock_run, _mock_sync):
        """Without a ref, the sysroot ref is deployed."""
        ostree_utils.create_deployment()
        deploy_cmd = mock_run.call_args_list[0][0][0]
        self.assertIn(constants.SYSROOT_OSTREE_REF, deploy_cmd)
        self.assertIn("--no-prune --retain", deploy_cmd)

    @mock.patch('software.ostree_utils.sync_boot_entries')
    @mock.patch('software.ostree_utils.subprocess.run')
    def test_explicit_ref_used(self, mock_run, _mock_sync):
        """An explicit ref is deployed instead of the default."""
        ostree_utils.create_deployment("myremote:starlingx")
        self.assertIn("myremote:starlingx", mock_run.call_args_list[0][0][0])

    @mock.patch('software.ostree_utils.sync_boot_entries')
    @mock.patch('software.ostree_utils.subprocess.run')
    def test_grub_default_set_to_zero(self, mock_run, _mock_sync):
        """The grub default entry is set to 0 after deploying."""
        ostree_utils.create_deployment()
        boot_cmd = mock_run.call_args_list[1][0][0]
        self.assertEqual(boot_cmd,
                         ["grub-editenv", "/boot/efi/EFI/BOOT/boot.env",
                          "set", "default=0"])

    @mock.patch('software.ostree_utils.sync_boot_entries')
    @mock.patch('software.ostree_utils.subprocess.run')
    def test_boot_entries_synced_first(self, _mock_run, mock_sync):
        """Boot entries are synced before deploying."""
        ostree_utils.create_deployment()
        mock_sync.assert_called_once()

    @mock.patch('software.ostree_utils.sync_boot_entries')
    @mock.patch('software.ostree_utils.subprocess.run', side_effect=_cpe())
    def test_deploy_failure_raises(self, _mock_run, _mock_sync):
        """Deploy failure raises OSTreeCommandFail."""
        with self.assertRaises(OSTreeCommandFail):
            ostree_utils.create_deployment()


class TestSyncBootEntries(unittest.TestCase):
    """sync_boot_entries — copies entries only when they differ."""

    @mock.patch('software.ostree_utils.shutil.copytree')
    @mock.patch('software.ostree_utils.shutil.rmtree')
    @mock.patch('software.ostree_utils.os.listdir')
    def test_identical_entries_no_copy(self, mock_ls, mock_rm, mock_copy):
        """Matching directory contents means no copy."""
        mock_ls.side_effect = [["a.conf"], ["a.conf"]]
        ostree_utils.sync_boot_entries()
        mock_rm.assert_not_called()
        mock_copy.assert_not_called()

    @mock.patch('software.ostree_utils.shutil.copytree')
    @mock.patch('software.ostree_utils.shutil.rmtree')
    @mock.patch('software.ostree_utils.os.listdir')
    def test_differing_entries_trigger_copy(self, mock_ls, mock_rm, mock_copy):
        """Differing contents replace /boot/loader/entries."""
        mock_ls.side_effect = [["a.conf"], ["a.conf", "b.conf"]]
        ostree_utils.sync_boot_entries()
        mock_rm.assert_called_once_with("/boot/loader/entries/")
        mock_copy.assert_called_once_with("/boot/loader.0/entries/",
                                          "/boot/loader/entries/")

    @mock.patch('software.ostree_utils.os.listdir',
                side_effect=FileNotFoundError("missing"))
    def test_missing_dir_is_swallowed(self, _mock_ls):
        """A missing directory is logged, not raised."""
        ostree_utils.sync_boot_entries()


class TestCreateBindMount(unittest.TestCase):
    """create_bind_mount — retries once before failing."""

    @mock.patch('software.ostree_utils.sh')
    def test_successful_mount_no_retry(self, mock_sh):
        """A successful mount is attempted once."""
        ostree_utils.create_bind_mount("/src", "/tgt")
        self.assertEqual(mock_sh.mount.call_count, 1)

    @mock.patch('software.ostree_utils.sh')
    def test_default_permissions_read_only(self, mock_sh):
        """Default permissions are read-only."""
        ostree_utils.create_bind_mount("/src", "/tgt")
        args = mock_sh.mount.call_args[0]
        self.assertIn(constants.READ_ONLY_PERMISSION, args)

    @mock.patch('software.ostree_utils.sh')
    def test_explicit_permissions_passed(self, mock_sh):
        """Explicit permissions are forwarded to mount."""
        ostree_utils.create_bind_mount("/src", "/tgt",
                                       constants.READ_WRITE_PERMISSION)
        args = mock_sh.mount.call_args[0]
        self.assertIn(constants.READ_WRITE_PERMISSION, args)


class TestOstreeLockDecorator(unittest.TestCase):
    """ostree_lock — runs the wrapped function and returns its value."""

    @mock.patch('software.ostree_utils.fcntl.flock')
    def test_returns_wrapped_result(self, _mock_flock):
        """The decorated function's return value is passed through."""
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.close()
        with mock.patch('software.ostree_utils.constants.OSTREE_LOCK', tmp.name):
            @ostree_utils.with_ostree_lock
            def my_func():
                return "result"
            self.assertEqual(my_func(), "result")
        os.unlink(tmp.name)

    @mock.patch('software.ostree_utils.fcntl.flock')
    def test_forwards_arguments(self, _mock_flock):
        """Positional and keyword arguments reach the wrapped function."""
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.close()
        with mock.patch('software.ostree_utils.constants.OSTREE_LOCK', tmp.name):
            @ostree_utils.with_ostree_lock
            def my_func(a, b=None):
                return (a, b)
            self.assertEqual(my_func(1, b=2), (1, 2))
        os.unlink(tmp.name)

    @mock.patch('software.ostree_utils.fcntl.flock')
    def test_releases_lock_on_exception(self, mock_flock):
        """The lock is released even when the function raises."""
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.close()
        with mock.patch('software.ostree_utils.constants.OSTREE_LOCK', tmp.name):
            @ostree_utils.with_ostree_lock
            def my_func():
                raise ValueError("boom")
            with self.assertRaises(ValueError):
                my_func()
        # LOCK_EX then LOCK_UN
        self.assertEqual(mock_flock.call_count, 2)
        os.unlink(tmp.name)


class TestAddTombstoneCommitIfPrepatched(unittest.TestCase):
    """add_tombstone_commit_if_prepatched — history check and tombstone file."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    @mock.patch('software.ostree_utils.subprocess.run')
    def test_complete_history_returns_false(self, mock_run):
        """Full history means no tombstone is needed."""
        mock_run.return_value = _completed(b"commit aaa\nParent: bbb\n")
        result = ostree_utils.add_tombstone_commit_if_prepatched(
            "starlingx", self.tmpdir)
        self.assertFalse(result)

    @mock.patch('software.ostree_utils.subprocess.run')
    def test_incomplete_history_creates_tombstone(self, mock_run):
        """Truncated history creates a tombstone file and returns True."""
        parent = "abcdef1234567890"
        log = (b"commit aaa\n"
               b"Parent:  " + parent.encode() + b"\n"
               b"<< History beyond this commit not fetched >>\n")
        mock_run.return_value = _completed(log)
        # config must exist for the config update branch
        with open(os.path.join(self.tmpdir, "config"), 'w') as f:
            f.write("[core]\nrepo_version=1\n")

        result = ostree_utils.add_tombstone_commit_if_prepatched(
            "starlingx", self.tmpdir)
        self.assertTrue(result)
        tombstone = os.path.join(self.tmpdir, "objects", parent[:2],
                                 parent[2:] + ".tombstone-commit")
        self.assertTrue(os.path.isfile(tombstone))

    @mock.patch('software.ostree_utils.subprocess.run')
    def test_config_gets_tombstone_commits_true(self, mock_run):
        """The repo config gains tombstone-commits=true."""
        parent = "abcdef1234567890"
        log = (b"Parent:  " + parent.encode() + b"\n"
               b"<< History beyond this commit not fetched >>\n")
        mock_run.return_value = _completed(log)
        config_path = os.path.join(self.tmpdir, "config")
        with open(config_path, 'w') as f:
            f.write("[core]\nrepo_version=1\n")

        ostree_utils.add_tombstone_commit_if_prepatched("starlingx", self.tmpdir)
        cfg = configparser.ConfigParser()
        cfg.read(config_path)
        self.assertEqual(cfg["core"]["tombstone-commits"], "true")

    @mock.patch('software.ostree_utils.subprocess.run')
    def test_existing_tombstone_returns_false(self, mock_run):
        """An already-present tombstone file returns False."""
        parent = "abcdef1234567890"
        log = (b"Parent:  " + parent.encode() + b"\n"
               b"<< History beyond this commit not fetched >>\n")
        mock_run.return_value = _completed(log)
        obj_dir = os.path.join(self.tmpdir, "objects", parent[:2])
        os.makedirs(obj_dir)
        open(os.path.join(obj_dir, parent[2:] + ".tombstone-commit"), 'w').close()

        result = ostree_utils.add_tombstone_commit_if_prepatched(
            "starlingx", self.tmpdir)
        self.assertFalse(result)

    @mock.patch('software.ostree_utils.subprocess.run')
    def test_incomplete_history_without_parent_returns_false(self, mock_run):
        """Truncated history with no Parent line returns False."""
        mock_run.return_value = _completed(
            b"<< History beyond this commit not fetched >>\n")
        result = ostree_utils.add_tombstone_commit_if_prepatched(
            "starlingx", self.tmpdir)
        self.assertFalse(result)

    @mock.patch('software.ostree_utils.subprocess.run', side_effect=_cpe())
    def test_log_failure_raises(self, _mock_run):
        """A failed ostree log raises OSTreeCommandFail."""
        with self.assertRaises(OSTreeCommandFail):
            ostree_utils.add_tombstone_commit_if_prepatched(
                "starlingx", self.tmpdir)
