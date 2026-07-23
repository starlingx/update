#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from unittest.mock import PropertyMock
from unittest.mock import MagicMock
from unittest.mock import patch
import unittest
from software.tests import base  # noqa: F401
from software.software_controller import PatchController
from software import constants
from software import states
import software.software_controller as mod

RC = 'software.software_controller.PatchController.release_collection'
WSF = 'software.software_controller.PatchController.write_state_file'


def make_sc():
    sc = PatchController.__new__(PatchController)
    sc.base_pkgdata = MagicMock()
    sc.hosts = {}
    sc.hosts_lock = MagicMock()
    sc.controller_neighbours = {}
    sc.controller_neighbours_lock = MagicMock()
    sc.socket_lock = MagicMock()
    sc.sock_out = None
    sc.install_local = False
    sc.patch_op_counter = 0
    sc.interim_state = {}
    sc.hostname = 'ctrl-0'
    sc.fm_api = MagicMock()
    sc.db_api_instance = MagicMock()
    return sc


class TestPatchCommit(unittest.TestCase):
    @patch('software.software_controller.reload_release_data')
    @patch('software.software_controller.os.path.exists', return_value=True)
    @patch(RC, new_callable=PropertyMock)
    def test_commit_non_rel(self, mock_rc, _mock_exists, _mock_reload):
        sc = make_sc()
        rel = MagicMock()
        rel.status = 'DEV'
        rel.id = 'r1'
        mock_rc.return_value.iterate_releases.return_value = [rel]
        result = sc.patch_commit(['r1'])
        self.assertIn('non-REL', result['error'])

    @patch('software.software_controller.reload_release_data')
    @patch('software.software_controller.os.path.exists', return_value=True)
    @patch(RC, new_callable=PropertyMock)
    def test_commit_unknown_id(self, mock_rc, _mock_exists, _mock_reload):
        sc = make_sc()
        mock_rc.return_value.iterate_releases.return_value = []
        mock_rc.return_value.get_release_by_id.return_value = None
        result = sc.patch_commit(['r1'])
        self.assertIn('unrecognized', result['error'])

    @patch('software.software_controller.reload_release_data')
    @patch('software.software_controller.shutil.move')
    @patch('software.software_controller.os.path.exists', return_value=True)
    @patch(RC, new_callable=PropertyMock)
    def test_commit_success(
            self,
            mock_rc,
            _mock_exists,
            _mock_move,
            _mock_reload):
        sc = make_sc()
        rel = MagicMock()
        rel.status = constants.STATUS_RELEASED
        rel.id = 'r1'
        rel.state = states.DEPLOYED
        rel.requires_release_ids = []
        mock_rc.return_value.iterate_releases.return_value = [rel]
        mock_rc.return_value.get_release_by_id.return_value = rel
        result = sc.patch_commit(['r1'])
        self.assertIn('committed', result['info'])

    @patch('software.software_controller.reload_release_data')
    @patch('software.software_controller.os.path.exists', return_value=True)
    @patch(RC, new_callable=PropertyMock)
    def test_commit_not_deployed(self, mock_rc, _mock_exists, _mock_reload):
        sc = make_sc()
        rel = MagicMock()
        rel.status = constants.STATUS_RELEASED
        rel.id = 'r1'
        rel.state = states.AVAILABLE
        rel.requires_release_ids = []
        mock_rc.return_value.iterate_releases.return_value = [rel]
        mock_rc.return_value.get_release_by_id.return_value = rel
        result = sc.patch_commit(['r1'])
        self.assertIn('not applied', result['error'])

    @patch('software.software_controller.reload_release_data')
    @patch('software.software_controller.os.path.exists', return_value=True)
    @patch(RC, new_callable=PropertyMock)
    def test_commit_dry_run(self, mock_rc, _mock_exists, _mock_reload):
        sc = make_sc()
        rel = MagicMock()
        rel.status = constants.STATUS_RELEASED
        rel.id = 'r1'
        rel.state = states.DEPLOYED
        rel.requires_release_ids = []
        mock_rc.return_value.iterate_releases.return_value = [rel]
        mock_rc.return_value.get_release_by_id.return_value = rel
        result = sc.patch_commit(['r1'], dry_run=True)
        self.assertIn('MiB', result['info'])


class TestQueryHostCache(unittest.TestCase):
    def test_empty(self):
        sc = make_sc()
        old_sc = mod.sc
        mod.sc = sc
        try:
            result = sc.query_host_cache()
            self.assertEqual(result, [])
        finally:
            mod.sc = old_sc

    def test_with_hosts(self):
        sc = make_sc()
        host = MagicMock()
        host.get_dict.return_value = {'hostname': 'w-0', 'state': 'idle'}
        sc.hosts = {'w-0': host}
        sc.interim_state = {}
        old_sc = mod.sc
        mod.sc = sc
        try:
            result = sc.query_host_cache()
            self.assertEqual(len(result), 1)
            self.assertFalse(result[0]['interim_state'])
        finally:
            mod.sc = old_sc

    def test_with_interim(self):
        sc = make_sc()
        host = MagicMock()
        host.get_dict.return_value = {'hostname': 'w-0', 'state': 'installing'}
        sc.hosts = {'w-0': host}
        sc.interim_state = {'r1': ['w-0']}
        old_sc = mod.sc
        mod.sc = sc
        try:
            result = sc.query_host_cache()
            self.assertTrue(result[0]['interim_state'])
        finally:
            mod.sc = old_sc


class TestGetDependencies(unittest.TestCase):
    @patch(RC, new_callable=PropertyMock)
    def test_recursive(self, mock_rc):
        sc = make_sc()
        r1 = MagicMock(id='r1', requires=['r0'])
        r0 = MagicMock(id='r0', requires=[])
        mock_rc.return_value.get_release_by_id.side_effect = {
            'r1': r1, 'r0': r0}.get
        result = sc.get_dependencies(['r1'], True)
        self.assertIn('r0', result)
        self.assertIn('r1', result)

    @patch(RC, new_callable=PropertyMock)
    def test_no_requirements_returns_input(self, mock_rc):
        sc = make_sc()
        r1 = MagicMock(id='r1', requires=[])
        mock_rc.return_value.get_release_by_id.return_value = r1
        result = sc.get_dependencies(['r1'], False)
        self.assertEqual(result, ['r1'])

    @patch(RC, new_callable=PropertyMock)
    def test_non_recursive_stops_at_direct_requirements(self, mock_rc):
        """recursive=False collects direct requirements but does not
        follow the chain beyond them.
            """
        sc = make_sc()
        r2 = MagicMock(id='r2', requires=['r1'])
        r1 = MagicMock(id='r1', requires=['r0'])
        r0 = MagicMock(id='r0', requires=[])
        mock_rc.return_value.get_release_by_id.side_effect = {
            'r2': r2, 'r1': r1, 'r0': r0}.get
        result = sc.get_dependencies(['r2'], False)
        # r1 is a direct requirement of r2; r0 is only reachable via r1
        self.assertEqual(result, ['r1', 'r2'])
        self.assertNotIn('r0', result)

    @patch(RC, new_callable=PropertyMock)
    def test_recursive_follows_full_chain(self, mock_rc):
        """recursive=True walks the whole requirement chain."""
        sc = make_sc()
        r2 = MagicMock(id='r2', requires=['r1'])
        r1 = MagicMock(id='r1', requires=['r0'])
        r0 = MagicMock(id='r0', requires=[])
        mock_rc.return_value.get_release_by_id.side_effect = {
            'r2': r2, 'r1': r1, 'r0': r0}.get
        result = sc.get_dependencies(['r2'], True)
        self.assertEqual(result, ['r0', 'r1', 'r2'])

    @patch(RC, new_callable=PropertyMock)
    def test_result_is_sorted_and_deduplicated(self, mock_rc):
        """Shared requirements appear once, output is sorted."""
        sc = make_sc()
        rb = MagicMock(id='rb', requires=['ra'])
        rc_ = MagicMock(id='rc', requires=['ra'])
        ra = MagicMock(id='ra', requires=[])
        mock_rc.return_value.get_release_by_id.side_effect = {
            'rb': rb, 'rc': rc_, 'ra': ra}.get
        result = sc.get_dependencies(['rc', 'rb'], True)
        self.assertEqual(result, ['ra', 'rb', 'rc'])


class TestPatchQueryDependencies(unittest.TestCase):
    @patch(RC, new_callable=PropertyMock)
    def test_query(self, mock_rc):
        sc = make_sc()
        r1 = MagicMock(id='r1', requires_release_ids=[])
        mock_rc.return_value.get_release_by_id.return_value = r1
        result = sc.patch_query_dependencies(['r1'])
        self.assertIn('patches', result)

    @patch(RC, new_callable=PropertyMock)
    def test_query_not_found(self, mock_rc):
        sc = make_sc()
        mock_rc.return_value.get_release_by_id.return_value = None
        result = sc.patch_query_dependencies(['r1'])
        self.assertIn('error', result)


class TestCopyInstallScripts(unittest.TestCase):
    @patch('software.software_controller.shutil.copyfile')
    @patch('software.software_controller.os.chmod')
    @patch('software.software_controller.os.makedirs')
    @patch('software.software_controller.os.path.exists', return_value=False)
    @patch(RC, new_callable=PropertyMock)
    def test_deploying_release(
            self,
            mock_rc,
            _mock_exists,
            _mock_mkdirs,
            _mock_chmod,
            mock_copy):
        sc = make_sc()
        rel = MagicMock()
        rel.id = 'r1'
        rel.state = states.DEPLOYING
        rel.pre_install = 'pre.sh'
        rel.post_install = 'post.sh'
        mock_rc.return_value.iterate_releases.return_value = [rel]
        sc.copy_install_scripts()
        self.assertTrue(mock_copy.called)

    @patch('software.software_controller.os.path.exists', return_value=True)
    @patch('software.software_controller.os.remove')
    @patch(RC, new_callable=PropertyMock)
    def test_non_deploying_cleanup(self, mock_rc, mock_rm, _mock_exists):
        sc = make_sc()
        rel = MagicMock()
        rel.id = 'r1'
        rel.state = states.DEPLOYED
        rel.pre_install = 'pre.sh'
        rel.post_install = 'post.sh'
        mock_rc.return_value.iterate_releases.return_value = [rel]
        sc.copy_install_scripts()
        self.assertTrue(mock_rm.called)
