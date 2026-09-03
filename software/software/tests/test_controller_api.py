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
from software.exceptions import SoftwareServiceError

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


class TestInstallLocal(unittest.TestCase):
    @patch('software.software_controller.get_instance')
    @patch('software.software_controller.os.path.isfile', return_value=False)
    def test_deploy_in_progress(self, _mock_isfile, mock_db):
        sc = make_sc()
        mock_db.return_value.get_deploy_all.return_value = [{'state': 'x'}]
        result = sc.software_install_local_api(False)
        self.assertIn('in progress', result['info'])

    @patch('software.software_controller.get_instance')
    @patch('software.software_controller.os.path.isfile', return_value=False)
    @patch('software.software_controller.INSTALL_LOCAL_FLAG', '/tmp/test_flag')
    def test_start(self, _mock_isfile, mock_db):
        sc = make_sc()
        mock_db.return_value.get_deploy_all.return_value = []
        with patch('builtins.open', unittest.mock.mock_open()):
            result = sc.software_install_local_api(False)
        self.assertIn('started', result['info'])

    @patch('software.software_controller.get_instance')
    @patch('software.software_controller.os.path.isfile', return_value=True)
    @patch('software.software_controller.os.remove')
    @patch('software.software_controller.INSTALL_LOCAL_FLAG', '/tmp/test_flag')
    def test_delete(self, _mock_remove, _mock_isfile, mock_db):
        sc = make_sc()
        mock_db.return_value.get_deploy_all.return_value = []
        result = sc.software_install_local_api(True)
        self.assertIn('stopped', result['info'])

    @patch('software.software_controller.get_instance')
    @patch('software.software_controller.os.path.isfile', return_value=True)
    def test_already_enabled(self, _mock_isfile, mock_db):
        sc = make_sc()
        mock_db.return_value.get_deploy_all.return_value = []
        result = sc.software_install_local_api(False)
        self.assertIn('already', result['info'])


class TestQueryCached(unittest.TestCase):
    @patch(RC, new_callable=PropertyMock)
    def test_no_filter(self, mock_rc):
        sc = make_sc()
        rel = MagicMock()
        rel.to_query_dict.return_value = {'id': 'r1', 'state': 'deployed'}
        mock_rc.return_value.iterate_releases.return_value = [rel]
        self.assertEqual(len(sc.software_release_query_cached()), 1)

    @patch(RC, new_callable=PropertyMock)
    def test_specific(self, mock_rc):
        sc = make_sc()
        rel = MagicMock()
        rel.to_query_dict.return_value = {'id': 'r1'}
        mock_rc.return_value.get_release_by_id.return_value = rel
        self.assertEqual(
            len(sc.software_release_query_specific_cached(['r1'])), 1)

    @patch(RC, new_callable=PropertyMock)
    def test_specific_not_found(self, mock_rc):
        sc = make_sc()
        mock_rc.return_value.get_release_by_id.return_value = None
        self.assertEqual(
            len(sc.software_release_query_specific_cached(['r1'])), 0)


class TestSync(unittest.TestCase):
    @patch(WSF)
    def test_no_socket(self, _mock_w):
        sc = make_sc()
        self.assertTrue(sc.software_sync())

    @patch(WSF)
    def test_install_local(self, _mock_w):
        sc = make_sc()
        sc.sock_out = MagicMock()
        sc.install_local = True
        self.assertTrue(sc.software_sync())


class TestDeployAPIs(unittest.TestCase):
    @patch('software.software_controller.get_instance')
    def test_host_list(self, _mock_db):
        sc = make_sc()
        sc.db_api_instance.get_deploy_host.return_value = [{'hostname': 'c0'}]
        self.assertEqual(len(sc.deploy_host_list()), 1)

    def test_any_installing_false(self):
        sc = make_sc()
        sc.hosts = {'h1': MagicMock(state='idle')}
        self.assertFalse(sc.any_patch_host_installing())

    @patch('software.software_controller.get_instance')
    def test_upgrade_none(self, mock_db):
        sc = make_sc()
        sc.db_api_instance = mock_db.return_value
        mock_db.return_value.get_deploy_all.return_value = []
        self.assertIsNone(sc.get_software_upgrade())

    @patch('software.software_controller.get_instance')
    def test_upgrade_exists(self, mock_db):
        sc = make_sc()
        sc.db_api_instance = mock_db.return_value
        mock_db.return_value.get_deploy_all.return_value = [
            {'from_release': 'a', 'to_release': 'b', 'state': 'start'}
        ]
        self.assertIsNotNone(sc.get_software_upgrade())


class TestDeleteAPI(unittest.TestCase):
    @patch(RC, new_callable=PropertyMock)
    def test_not_found(self, mock_rc):
        sc = make_sc()
        mock_rc.return_value.get_release_by_id.return_value = None
        with self.assertRaises(SoftwareServiceError):
            sc.software_release_delete_api(['r1'])

    @patch(RC, new_callable=PropertyMock)
    def test_not_deletable(self, mock_rc):
        sc = make_sc()
        rel = MagicMock()
        rel.is_deletable = False
        mock_rc.return_value.get_release_by_id.return_value = rel
        with self.assertRaises(SoftwareServiceError):
            sc.software_release_delete_api(['r1'])


class TestMisc(unittest.TestCase):
    @patch(WSF)
    def test_inc_counter(self, _mock_w):
        sc = make_sc()
        sc.inc_patch_op_counter()
        self.assertEqual(sc.patch_op_counter, 1)

    @patch('software.software_controller.package_dir', {'24.09': '/pkg'})
    def test_get_ostree_tar(self):
        sc = make_sc()
        result = sc.get_ostree_tar_filename('24.09', 'P1')
        self.assertIn('P1', result)

    @patch(RC, new_callable=PropertyMock)
    def test_query_what_requires(self, mock_rc):
        sc = make_sc()
        rel = MagicMock()
        rel.requires_release_ids = ['r1']
        rel.id = 'r2'
        mock_rc.return_value.iterate_releases.return_value = iter([rel])
        result = sc.patch_query_what_requires(['r1'])
        self.assertIn('r1', result['info'])

    @patch(RC, new_callable=PropertyMock)
    def test_dependency_no_deps(self, mock_rc):
        sc = make_sc()
        rel = MagicMock()
        rel.requires_release_ids = []
        mock_rc.return_value.get_release_by_id.return_value = rel
        self.assertEqual(sc.get_release_dependency_list('r1'), [])
