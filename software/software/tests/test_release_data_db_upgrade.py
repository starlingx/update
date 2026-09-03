#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for modules:
release_data, db.api, deploy_state,
deploy_host_state, utilities.utils.
"""

import os
import shutil
import subprocess
import unittest
from unittest import mock

from software.tests import base  # noqa: F401
from software.exceptions import InvalidOperation
from software.states import DEPLOY_HOST_STATES
from software.release_data import SWRelease
from software.exceptions import FileSystemError
from software.release_data import SWReleaseCollection
from software.release_data import LocalStorage
from software.release_data import get_SWReleaseCollection
from software.release_data import _local_storage
from software.release_data import reload_release_data
from software.db.api import SoftwareAPI
from software.db.api import get_instance
from software.deploy_host_state import DeployHostState
from software.utilities.utils import get_db_connection
from software.utilities.utils import get_password_from_keyring
from software.utilities.utils import get_upgrade_token
from software.utilities.utils import get_upgrade_data
from software.utilities.utils import apply_upgrade_manifest
from software.utilities.utils import get_keystone_user_id
from software.utilities.utils import get_keystone_project_id
from software.utilities.utils import get_postgres_bin
from software.utilities.utils import create_manifest_runtime_config
from software.utilities.utils import create_system_config
from software.utilities.utils import create_host_config
from software.utilities.utils import add_upgrade_entries_to_hiera_data


class TestSWRelease(unittest.TestCase):
    """Tests for SWRelease properties and methods."""

    def _make_release(self, rel_id='starlingx-24.09.0',
                      state='available', extra_meta=None,
                      contents=None):
        meta = {'sw_version': '24.09.0', 'state': state}
        if extra_meta:
            meta.update(extra_meta)
        if contents is None:
            contents = {}
        return SWRelease(rel_id, meta, contents)

    def test_basic_properties(self):
        rel = self._make_release()
        self.assertEqual(rel.id, 'starlingx-24.09.0')
        self.assertEqual(rel.state, 'available')
        self.assertEqual(rel.sw_release, '24.09.0')
        self.assertEqual(rel.sw_version, '24.09')

    def test_is_ga_release_true(self):
        rel = self._make_release()
        self.assertTrue(rel.is_ga_release)

    def test_is_ga_release_false(self):
        rel = self._make_release(extra_meta={'sw_version': '24.09.1'})
        self.assertFalse(rel.is_ga_release)

    def test_is_ga_release_two_part(self):
        rel = self._make_release(extra_meta={'sw_version': '24.09'})
        self.assertTrue(rel.is_ga_release)

    def test_prepatched_iso_true(self):
        rel = self._make_release(extra_meta={'prepatched_iso': 'Y'})
        self.assertTrue(rel.prepatched_iso)

    def test_prepatched_iso_false(self):
        rel = self._make_release()
        self.assertFalse(rel.prepatched_iso)

    def test_unremovable(self):
        rel = self._make_release(extra_meta={'unremovable': 'Y'})
        self.assertTrue(rel.unremovable)

    def test_reboot_required(self):
        rel = self._make_release(extra_meta={'reboot_required': 'Y'})
        self.assertTrue(rel.reboot_required)

    def test_optional_properties_default(self):
        rel = self._make_release()
        self.assertIsNone(rel.summary)
        self.assertIsNone(rel.description)
        self.assertIsNone(rel.install_instructions)
        self.assertIsNone(rel.warnings)
        self.assertIsNone(rel.status)
        self.assertIsNone(rel.component)
        self.assertEqual(rel.packages, [])
        self.assertEqual(rel.activation_scripts, [])
        self.assertIsNone(rel.pre_start)
        self.assertIsNone(rel.post_start)
        self.assertIsNone(rel.pre_install)
        self.assertIsNone(rel.post_install)
        self.assertIsNone(rel.apply_active_release_only)
        self.assertEqual(rel.requires_release_ids, [])
        self.assertEqual(rel.preinstalled_patches, [])

    def test_commit_id_with_commits(self):
        contents = {
            'number_of_commits': '1',
            'commit1': {'commit': 'abc123', 'checksum': 'sha256'}
        }
        rel = self._make_release(contents=contents)
        self.assertEqual(rel.commit_id, 'abc123')
        self.assertEqual(rel.commit_checksum, 'sha256')

    def test_commit_id_zero_commits(self):
        contents = {'number_of_commits': '0'}
        rel = self._make_release(contents=contents)
        self.assertIsNone(rel.commit_id)
        self.assertIsNone(rel.commit_checksum)

    def test_commit_id_no_contents(self):
        rel = self._make_release(contents={})
        self.assertIsNone(rel.commit_id)

    def test_base_commit_id(self):
        contents = {'base': {'commit': 'base123'}}
        rel = self._make_release(contents=contents)
        self.assertEqual(rel.base_commit_id, 'base123')

    def test_base_commit_id_none(self):
        rel = self._make_release(contents={})
        self.assertIsNone(rel.base_commit_id)

    def test_is_deletable(self):
        rel = self._make_release(state='available')
        self.assertTrue(rel.is_deletable)

    def test_is_not_deletable(self):
        rel = self._make_release(state='deployed')
        self.assertFalse(rel.is_deletable)

    def test_comparison_operators(self):
        r1 = self._make_release(extra_meta={'sw_version': '24.09.0'})
        r2 = self._make_release(extra_meta={'sw_version': '24.09.1'})
        self.assertTrue(r1 < r2)
        self.assertTrue(r1 <= r2)
        self.assertTrue(r2 > r1)
        self.assertTrue(r2 >= r1)
        self.assertTrue(r1 != r2)
        self.assertFalse(r1 == r2)

    def test_to_query_dict(self):
        rel = self._make_release(extra_meta={
            'summary': 'test', 'packages': ['pkg1'],
            'activation_scripts': ['s1']})
        d = rel.to_query_dict()
        self.assertEqual(d['release_id'], 'starlingx-24.09.0')
        self.assertEqual(d['summary'], 'test')

    @mock.patch('shutil.move')
    @mock.patch('os.makedirs')
    @mock.patch('os.path.isdir', return_value=False)
    def test_update_state(self, _isdir, _makedirs, _move):
        rel = self._make_release(state='available')
        rel.update_state('deploying')
        self.assertEqual(rel.state, 'deploying')
        _move.assert_called_once()

    @mock.patch('shutil.move', side_effect=shutil.Error("fail"))
    @mock.patch('os.path.isdir', return_value=True)
    def test_update_state_move_failure(self, _isdir, _move):
        rel = self._make_release(state='available')
        with self.assertRaises(FileSystemError):
            rel.update_state('deploying')


class TestSWReleaseCollection(unittest.TestCase):
    """Tests for SWReleaseCollection."""

    def _make_collection(self, releases=None):
        if releases is None:
            releases = {
                'rel-1': ('24.09.0', 'deployed'),
                'rel-2': ('24.09.1', 'available'),
                'rel-3': ('24.03.0', 'deployed'),
            }
        mock_rd = mock.MagicMock()
        mock_rd.metadata = {}
        mock_rd.contents = {}
        for rid, (ver, st) in releases.items():
            mock_rd.metadata[rid] = {'sw_version': ver, 'state': st}
            mock_rd.contents[rid] = {}
        return SWReleaseCollection(mock_rd)

    def test_get_release_by_id(self):
        coll = self._make_collection()
        rel = coll.get_release_by_id('rel-1')
        self.assertIsNotNone(rel)
        self.assertEqual(rel.id, 'rel-1')

    def test_get_release_by_id_missing(self):
        coll = self._make_collection()
        self.assertIsNone(coll.get_release_by_id('nonexistent'))

    def test_getitem(self):
        coll = self._make_collection()
        self.assertIsNotNone(coll['rel-1'])
        self.assertIsNone(coll['bad'])

    def test_iterate_releases(self):
        coll = self._make_collection()
        ids = [r.id for r in coll.iterate_releases()]
        self.assertEqual(len(ids), 3)
        self.assertEqual(ids, sorted(ids))

    def test_iterate_releases_by_state(self):
        coll = self._make_collection()
        deployed = list(coll.iterate_releases_by_state('deployed'))
        self.assertEqual(len(deployed), 2)

    @mock.patch('shutil.move')
    @mock.patch('os.path.isdir', return_value=True)
    def test_update_state(self, _isdir, _move):
        coll = self._make_collection()
        coll.update_state(['rel-2'], 'deploying')
        rel = coll.get_release_by_id('rel-2')
        self.assertEqual(rel.state, 'deploying')

    def test_running_release(self):
        coll = self._make_collection()
        running = coll.running_release
        self.assertIsNotNone(running)
        self.assertEqual(running.sw_release, '24.09.0')

    def test_get_release_by_commit_id(self):
        coll = self._make_collection()
        self.assertIsNone(coll.get_release_by_commit_id('no-match'))

    def test_get_release_id_by_sw_release(self):
        coll = self._make_collection()
        rid = coll.get_release_id_by_sw_release('24.09.0')
        self.assertEqual(rid, 'rel-1')

    def test_get_release_id_by_sw_release_missing(self):
        coll = self._make_collection()
        self.assertIsNone(coll.get_release_id_by_sw_release('99.99.0'))


class TestLocalStorageAndHelpers(unittest.TestCase):
    """Tests for LocalStorage, reload_release_data,
    get_SWReleaseCollection.
    """

    def test_local_storage(self):
        ls = LocalStorage()
        self.assertIsNone(ls.get_value('key'))
        ls.set_value('key', 'val')
        self.assertEqual(ls.get_value('key'), 'val')
        ls.void_value('key')
        self.assertIsNone(ls.get_value('key'))

    @mock.patch('software.release_data._local_storage')
    @mock.patch('software.release_data.ReleaseData')
    def test_get_sw_release_collection(self, mock_rd_cls, mock_ls):
        mock_ls.get_value.return_value = None
        mock_rd = mock.MagicMock()
        mock_rd.metadata = {}
        mock_rd.contents = {}
        mock_rd_cls.return_value = mock_rd
        coll = get_SWReleaseCollection()
        self.assertIsNotNone(coll)
        mock_rd.load_all.assert_called_once()

    def test_reload_release_data(self):
        _local_storage.set_value('release_data', 'something')
        reload_release_data()
        self.assertIsNone(_local_storage.get_value('release_data'))


class TestSoftwareAPI(unittest.TestCase):
    """Tests for SoftwareAPI singleton and methods."""

    def setUp(self):
        SoftwareAPI._instance = None

    def test_singleton(self):
        a = SoftwareAPI()
        b = SoftwareAPI()
        self.assertIs(a, b)

    def test_get_instance(self):
        inst = get_instance()
        self.assertIsNotNone(inst)

    @mock.patch('software.software_entities.get_software_filesystem_data',
                return_value={'deploy': [
                    {'from_release': '24.03.0', 'to_release': '24.09.0',
                     'state': 'start'}]})
    def test_get_deploy(self, _get):
        api = get_instance()
        result = api.get_deploy('24.03.0', '24.09.0')
        self.assertEqual(result['state'], 'start')

    @mock.patch('software.software_entities.get_software_filesystem_data',
                return_value={'deploy_host': [
                    {'hostname': 'controller-0', 'state': 'pending'}]})
    def test_get_deploy_host(self, _get):
        api = get_instance()
        result = api.get_deploy_host()
        self.assertEqual(len(result), 1)

    @mock.patch('software.software_entities.get_software_filesystem_data',
                return_value={})
    def test_get_system_deploy_empty(self, _get):
        api = get_instance()
        result = api.get_system_deploy()
        self.assertEqual(result, [])

    @mock.patch('software.software_entities.get_software_filesystem_data',
                return_value={'deploy': [
                    {'from_release': '24.03.0', 'to_release': '24.09.0',
                     'state': 'start'}]})
    def test_get_current_deploy(self, _get):
        api = get_instance()
        result = api.get_current_deploy()
        self.assertIsNotNone(result)

    @mock.patch('software.software_entities.get_software_filesystem_data',
                return_value={'deploy': []})
    def test_get_current_deploy_none(self, _get):
        api = get_instance()
        result = api.get_current_deploy()
        self.assertIsNone(result)


class TestDeployHostStateTransform(unittest.TestCase):
    """Tests for DeployHostState.transform and event methods."""

    def setUp(self):
        DeployHostState._callbacks = []

    @mock.patch('software.deploy_host_state.get_instance')
    def test_transform_invalid_raises(self, mock_db):
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'pending'}
        dhs = DeployHostState('controller-0')
        with self.assertRaises(InvalidOperation):
            dhs.transform(DEPLOY_HOST_STATES.DEPLOYED)


class TestGetDbConnection(unittest.TestCase):
    """Tests for get_db_connection."""

    def test_returns_connection_string(self):
        records = {'mydb': {'username': 'user', 'password': 'pass'}}
        result = get_db_connection(records, 'mydb')
        self.assertEqual(result,
                         'postgresql://user:pass@localhost/mydb')


class TestGetPasswordFromKeyring(unittest.TestCase):
    """Tests for get_password_from_keyring."""

    @mock.patch('keyring.get_password', return_value='secret')
    def test_success(self, _kr):
        result = get_password_from_keyring('CGCS', 'admin')
        self.assertEqual(result, 'secret')
        self.assertNotIn('XDG_DATA_HOME', os.environ)

    @mock.patch('keyring.get_password', side_effect=Exception("fail"))
    def test_failure_raises(self, _kr):
        with self.assertRaises(Exception):  # noqa: H202
            get_password_from_keyring('CGCS', 'admin')
        self.assertNotIn('XDG_DATA_HOME', os.environ)


class TestGetUpgradeToken(unittest.TestCase):
    """Tests for get_upgrade_token."""

    @mock.patch('software.utilities.utils.get_password_from_keyring',
                return_value='admin_pass')
    @mock.patch('builtins.open', mock.mock_open(read_data=''))
    @mock.patch('yaml.load')
    def test_populates_config(self, mock_yaml, _kr):
        mock_yaml.return_value = {
            'openstack::keystone::params::api_version': 'v3',
            'platform::client::params::admin_user_domain': 'Default',
            'platform::client::params::admin_project_domain': 'Default',
            'platform::client::params::admin_username': 'admin',
        }
        config = {}
        secure = {}
        get_upgrade_token('24.03', config, secure)
        self.assertIn('openstack::keystone::upgrade::url', config)
        self.assertIn(
            'openstack::keystone::upgrade::upgrade_token_cmd', secure)

    @mock.patch('software.utilities.utils.get_password_from_keyring',
                return_value='admin_pass')
    @mock.patch('builtins.open', mock.mock_open(read_data=''))
    @mock.patch('yaml.load')
    def test_missing_domain_defaults(self, mock_yaml, _kr):
        mock_yaml.return_value = {
            'openstack::keystone::params::api_version': 'v3',
            'platform::client::params::admin_username': 'admin',
        }
        config = {}
        secure = {}
        get_upgrade_token('24.03', config, secure)
        self.assertIn('openstack::keystone::upgrade::url', config)


class TestGetUpgradeData(unittest.TestCase):
    """Tests for get_upgrade_data."""

    @mock.patch('builtins.open', mock.mock_open(read_data=''))
    @mock.patch('yaml.load')
    def test_populates_system_config(self, mock_yaml):
        mock_yaml.return_value = {
            'keystone::endpoint::region': 'RegionOne',
        }
        sys_config = {}
        secure = {}
        get_upgrade_data('24.03', sys_config, secure)
        self.assertEqual(
            sys_config['platform::client::params::identity_region'],
            'RegionOne')


class TestApplyUpgradeManifest(unittest.TestCase):
    """Tests for apply_upgrade_manifest."""

    @mock.patch('builtins.open', mock.mock_open())
    @mock.patch('subprocess.check_call',
                side_effect=subprocess.CalledProcessError(1, 'cmd'))
    def test_failure_raises(self, _call):
        with self.assertRaises(Exception):  # noqa: H202
            apply_upgrade_manifest('10.0.0.1')


class TestKeystoneQueries(unittest.TestCase):
    """Tests for get_keystone_user_id and get_keystone_project_id."""

    @mock.patch('psycopg2.connect')
    def test_get_user_id(self, mock_conn):
        mock_cur = mock.MagicMock()
        mock_cur.fetchone.return_value = {'user_id': 'uid-123'}
        mock_conn.return_value.__enter__ = mock.MagicMock(
            return_value=mock_conn.return_value)
        mock_conn.return_value.__exit__ = mock.MagicMock(return_value=False)
        mock_conn.return_value.cursor.return_value.__enter__ = (
            mock.MagicMock(return_value=mock_cur))
        mock_conn.return_value.cursor.return_value.__exit__ = (
            mock.MagicMock(return_value=False))
        result = get_keystone_user_id('admin')
        self.assertEqual(result, 'uid-123')

    @mock.patch('psycopg2.connect')
    def test_get_user_id_not_found(self, mock_conn):
        mock_cur = mock.MagicMock()
        mock_cur.fetchone.return_value = None
        mock_conn.return_value.__enter__ = mock.MagicMock(
            return_value=mock_conn.return_value)
        mock_conn.return_value.__exit__ = mock.MagicMock(return_value=False)
        mock_conn.return_value.cursor.return_value.__enter__ = (
            mock.MagicMock(return_value=mock_cur))
        mock_conn.return_value.cursor.return_value.__exit__ = (
            mock.MagicMock(return_value=False))
        result = get_keystone_user_id('nobody')
        self.assertIsNone(result)

    @mock.patch('psycopg2.connect')
    def test_get_project_id(self, mock_conn):
        mock_cur = mock.MagicMock()
        mock_cur.fetchone.return_value = {'id': 'pid-456'}
        mock_conn.return_value.__enter__ = mock.MagicMock(
            return_value=mock_conn.return_value)
        mock_conn.return_value.__exit__ = mock.MagicMock(return_value=False)
        mock_conn.return_value.cursor.return_value.__enter__ = (
            mock.MagicMock(return_value=mock_cur))
        mock_conn.return_value.cursor.return_value.__exit__ = (
            mock.MagicMock(return_value=False))
        result = get_keystone_project_id('admin')
        self.assertEqual(result, 'pid-456')

    @mock.patch('psycopg2.connect')
    def test_get_project_id_not_found(self, mock_conn):
        mock_cur = mock.MagicMock()
        mock_cur.fetchone.return_value = None
        mock_conn.return_value.__enter__ = mock.MagicMock(
            return_value=mock_conn.return_value)
        mock_conn.return_value.__exit__ = mock.MagicMock(return_value=False)
        mock_conn.return_value.cursor.return_value.__enter__ = (
            mock.MagicMock(return_value=mock_cur))
        mock_conn.return_value.cursor.return_value.__exit__ = (
            mock.MagicMock(return_value=False))
        result = get_keystone_project_id('nobody')
        self.assertIsNone(result)


class TestGetPostgresBin(unittest.TestCase):
    """Tests for get_postgres_bin."""

    @mock.patch('subprocess.check_output',
                return_value=b'/usr/lib/postgresql/bin\n')
    def test_success(self, _call):
        result = get_postgres_bin()
        self.assertEqual(result, '/usr/lib/postgresql/bin')

    @mock.patch('subprocess.check_output',
                side_effect=subprocess.CalledProcessError(1, 'cmd'))
    def test_failure_raises(self, _call):
        with self.assertRaises(subprocess.CalledProcessError):
            get_postgres_bin()


class TestCreateManifestRuntimeConfig(unittest.TestCase):
    """Tests for create_manifest_runtime_config."""

    @mock.patch('builtins.open', side_effect=IOError("fail"))
    def test_write_failure_raises(self, _open):
        with self.assertRaises(IOError):
            create_manifest_runtime_config('/tmp/test.yaml', {'k': 'v'})


class TestCreateSystemConfig(unittest.TestCase):
    """Tests for create_system_config."""

    @mock.patch('subprocess.check_call',
                side_effect=subprocess.CalledProcessError(1, 'cmd'))
    def test_failure_raises(self, _call):
        with self.assertRaises(Exception):  # noqa: H202
            create_system_config()


class TestCreateHostConfig(unittest.TestCase):
    """Tests for create_host_config."""

    @mock.patch('subprocess.check_call')
    def test_without_hostname(self, mock_call):
        create_host_config()
        args = mock_call.call_args[0][0]
        self.assertEqual(len(args), 3)

    @mock.patch('subprocess.check_call')
    def test_with_hostname(self, mock_call):
        create_host_config(hostname='controller-0')
        args = mock_call.call_args[0][0]
        self.assertIn('controller-0', args)

    @mock.patch('subprocess.check_call',
                side_effect=subprocess.CalledProcessError(1, 'cmd'))
    def test_failure_raises(self, _call):
        with self.assertRaises(Exception):  # noqa: H202
            create_host_config()


class TestAddUpgradeEntriesToHieraData(unittest.TestCase):
    """Tests for add_upgrade_entries_to_hiera_data."""

    @mock.patch('os.rename')
    @mock.patch('os.close')
    @mock.patch('tempfile.mkstemp', return_value=(99, '/tmp/tmpXXX'))
    @mock.patch('yaml.dump')
    @mock.patch('yaml.load')
    @mock.patch('builtins.open', mock.mock_open(read_data=''))
    @mock.patch('software.utilities.utils.get_upgrade_data')
    @mock.patch('software.utilities.utils.get_upgrade_token')
    def test_success(self, _token, _data, mock_yaml_load, _dump,
                     _mkstemp, _close, _rename):
        mock_yaml_load.return_value = {}
        add_upgrade_entries_to_hiera_data('24.03')
        self.assertEqual(_rename.call_count, 3)


class TestDbApiMethods(unittest.TestCase):
    """Tests for SoftwareAPI methods."""

    def _make_db(self):
        db = SoftwareAPI.__new__(SoftwareAPI)
        db._lock = mock.MagicMock()
        db.deploy_handler = mock.MagicMock()
        db.deploy_host_handler = mock.MagicMock()
        db.system_deploy_handler = mock.MagicMock()
        return db

    def test_get_system_deploy(self):
        db = self._make_db()
        db.system_deploy_handler.query.return_value = {"id": "d1"}
        result = db.get_system_deploy()
        self.assertEqual(result["id"], "d1")
