#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Extended tests for software.utilities.migrate module."""

import json
import subprocess
import unittest
from unittest import mock

import psycopg2

from software.tests import base as test_base  # noqa: F401

# migrate.py calls get_postgres_bin() -> pg_config at module scope, so
# subprocess.check_output must be patched before importing it.
mock.patch('subprocess.check_output', return_value=b'/usr/bin').start()

from software.utilities.migrate import create_database
from software.utilities.migrate import create_mgmt_ip_hieradata
from software.utilities.migrate import get_connection_string
from software.utilities.migrate import get_first_controller
from software.utilities.migrate import get_hostname_mgmt_ip
from software.utilities.migrate import get_shared_services
from software.utilities.migrate import get_system_mode
from software.utilities.migrate import get_system_role
from software.utilities.migrate import gethostaddress
from software.utilities.migrate import import_databases
from software.utilities.migrate import migrate_armada_config
from software.utilities.migrate import migrate_databases
from software.utilities.migrate import migrate_helm_config
from software.utilities.migrate import migrate_hiera_data
from software.utilities.migrate import migrate_keyring_data
from software.utilities.migrate import migrate_pxeboot_config
from software.utilities.migrate import migrate_sysinv_data
from software.utilities.migrate import migrate_sysinv_database
from software.utilities.migrate import migrate_vim_database

# migrate.py calls get_postgres_bin() -> pg_config at module level.
# Mock subprocess.check_output before importing.
mock.patch('subprocess.check_output', return_value=b'/usr/bin').start()


class TestMigrateKeyringDataExtended(unittest.TestCase):

    @mock.patch('software.utilities.migrate.os.rename')
    @mock.patch('software.utilities.migrate.set_keyring_env')
    @mock.patch('software.utilities.migrate.change_keyring_ownership',
                create=True)
    @mock.patch('software.utilities.migrate.shutil')
    @mock.patch('software.utilities.migrate.os.makedirs')
    def test_removes_target_first(self, _makedirs, mock_shutil,
                                  _chown, _env, _rename):
        migrate_keyring_data("24.03", "24.09")
        # The target keyring dir is cleared first, before staging dirs.
        self.assertGreaterEqual(mock_shutil.rmtree.call_count, 1)
        first_call = mock_shutil.rmtree.call_args_list[0]
        self.assertIn("/.keyring/", first_call[0][0])
        self.assertTrue(
            first_call[1].get("ignore_errors", False))

    @mock.patch('software.utilities.migrate.os.rename')
    @mock.patch('software.utilities.migrate.set_keyring_env')
    @mock.patch('software.utilities.migrate.change_keyring_ownership',
                create=True)
    @mock.patch('software.utilities.migrate.shutil')
    @mock.patch('software.utilities.migrate.os.makedirs')
    def test_copies_from_source(self, _makedirs, mock_shutil,
                                _chown, _env, _rename):
        migrate_keyring_data("24.03", "24.09")
        # New code uses copy2, old uses copytree
        if mock_shutil.copy2.called:
            src = mock_shutil.copy2.call_args[0][0]
        else:
            src = mock_shutil.copytree.call_args[0][0]
        self.assertIn("24.03", src)


class TestMigratePxebootConfig(unittest.TestCase):

    @mock.patch('software.utilities.migrate.os.symlink')
    @mock.patch('software.utilities.migrate.os.unlink')
    @mock.patch('software.utilities.migrate.os.path.islink', return_value=True)
    @mock.patch('software.utilities.migrate.pathlib.Path')
    @mock.patch('software.utilities.migrate.subprocess.check_call')
    def test_rsync_and_symlink(self, mock_call, _mock_path, _mock_islink,
                               mock_unlink, mock_symlink):
        migrate_pxeboot_config("24.03", "24.09")
        mock_call.assert_called_once()
        cmd = mock_call.call_args[0][0]
        self.assertEqual(cmd[0], "rsync")
        mock_unlink.assert_called_once()
        mock_symlink.assert_called_once()

    @mock.patch('software.utilities.migrate.pathlib.Path')
    @mock.patch('software.utilities.migrate.subprocess.check_call',
                side_effect=subprocess.CalledProcessError(1, 'rsync'))
    def test_rsync_failure_raises(self, _mock_call, _mock_path):
        with self.assertRaises(subprocess.CalledProcessError):
            migrate_pxeboot_config("24.03", "24.09")


class TestMigrateArmadaConfig(unittest.TestCase):

    @mock.patch('software.utilities.migrate.subprocess.check_call')
    @mock.patch('software.utilities.migrate.os.path.exists', return_value=True)
    def test_copies_armada(self, _mock_exists, mock_call):
        migrate_armada_config("24.03", "24.09")
        mock_call.assert_called_once()
        cmd = mock_call.call_args[0][0]
        self.assertIn("rsync", cmd)

    @mock.patch('software.utilities.migrate.subprocess.check_call',
                side_effect=subprocess.CalledProcessError(1, 'rsync'))
    @mock.patch('software.utilities.migrate.os.path.exists', return_value=True)
    def test_failure_raises(self, _mock_exists, _mock_call):
        with self.assertRaises(subprocess.CalledProcessError):
            migrate_armada_config("24.03", "24.09")


class TestMigrateHelmConfig(unittest.TestCase):

    @mock.patch('software.utilities.migrate.subprocess.check_call')
    def test_copies_helm(self, mock_call):
        migrate_helm_config("24.03", "24.09")
        mock_call.assert_called_once()
        cmd = mock_call.call_args[0][0]
        self.assertIn("rsync", cmd)

    @mock.patch('software.utilities.migrate.subprocess.check_call',
                side_effect=subprocess.CalledProcessError(1, 'rsync'))
    def test_failure_raises(self, _mock_call):
        with self.assertRaises(subprocess.CalledProcessError):
            migrate_helm_config("24.03", "24.09")


class TestMigrateSysinvData(unittest.TestCase):

    @mock.patch('software.utilities.migrate.subprocess.check_call',
                side_effect=subprocess.CalledProcessError(1, 'rsync'))
    def test_rsync_failure_raises(self, _mock_call):
        with self.assertRaises(subprocess.CalledProcessError):
            migrate_sysinv_data("24.03", "24.09", "6666")


class TestMigrateHieraData(unittest.TestCase):

    @mock.patch('software.utilities.migrate.yaml.dump')
    @mock.patch('software.utilities.migrate.yaml.load',
                return_value={'platform::params::software_version': '24.03'})
    @mock.patch('software.utilities.migrate.shutil.copy')
    @mock.patch('software.utilities.migrate.os.makedirs')
    @mock.patch('software.utilities.migrate.shutil.rmtree')
    @mock.patch('builtins.open', mock.mock_open())
    def test_migrates_hiera(self, mock_rmtree, mock_makedirs,
                            mock_copy, _mock_load, _mock_dump):
        migrate_hiera_data("24.03")
        mock_rmtree.assert_called_once()
        mock_makedirs.assert_called_once()
        self.assertEqual(mock_copy.call_count, 2)


class TestMigrateVimDatabase(unittest.TestCase):

    @mock.patch('software.utilities.migrate.subprocess.check_call')
    def test_migrates_vim(self, mock_call):
        migrate_vim_database("24.03", "24.09")
        self.assertTrue(mock_call.call_count >= 3)

    @mock.patch('software.utilities.migrate.subprocess.check_call',
                side_effect=subprocess.CalledProcessError(1, 'rm'))
    def test_failure_raises(self, _mock_call):
        with self.assertRaises(subprocess.CalledProcessError):
            migrate_vim_database("24.03", "24.09")


class TestCreateDatabase(unittest.TestCase):

    @mock.patch('software.utilities.migrate.subprocess.check_call')
    def test_creates_db(self, mock_call):
        create_database("6666")
        self.assertTrue(mock_call.call_count > 0)

    @mock.patch('software.utilities.migrate.subprocess.check_call',
                side_effect=subprocess.CalledProcessError(1, 'initdb'))
    def test_failure_raises(self, _mock_call):
        with self.assertRaises(subprocess.CalledProcessError):
            create_database("6666")


class TestImportDatabases(unittest.TestCase):

    @mock.patch('software.utilities.migrate.get_system_role',
                return_value=None)
    @mock.patch('software.utilities.migrate.glob.glob',
                return_value=['/var/lib/postgresql'
                              '/upgrade/sysinv'
                              '.postgreSql.data'])
    @mock.patch('software.utilities.migrate.subprocess.check_call')
    def test_imports(self, mock_call, _mock_glob, _role):
        import_databases("6666")
        self.assertTrue(mock_call.call_count >= 3)

    @mock.patch('software.utilities.migrate.subprocess.check_call',
                side_effect=subprocess.CalledProcessError(1, 'psql'))
    def test_failure_raises(self, _mock_call):
        with self.assertRaises(subprocess.CalledProcessError):
            import_databases("6666")


class TestGetSystemRole(unittest.TestCase):

    @mock.patch('software.utilities.migrate.psycopg2.connect')
    def test_returns_role(self, mock_connect):
        mock_cur = mock.MagicMock()
        mock_cur.fetchone.return_value = ('systemcontroller',)
        mock_conn = mock.MagicMock()
        mock_conn.cursor.return_value = mock_cur
        mock_connect.return_value = mock_conn
        role = get_system_role("6666")
        self.assertEqual(role, "systemcontroller")

    @mock.patch('software.utilities.migrate.psycopg2.connect')
    def test_none_raises(self, mock_connect):
        mock_cur = mock.MagicMock()
        mock_cur.fetchone.return_value = None
        mock_conn = mock.MagicMock()
        mock_conn.cursor.return_value = mock_cur
        mock_connect.return_value = mock_conn
        with self.assertRaises(psycopg2.ProgrammingError):
            get_system_role("6666")


class TestGetSystemMode(unittest.TestCase):

    @mock.patch('software.utilities.migrate.psycopg2.connect')
    def test_returns_mode(self, mock_connect):
        mock_cur = mock.MagicMock()
        mock_cur.fetchone.return_value = ('simplex',)
        mock_conn = mock.MagicMock()
        mock_conn.cursor.return_value = mock_cur
        mock_connect.return_value = mock_conn
        mode = get_system_mode("6666")
        self.assertEqual(mode, "simplex")

    @mock.patch('software.utilities.migrate.psycopg2.connect')
    def test_none_raises(self, mock_connect):
        mock_cur = mock.MagicMock()
        mock_cur.fetchone.return_value = None
        mock_conn = mock.MagicMock()
        mock_conn.cursor.return_value = mock_cur
        mock_connect.return_value = mock_conn
        with self.assertRaises(psycopg2.ProgrammingError):
            get_system_mode("6666")


class TestGetFirstController(unittest.TestCase):

    @mock.patch('software.utilities.migrate.get_system_mode',
                return_value='simplex')
    def test_simplex(self, _mock_mode):
        result = get_first_controller("6666")
        self.assertEqual(result, "controller-0")

    @mock.patch('software.utilities.migrate.get_system_mode',
                return_value='duplex')
    def test_duplex(self, _mock_mode):
        result = get_first_controller("6666")
        self.assertEqual(result, "controller-1")


class TestGetHostnameMgmtIp(unittest.TestCase):

    @mock.patch('software.utilities.migrate.psycopg2.connect')
    def test_returns_ip(self, mock_connect):
        mock_cur = mock.MagicMock()
        mock_cur.fetchone.return_value = ('192.168.1.1',)
        mock_conn = mock.MagicMock()
        mock_conn.cursor.return_value = mock_cur
        mock_connect.return_value = mock_conn
        ip = get_hostname_mgmt_ip("controller-0", "6666")
        self.assertEqual(ip, "192.168.1.1")

    @mock.patch('software.utilities.migrate.psycopg2.connect')
    def test_none_raises(self, mock_connect):
        mock_cur = mock.MagicMock()
        mock_cur.fetchone.return_value = None
        mock_conn = mock.MagicMock()
        mock_conn.cursor.return_value = mock_cur
        mock_connect.return_value = mock_conn
        with self.assertRaises(psycopg2.ProgrammingError):
            get_hostname_mgmt_ip("controller-0", "6666")


class TestGetSharedServices(unittest.TestCase):

    @mock.patch('software.utilities.migrate.psycopg2.connect')
    def test_returns_shared(self, mock_connect):
        caps = json.dumps({'region_config': True,
                           'shared_services': ['identity']})
        mock_cur = mock.MagicMock()
        mock_cur.fetchone.return_value = (caps,)
        mock_conn = mock.MagicMock()
        mock_conn.cursor.return_value = mock_cur
        mock_connect.return_value = mock_conn
        result = get_shared_services("6666")
        self.assertEqual(result, ['identity'])

    @mock.patch('software.utilities.migrate.psycopg2.connect')
    def test_no_region_config(self, mock_connect):
        caps = json.dumps({})
        mock_cur = mock.MagicMock()
        mock_cur.fetchone.return_value = (caps,)
        mock_conn = mock.MagicMock()
        mock_conn.cursor.return_value = mock_cur
        mock_connect.return_value = mock_conn
        result = get_shared_services("6666")
        self.assertEqual(result, [])

    @mock.patch('software.utilities.migrate.psycopg2.connect')
    def test_none_raises(self, mock_connect):
        mock_cur = mock.MagicMock()
        mock_cur.fetchone.return_value = None
        mock_conn = mock.MagicMock()
        mock_conn.cursor.return_value = mock_cur
        mock_connect.return_value = mock_conn
        with self.assertRaises(psycopg2.ProgrammingError):
            get_shared_services("6666")


class TestGetConnectionString(unittest.TestCase):

    def test_barbican_format(self):
        creds = {'barbican': {'username': 'user', 'password': 'pass'}}
        result = get_connection_string(creds, "6666", "barbican")
        self.assertEqual(result,
                         "postgresql://user:pass@127.0.0.1:6666/barbican")

    def test_other_format(self):
        creds = {'sysinv': {'username': 'user', 'password': 'pass'}}
        result = get_connection_string(creds, "6666", "sysinv")
        self.assertIn("connection=postgresql://", result)
        self.assertIn("sysinv", result)


class TestGethostaddress(unittest.TestCase):

    @mock.patch('software.utilities.migrate.socket.getaddrinfo')
    def test_returns_ip(self, mock_getaddr):
        mock_getaddr.return_value = [(2, 1, 6, '', ('10.0.0.1', 0))]
        result = gethostaddress("controller-0")
        self.assertEqual(result, "10.0.0.1")


class TestMigrateSysinvDatabase(unittest.TestCase):

    @mock.patch('software.utilities.migrate.subprocess.run')
    def test_runs_dbsync(self, mock_run):
        migrate_sysinv_database()
        mock_run.assert_called_once()
        self.assertIn('sysinv-dbsync', mock_run.call_args[0][0])

    @mock.patch('software.utilities.migrate.subprocess.run',
                side_effect=subprocess.CalledProcessError(1, 'sysinv-dbsync'))
    def test_failure_raises(self, _mock_run):
        with self.assertRaises(subprocess.CalledProcessError):
            migrate_sysinv_database()


class TestMigrateDatabases(unittest.TestCase):

    @mock.patch('software.utilities.utils.get_debian_version_codename',
                return_value='trixie')
    @mock.patch('software.utilities.migrate.subprocess.run')
    @mock.patch('builtins.open', mock.mock_open())
    def test_migrates_basic(self, mock_run, _codename):
        creds = {
            'barbican': {'username': 'u', 'password': 'p'},
            'fm': {'username': 'u', 'password': 'p'},
            'keystone': {'username': 'u', 'password': 'p'},
        }
        migrate_databases([], creds, "6666")
        self.assertTrue(mock_run.call_count > 0)

    @mock.patch('software.utilities.utils.get_debian_version_codename',
                return_value='trixie')
    @mock.patch('software.utilities.migrate.subprocess.run')
    @mock.patch('builtins.open', mock.mock_open())
    def test_simplex_keystone(self, mock_run, _codename):
        creds = {
            'barbican': {'username': 'u', 'password': 'p'},
            'fm': {'username': 'u', 'password': 'p'},
            'keystone': {'username': 'u', 'password': 'p'},
        }
        migrate_databases([], creds, "6666", simplex=True)
        # identity is not shared, so keystone must be migrated
        cmds = " ".join(str(c) for c in mock_run.call_args_list)
        self.assertIn("keystone", cmds)

    @mock.patch('software.utilities.utils.get_debian_version_codename',
                return_value='trixie')
    @mock.patch('software.utilities.migrate.subprocess.run')
    @mock.patch('builtins.open', mock.mock_open())
    def test_with_identity_shared(self, mock_run, _codename):
        creds = {
            'barbican': {'username': 'u', 'password': 'p'},
            'fm': {'username': 'u', 'password': 'p'},
        }
        migrate_databases(['identity'], creds, "6666")
        # identity is shared, so keystone migration must be skipped
        cmds = " ".join(str(c) for c in mock_run.call_args_list)
        self.assertNotIn("keystone", cmds)
        # other services still migrate
        self.assertIn("barbican", cmds)

    @mock.patch('software.utilities.utils.get_debian_version_codename',
                return_value='trixie')
    @mock.patch('software.utilities.migrate.subprocess.run')
    @mock.patch('builtins.open', mock.mock_open())
    def test_systemcontroller_role(self, mock_run, _codename):
        creds = {
            'barbican': {'username': 'u', 'password': 'p'},
            'fm': {'username': 'u', 'password': 'p'},
            'keystone': {'username': 'u', 'password': 'p'},
            'dcmanager': {'username': 'u', 'password': 'p'},
            'dcorch': {'username': 'u', 'password': 'p'},
        }
        migrate_databases([], creds, "6666",
                          role='systemcontroller')
        self.assertTrue(mock_run.call_count > 0)


class TestCreateMgmtIpHieradata(unittest.TestCase):

    @mock.patch('software.utilities.migrate.shutil.copy')
    @mock.patch('software.utilities.migrate.get_hostname_mgmt_ip',
                return_value='10.0.0.1')
    def test_creates_hieradata(self, _mock_ip, mock_copy):
        create_mgmt_ip_hieradata("controller-0", "6666")
        mock_copy.assert_called_once()
        dst = mock_copy.call_args[0][1]
        self.assertIn("10.0.0.1", dst)

    @mock.patch('software.utilities.migrate.get_hostname_mgmt_ip',
                side_effect=psycopg2.ProgrammingError("db error"))
    def test_failure_raises(self, _mock_ip):
        with self.assertRaises(psycopg2.ProgrammingError):
            create_mgmt_ip_hieradata("controller-0", "6666")
