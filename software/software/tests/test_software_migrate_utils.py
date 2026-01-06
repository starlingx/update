#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2025 Wind River Systems, Inc.
#
import unittest

from software.utilities.utils import sort_migration_scripts


class TestSoftwareMigration(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_sort_migration_scripts(self):
        scripts = ['01-script1.sh',
                   '02-script2.py',
                   '09-script9.sh',
                   '06-script77.py',
                   '123-script-9.py']

        migrate_exp = ['01-script1.sh',
                       '02-script2.py',
                       '06-script77.py',
                       '09-script9.sh',
                       '123-script-9.py']
        migrate = sort_migration_scripts(scripts, 'migrate')
        assert migrate_exp == migrate

        activate_exp = ['01-script1.sh',
                        '02-script2.py',
                        '06-script77.py',
                        '09-script9.sh',
                        '123-script-9.py']
        activate = sort_migration_scripts(scripts, 'activate')
        assert activate_exp == activate

        rollback_exp = ['123-script-9.py',
                        '09-script9.sh',
                        '06-script77.py',
                        '02-script2.py',
                        '01-script1.sh']
        rollback = sort_migration_scripts(scripts, 'activate-rollback')
        assert rollback_exp == rollback
