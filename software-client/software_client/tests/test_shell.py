#
# Copyright (c) 2013-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import fixtures
import httplib2
from unittest import mock
import re
from six.moves import cStringIO as StringIO
import sys
from testtools import matchers

import keystoneauth1

from software_client import exc
from software_client import software_client
from software_client.tests import utils

FAKE_ENV = {'OS_USERNAME': 'username',
            'OS_PASSWORD': 'password',
            'OS_PROJECT_NAME': 'project',
            'OS_REGION_NAME': 'region',
            'OS_TENANT_NAME': 'tenant_name',
            'OS_AUTH_URL': 'http://no.where'}


class ShellTest(utils.BaseTestCase):
    re_options = re.DOTALL | re.MULTILINE

    mock_endpoint_patcher = mock.patch.object(keystoneauth1.session.Session,
                                              'get_endpoint')

    # Patch os.environ to avoid required auth info.
    def make_env(self, exclude=None):
        env = dict((k, v) for k, v in FAKE_ENV.items() if k != exclude)
        self.useFixture(fixtures.MonkeyPatch('os.environ', env))

    def setUp(self):
        super(ShellTest, self).setUp()
        self.mock_endpoint = self.mock_endpoint_patcher.start()

    def tearDown(self):
        super(ShellTest, self).tearDown()
        self.mock_endpoint_patcher.stop()

    def shell(self, argstr):
        orig = sys.stdout
        try:
            sys.stdout = StringIO()
            _shell = software_client.SoftwareClientShell()
            _shell.main(argstr.split())
        except SystemExit:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.assertEqual(exc_value.code, 0)
        finally:
            out = sys.stdout.getvalue()
            sys.stdout.close()
            sys.stdout = orig

        return out

    def test_help_unknown_command(self):
        self.assertRaises(exc.CommandError, self.shell, 'help foofoo')

    def test_debug(self):
        httplib2.debuglevel = 0
        self.shell('--debug help')
        self.assertEqual(httplib2.debuglevel, 1)

    def test_help(self):
        required = [
            '.*?^usage: software',
            '.*?^See "software help COMMAND" '
            'for help on a specific command',
        ]
        for argstr in ['--help', 'help']:
            help_text = self.shell(argstr)
            for r in required:
                self.assertThat(help_text,
                                matchers.MatchesRegex(r,
                                                      self.re_options))

    def test_help_on_subcommand(self):
        required = [
            r'.*?^usage: software list \[--release RELEASE\] \[--state STATE\]'
            r'',
            r".*?^List the software releases",
            r'',
            r".*?^Optional arguments:",
            r".*?--release RELEASE  filter against a release ID",
            r".*?--state STATE      filter against a release state",
        ]
        argstrings = [
            'help list',
        ]
        for argstr in argstrings:
            help_text = self.shell(argstr)
            for r in required:
                self.assertThat(help_text,
                                matchers.MatchesRegex(r, self.re_options))

    def test_auth_param(self):
        self.make_env(exclude='OS_USERNAME')
        self.test_help()
