# Copyright (c) 2013-2024 Wind River Systems, Inc.
# Copyright 2013 Hewlett-Packard Development Company, L.P.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


import testtools

from software_client.tests import utils
import software_client.v1.release

RELEASE = {
  'sd':
  {'starlingx-24.03.0': {
    'state': 'deployed',
    'sw_version': '24.03.0',
    'status': 'REL',
    'unremovable': 'Y',
    'summary': 'STX 24.03 GA release',
    'description': 'STX 24.03 major GA release',
    'install_instructions': '',
    'warnings': '',
    'apply_active_release_only': '',
    'reboot_required': 'Y',
    'requires': [],
    'packages': []
    }
  }
}

fixtures = {
    '/v1/software/query?show=all':
    {
        'GET': (
            {},
            {'sd': RELEASE['sd']},
        ),
    },
    '/v1/software/show/1':
    {
        'POST': (
            {},
            True,
        ),
    },
    '/v1/software/delete/1':
    {
        'POST': (
            {},
            {},
        ),
    },
    '/v1/software/is_available/1':
    {
        'POST': (
            {},
            True,
        ),
    },
    '/v1/software/is_deployed/1':
    {
        'POST': (
            {},
            False,
        ),
    },
    '/v1/software/is_committed/1':
    {
        'POST': (
            {},
            False,
        ),
    },
    '/v1/software/install_local':
    {
        'GET': (
            {},
            {},
        ),
    },
}


class Args:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            if isinstance(value, dict):
                self.__dict__[key] = Args(**value)
            else:
                self.__dict__[key] = value


class ReleaseManagerTest(testtools.TestCase):

    def setUp(self):
        super(ReleaseManagerTest, self).setUp()
        self.api = utils.FakeAPI(fixtures)
        self.mgr = software_client.v1.release.ReleaseManager(self.api)

    def test_release_list(self):
        input = {"state": "all", "release": ""}
        args = Args(**input)
        release = self.mgr.list(args)
        expect = [
            ('GET', '/v1/software/query?show=all', {}, None),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertEqual(len(release), 2)

    def test_release_show(self):
        input = {"state": "", "release": "1"}
        args = Args(**input)
        release = self.mgr.show(args)
        expect = [
            ('POST', '/v1/software/show/1', {}, {}),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertEqual(len(release), 2)

    def test_release_delete(self):
        response = self.mgr.release_delete("1")
        expect = [
            ('POST', '/v1/software/delete/1', {}, {}),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertEqual(len(response), 2)

    def test_is_available(self):
        response = self.mgr.is_available('1')
        expect = [
            ('POST', '/v1/software/is_available/1', {}, {}),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertTrue(response[1], True)

    def test_is_deployed(self):
        response = self.mgr.is_deployed('1')
        expect = [
            ('POST', '/v1/software/is_deployed/1', {}, {}),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertFalse(response[1], False)

    def test_is_committed(self):
        response = self.mgr.is_committed('1')
        expect = [
            ('POST', '/v1/software/is_committed/1', {}, {}),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertFalse(response[1], True)

    def test_upload(self):
        input = {'release': '1', 'local': ''}
        args = Args(**input)
        response = self.mgr.upload(args)
        expect = [
            ('POST', '/v1/software/upload', {}, {}),
        ]
        self.assertNotEqual(self.api.calls, expect)
        self.assertEqual(response, 0)

    def test_upload_dir(self):
        input = {'release': '1'}
        args = Args(**input)
        response = self.mgr.upload_dir(args)
        expect = [
            ('POST', '/v1/software/upload', {}, {}),
        ]
        self.assertNotEqual(self.api.calls, expect)
        self.assertEqual(response, 0)

    def test_install_local(self):
        self.mgr.install_local()
        expect = [
            ('GET', '/v1/software/install_local', {}, None),
        ]
        self.assertEqual(self.api.calls, expect)

    def test_commit_patch(self):
        input = {'sw_version': '1', 'all': ''}
        args = Args(**input)
        kernel = self.mgr.commit_patch(args)
        expect = [
            ('GET', '/v1/software/commit_patch/1', {}, None),
        ]
        self.assertNotEqual(self.api.calls, expect)
