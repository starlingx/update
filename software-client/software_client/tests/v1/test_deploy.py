# Copyright (c) 2019-2024 Wind River Systems, Inc.
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
import software_client.v1.deploy
import software_client.v1.deploy_shell


HOST_LIST = {'data': [{
  'ip': '192.168.204.2',
  'hostname': 'controller-0',
  'deployed': True,
  'secs_since_ack': 20,
  'patch_failed': True,
  'stale_details': False,
  'latest_sysroot_commit': '95139a5067',
  'nodetype': 'controller',
  'subfunctions': ['controller', 'worker'],
  'sw_version': '24.03',
  'state': 'install-failed',
  'allow_insvc_patching': True,
  'interim_state': False,
  'reboot_required': False}]
}


fixtures = {
    '/v1/software/host_list':
    {
        'GET': (
            {},
            HOST_LIST,
        ),
    },
    '/v1/software/deploy_show':
    {
        'GET': (
            {},
            {},
        ),
    },
    '/v1/software/deploy_precheck/1':
    {
        'GET': (
            {},
            {},
        ),
    },
    '/v1/software/deploy_precheck/1/force?region_name=RegionOne':
    {
        'POST': (
            {},
            {},
        ),
    },
    '/v1/software/deploy_start/1/force':
    {
        'POST': (
            {},
            {},
        ),
    },
    '/v1/software/deploy_host/1/force':
    {
        'POST': (
            {},
            {"error": True},
        ),
    },
    '/v1/software/deploy_activate/1':
    {
        'POST': (
            {},
            {},
        ),
    },
    '/v1/software/deploy_complete/1':
    {
        'POST': (
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


class DeployManagerTest(testtools.TestCase):

    def setUp(self):
        super(DeployManagerTest, self).setUp()
        self.api = utils.FakeAPI(fixtures)
        self.mgr = software_client.v1.deploy.DeployManager(self.api)

    def test_host_list(self):
        hosts = self.mgr.host_list()
        expect = [
            ('GET', '/v1/software/host_list', {}, None),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertEqual(len(hosts), 2)
        self.assertEqual(hosts[1]['data'][0]['hostname'],
                         HOST_LIST['data'][0]['hostname'])

    def test_show(self):
        deploy = self.mgr.show()
        expect = [
            ('GET', '/v1/software/deploy_show', {}, None),
        ]
        self.assertEqual(self.api.calls, expect)

    def test_precheck(self):
        input = {'deployment': '1', 'region_name': 'RegionOne', 'force': 1}
        args = Args(**input)
        check = self.mgr.precheck(args)
        expect = [
            ('POST', '/v1/software/deploy_precheck/1/force?region_name=RegionOne', {}, {}),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertEqual(len(check), 2)

    def test_start(self):
        input = {'deployment': '1', 'force': 1}
        args = Args(**input)
        resp = self.mgr.start(args)
        expect = [
            ('POST', '/v1/software/deploy_start/1/force', {}, {}),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertEqual(len(resp), 2)

    def test_host(self):
        input = {'agent': '1', 'force': 1}
        args = Args(**input)
        resp = self.mgr.host(args)
        expect = [
            ('POST', '/v1/software/deploy_host/1/force', {}, {}),
        ]
        self.assertEqual(self.api.calls, expect)

    def test_activate(self):
        input = {'deployment': '1'}
        args = Args(**input)
        resp = self.mgr.activate(args)
        expect = [
            ('POST', '/v1/software/deploy_activate/1', {}, {}),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertEqual(len(resp), 2)

    def test_complete(self):
        input = {'deployment': '1'}
        args = Args(**input)
        resp = self.mgr.complete(args)
        expect = [
            ('POST', '/v1/software/deploy_complete/1', {}, {}),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertEqual(len(resp), 2)
