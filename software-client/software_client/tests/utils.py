# Copyright 2024 Wind River Systems, Inc.
# Copyright 2012 OpenStack LLC.
# All Rights Reserved.
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

import copy
import fixtures
import testtools

from software_client.common import http
from six import StringIO


class BaseTestCase(testtools.TestCase):

    def setUp(self):
        super(BaseTestCase, self).setUp()
        self.useFixture(fixtures.FakeLogger())


class FakeAPI(object):
    def __init__(self, fixtures):
        self.fixtures = fixtures
        self.calls = []

    def _request(self, method, url, headers=None, body=None):
        call = (method, url, headers or {}, body)
        self.calls.append(call)
        return self.fixtures[url][method]

    def raw_request(self, *args, **kwargs):
        fixture = self._request(*args, **kwargs)
        body_iter = http.ResponseBodyIterator(StringIO(fixture[1]))
        return FakeResponse(fixture[0]), body_iter

    def json_request(self, *args, **kwargs):
        fixture = self._request(*args, **kwargs)
        return FakeResponse(fixture[0]), fixture[1]

    def upload_request_with_multipart(self, *args, **kwargs):
        # TODO(gdossant): add 'data' parameter to _request method.
        # It will impact more than 40 tests and must be done in
        # a specific commit.

        kwargs.pop('check_exceptions')
        data = kwargs.pop('data')

        fixture = self._request(*args, **kwargs)

        call = list(self.calls[0])
        call.append(data)
        self.calls[0] = tuple(call)

        return fixture[1]


class FakeResponse(object):
    def __init__(self, headers, body=None, version=None):
        """:param headers: dict representing HTTP response headers
        :param body: file-like object
        """
        self.headers = headers
        self.body = body
        self.status_code = 200

    def getheaders(self):
        return copy.deepcopy(self.headers).items()

    def getheader(self, key, default):
        return self.headers.get(key, default)

    def read(self, amt):
        return self.body.read(amt)
