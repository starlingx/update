# Copyright 2013-2024 Wind River, Inc.
# Copyright 2012 Openstack Foundation
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
#

import copy
import httplib2
from keystoneauth1 import adapter
import logging
import os
from oslo_serialization import jsonutils
import socket

import six


try:
    import ssl
except ImportError:
    # TODO(bcwaldon): Handle this failure more gracefully
    pass

from software_client import exc as exceptions

_logger = logging.getLogger(__name__)

CHUNKSIZE = 1024 * 64  # 64kB
SENSITIVE_HEADERS = ('X-Auth-Token',)
UPLOAD_REQUEST_TIMEOUT = 1800
USER_AGENT = 'software_client'
API_VERSION = '/v1'
DEFAULT_API_VERSION = 'latest'

# httplib2 retries requests on socket.timeout which
# is not idempotent and can lead to orhan objects.
# See: https://code.google.com/p/httplib2/issues/detail?id=124
httplib2.RETRIES = 1

if os.environ.get('SOFTWARE_CLIENT_DEBUG'):
    ch = logging.StreamHandler()
    _logger.setLevel(logging.DEBUG)
    _logger.addHandler(ch)


class ServiceCatalog(object):
    """Helper methods for dealing with a Keystone Service Catalog."""

    def __init__(self, resource_dict):
        self.catalog = resource_dict

    def get_token(self):
        """Fetch token details fron service catalog."""
        token = {'id': self.catalog['access']['token']['id'],
                 'expires': self.catalog['access']['token']['expires'], }
        try:
            token['user_id'] = self.catalog['access']['user']['id']
            token['tenant_id'] = (
                self.catalog['access']['token']['tenant']['id'])
        except Exception:
            # just leave the tenant and user out if it doesn't exist
            pass
        return token

    def url_for(self, attr=None, filter_value=None,
                service_type='usm', endpoint_type='publicURL'):
        """Fetch the URL from the Neutron service for
        a particular endpoint type. If none given, return
        publicURL.
        """
        catalog = self.catalog['access'].get('serviceCatalog', [])
        matching_endpoints = []
        for service in catalog:
            if service['type'] != service_type:
                continue

            endpoints = service['endpoints']
            for endpoint in endpoints:
                if not filter_value or endpoint.get(attr) == filter_value:
                    matching_endpoints.append(endpoint)

        if not matching_endpoints:
            raise exceptions.EndpointNotFound()
        elif len(matching_endpoints) > 1:
            raise exceptions.AmbiguousEndpoints(reason=matching_endpoints)
        else:
            if endpoint_type not in matching_endpoints[0]:
                raise exceptions.EndpointTypeNotFound(reason=endpoint_type)

        return matching_endpoints[0][endpoint_type]


def _extract_error_json_text(body_json):
    error_json = {}
    if 'error_message' in body_json:
        raw_msg = body_json['error_message']
        if 'error' in raw_msg:
            raw_error = jsonutils.loads(raw_msg)
            error_json = {'faultstring': raw_error.get('error'),
                          'debuginfo': raw_error.get('info')}
        elif 'error_message' in raw_msg:
            raw_error = jsonutils.loads(raw_msg)
            raw_msg = raw_error['error_message']
            error_json = jsonutils.loads(raw_msg)
    return error_json


def _extract_error_json(body, resp):
    """Return error_message from the HTTP response body."""
    try:
        content_type = resp.headers.get("Content-Type", "")
    except AttributeError:
        content_type = ""
    if content_type.startswith("application/json"):
        try:
            body_json = resp.json()
            return _extract_error_json_text(body_json)
        except AttributeError:
            body_json = jsonutils.loads(body)
            return _extract_error_json_text(body_json)
        except ValueError:
            return {}
    else:
        try:
            body_json = jsonutils.loads(body)
            return _extract_error_json_text(body_json)
        except ValueError:
            return {}


class Response(object):
    """SessionClient and HttpClient do not return the same
    response object. This calss is to create a common response
    data to fulfill the need of CLI and also isolate the
    implementation of different Client adapters.

    For now, CLI only needs content text and the status_code
    """

    def __init__(self, status_code, text):
        self._status_code = status_code
        if isinstance(text, bytes):
            self._text = text.decode()
        else:
            self._text = text

    @property
    def status_code(self):
        return self._status_code

    @property
    def text(self):
        return self._text


class SessionClient(adapter.LegacyJsonAdapter):

    def __init__(self, *args, **kwargs):
        self.user_agent = USER_AGENT
        self.api_version = 'v' + kwargs.pop('api_version')
        super(SessionClient, self).__init__(*args, **kwargs)

    def _http_request(self, url, method, **kwargs):
        version_str = '/' + self.api_version
        if url.startswith(version_str):
            url = url[len(version_str):]

        kwargs.setdefault('user_agent', self.user_agent)
        kwargs.setdefault('auth', self.auth)
        kwargs.setdefault('endpoint_override', self.endpoint_override)

        # Copy the kwargs so we can reuse the original in case of redirects
        kwargs['headers'] = copy.deepcopy(kwargs.get('headers', {}))
        kwargs['headers'].setdefault('User-Agent', self.user_agent)

        endpoint_filter = kwargs.setdefault('endpoint_filter', {})
        endpoint_filter.setdefault('interface', self.interface)
        endpoint_filter.setdefault('service_type', self.service_type)
        endpoint_filter.setdefault('region_name', self.region_name)

        resp = self.session.request(url, method,
                                    raise_exc=False, **kwargs)
        # NOTE (bqian) Do not recreate and raise exceptions. Let the
        # display_error utility function to handle the well formatted
        # response for webob.exc.HTTPClientError
        return resp

    def json_request(self, method, url, **kwargs):
        kwargs.setdefault('headers', {})
        kwargs['headers'].setdefault('Content-Type', 'application/json')
        kwargs['headers'].setdefault('Accept', 'application/json')
        if 'body' in kwargs:
            kwargs['data'] = jsonutils.dumps(kwargs.pop('body'))

        resp = self._http_request(url, method, timeout=UPLOAD_REQUEST_TIMEOUT, **kwargs)
        body = resp.content
        content_type = resp.headers.get('content-type', None)
        status = resp.status_code
        if status == 204 or status == 205 or content_type is None:
            return resp, list()
        if 'application/json' in content_type:
            try:
                body = resp.json()
            except ValueError:
                _logger.error('Could not decode response body as JSON')
        else:
            body = None
        return Response(resp.status_code, resp.text), body

    def multipart_request(self, method, url, **kwargs):
        kwargs.setdefault('headers', {})
        kwargs['headers'].setdefault('Content-Type', 'application/json')
        kwargs['headers'].setdefault('Accept', 'application/json')
        if 'body' in kwargs:
            kwargs['data'] = kwargs.pop('body')

        resp = self._http_request(url, method, timeout=UPLOAD_REQUEST_TIMEOUT, **kwargs)
        body = resp.content
        content_type = resp.headers.get('content-type', None)
        status = resp.status_code
        if status == 204 or status == 205 or content_type is None:
            return resp, list()
        if 'application/json' in content_type:
            try:
                body = resp.json()
            except ValueError:
                _logger.error('Could not decode response body as JSON')
        else:
            body = None
        return Response(resp.status_code, resp.text), body

    def raw_request(self, method, url, **kwargs):
        kwargs.setdefault('headers', {})
        kwargs['headers'].setdefault('Content-Type',
                                     'application/octet-stream')
        return self._http_request(url, method, **kwargs)

    def _get_connection_url(self, url):
        endpoint = self.endpoint_override
        version = self.api_version
        # if 'v1 in both, remove 'v1' from endpoint
        if version in endpoint and version in url:
            endpoint = endpoint.replace('/' + version, '', 1)
        # if 'v1 not in both, add 'v1' to endpoint
        elif version not in endpoint and version not in url:
            endpoint = endpoint.rstrip('/') + '/' + version

        return endpoint.rstrip('/') + '/' + url.lstrip('/')


class VerifiedHTTPSConnection(six.moves.http_client.HTTPSConnection):
    """httplib-compatibile connection using client-side SSL authentication

    :see http://code.activestate.com/recipes/
            577548-https-httplib-client-connection-with-certificate-v/
    """

    def __init__(self, host, port, key_file=None, cert_file=None,
                 ca_file=None, timeout=None, insecure=False):
        six.moves.http_client.HTTPSConnection.__init__(self, host, port,
                                                       key_file=key_file,
                                                       cert_file=cert_file)
        self.key_file = key_file
        self.cert_file = cert_file
        if ca_file is not None:
            self.ca_file = ca_file
        else:
            self.ca_file = self.get_system_ca_file()
        self.timeout = timeout
        self.insecure = insecure

    def connect(self):
        """Connect to a host on a given (SSL) port.
        If ca_file is pointing somewhere, use it to check Server Certificate.

        Redefined/copied and extended from httplib.py:1105 (Python 2.6.x).
        This is needed to pass cert_reqs=ssl.CERT_REQUIRED as parameter to
        ssl.wrap_socket(), which forces SSL to check server certificate against
        our client certificate.
        """
        sock = socket.create_connection((self.host, self.port), self.timeout)

        if self._tunnel_host:
            self.sock = sock
            self._tunnel()

        if self.insecure is True:
            kwargs = {'cert_reqs': ssl.CERT_NONE}
        else:
            kwargs = {'cert_reqs': ssl.CERT_REQUIRED, 'ca_certs': self.ca_file}

        if self.cert_file:
            kwargs['certfile'] = self.cert_file
            if self.key_file:
                kwargs['keyfile'] = self.key_file

        self.sock = ssl.wrap_socket(sock, **kwargs)

    @staticmethod
    def get_system_ca_file():
        """Return path to system default CA file."""
        # Standard CA file locations for Debian/Ubuntu, RedHat/Fedora,
        # Suse, FreeBSD/OpenBSD
        ca_path = ['/etc/ssl/certs/ca-certificates.crt',
                   '/etc/pki/tls/certs/ca-bundle.crt',
                   '/etc/ssl/ca-bundle.pem',
                   '/etc/ssl/cert.pem']
        for ca in ca_path:
            if os.path.exists(ca):
                return ca
        return None


class ResponseBodyIterator(object):
    """A class that acts as an iterator over an HTTP response."""

    def __init__(self, resp):
        self.resp = resp

    def __iter__(self):
        while True:
            yield six.next()  # pylint: disable=next-method-called

    def next(self):  # pylint: disable=next-method-defined
        chunk = self.resp.read(CHUNKSIZE)
        if chunk:
            return chunk
        else:
            raise StopIteration()


def construct_http_client(endpoint=None, endpoint_type=None, **kwargs):

    session = kwargs.pop('session', None)
    auth = kwargs.pop('auth', None)

    # SessionClient
    if 'endpoint_override' not in kwargs and endpoint:
        kwargs['endpoint_override'] = endpoint

    if 'service_type' not in kwargs:
        kwargs['service_type'] = 'usm'

    if 'interface' not in kwargs and endpoint_type:
        kwargs['interface'] = endpoint_type

    if 'region_name' in kwargs:
        kwargs['additional_headers'] = {
            'X-Region-Name': kwargs['region_name']}

    return SessionClient(session, auth=auth, **kwargs)
