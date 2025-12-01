# Copyright 2013-2025 Wind River, Inc.
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
import hashlib
import httplib2
import logging
import os
from oslo_serialization import jsonutils
from oslo_utils import encodeutils
import requests
import socket
from pecan.core import Response as PCResponse

import six
from six.moves.urllib.parse import urlparse
from platform_util.oidc import oidc_utils


try:
    import ssl
except ImportError:
    # TODO(bcwaldon): Handle this failure more gracefully
    pass

try:
    import json
except ImportError:
    import simplejson as json

from software_client import exc as exceptions

_logger = logging.getLogger(__name__)

CHUNKSIZE = 1024 * 64  # 64kB
SENSITIVE_HEADERS = ('X-Auth-Token', 'OIDC-Token')
UPLOAD_REQUEST_TIMEOUT = 1800
USER_AGENT = 'software_client'
API_VERSION = '/v1'
DEFAULT_API_VERSION = 'latest'
OIDC = 'oidc'

# httplib2 retries requests on socket.timeout which
# is not idempotent and can lead to orhan objects.
# See: https://code.google.com/p/httplib2/issues/detail?id=124
httplib2.RETRIES = 1

if os.environ.get('SOFTWARE_CLIENT_DEBUG'):
    ch = logging.StreamHandler()
    _logger.setLevel(logging.DEBUG)
    _logger.addHandler(ch)


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


class HTTPClient(httplib2.Http):
    """Handles the REST calls and responses, include authn."""

    #################
    # INIT
    #################
    def __init__(self, endpoint,
                 username=None, tenant_name=None, tenant_id=None,
                 password=None, auth_url=None,
                 token=None, region_name=None, timeout=7200,
                 endpoint_url=None, insecure=False,
                 endpoint_type='publicURL',
                 ca_cert=None, log_credentials=False,
                 **kwargs):
        if 'ca_file' in kwargs and kwargs['ca_file']:
            ca_cert = kwargs['ca_file']

        super(HTTPClient, self).__init__(timeout=timeout, ca_certs=ca_cert)

        self.username = username
        self.tenant_name = tenant_name
        self.tenant_id = tenant_id
        self.password = password
        self.auth_url = auth_url.rstrip('/') if auth_url else None
        self.endpoint_type = endpoint_type
        self.region_name = region_name
        self.auth_token = token
        self.auth_tenant_id = None
        self.auth_user_id = None
        self.content_type = 'application/json'
        self.endpoint_url = endpoint
        self.log_credentials = log_credentials
        self.connection_params = self.get_connection_params(self.endpoint_url, **kwargs)
        self.local_root = kwargs.get('local_root', False)
        self.api_version = 'v' + kwargs.pop('api_version')

        # oidc params
        self.oidc_token = None
        self.oidc_auth = kwargs.get('stx_auth_type') == OIDC
        self.oidc_username = kwargs.get('oidc_username', None)

        # httplib2 overrides
        self.disable_ssl_certificate_validation = insecure
        self.ca_file = kwargs.get('ca_file', None)
        self.cert_file = kwargs.get('cert_file', None)
        self.key_file = kwargs.get('key_file', None)

        self.service_catalog = None

    #################
    # REQUEST
    #################

    @staticmethod
    def http_log_resp(_logger, resp, body=None):
        if not _logger.isEnabledFor(logging.DEBUG):
            return

        resp_status_code = resp.get('status_code') or ""
        resp_headers = resp.get('headers') or ""
        _logger.debug("RESP:%(code)s %(headers)s %(body)s\n",
                      {'code': resp_status_code,
                       'headers': resp_headers,
                       'body': body})

    @staticmethod
    def http_log_req(_logger, args, kwargs):
        if not _logger.isEnabledFor(logging.DEBUG):
            return

        string_parts = ['curl -i']
        for element in args:
            if element in ('GET', 'POST', 'DELETE', 'PUT'):
                string_parts.append(' -X %s' % element)
            else:
                string_parts.append(' %s' % element)

        for (key, value) in kwargs['headers'].items():
            if key in SENSITIVE_HEADERS:
                v = value.encode('utf-8')
                h = hashlib.sha256(v)
                d = h.hexdigest()
                value = "{SHA256}%s" % d
            header = ' -H "%s: %s"' % (key, value)
            string_parts.append(header)

        if 'body' in kwargs and kwargs['body']:
            string_parts.append(" -d '%s'" % (kwargs['body']))
            req = encodeutils.safe_encode("".join(string_parts))
            _logger.debug("REQ: %s", req)

    def _cs_request(self, *args, **kwargs):
        kargs = {}
        kargs.setdefault('headers', kwargs.get('headers', {}))

        if 'content_type' in kwargs:
            kargs['headers']['Content-Type'] = kwargs['content_type']
            kargs['headers']['Accept'] = kwargs['content_type']
        elif 'Content-Type' not in kargs['headers']:
            kargs['headers']['Content-Type'] = self.content_type
            kargs['headers']['Accept'] = self.content_type

        if self.oidc_auth:
            self._get_oidc_token()
            kargs['headers']['OIDC-Token'] = self.oidc_token
        elif self.auth_token:
            kargs['headers']['X-Auth-Token'] = self.auth_token

        if 'body' in kwargs:
            kargs['body'] = kwargs['body']
        if self.log_credentials:
            log_kargs = kargs
        else:
            log_kargs = self._strip_credentials(kargs)

        self.http_log_req(_logger, args, log_kargs)
        try:
            response, body = self.request(*args, **kargs)
            resp = PCResponse(body=body, status=response.get('status', None))
        except requests.exceptions.SSLError as e:
            raise exceptions.SslCertificateValidationError(reason=str(e))
        except Exception as e:
            # Wrap the low-level connection error (socket timeout, redirect
            # limit, decompression error, etc) into our custom high-level
            # connection exception (it is excepted in the upper layers of code)
            _logger.debug("throwing ConnectionFailed : %s", e)
            raise exceptions.CommunicationError(str(e))
        finally:
            # Temporary Fix for gate failures. RPC calls and HTTP requests
            # seem to be stepping on each other resulting in bogus fd's being
            # picked up for making http requests
            self.connections.clear()

        # NOTE (bqian) Do not recreate and raise exceptions. Let the
        # display_error utility function to handle the well formatted
        # response for webob.exc.HTTPClientError

        return resp, body

    def _get_oidc_token(self):
        """Gets the auth data. Need to be called for every OIDC request."""
        oidc_token = oidc_utils.get_oidc_token(self.oidc_username)
        if oidc_token is None:
            raise exceptions.OidcCredentialsMissing()

        self.oidc_token = oidc_token

    def json_request(self, method, url, **kwargs):
        kwargs.setdefault('headers', {})
        kwargs['headers'].setdefault('Content-Type', 'application/json')
        kwargs['headers'].setdefault('Accept', 'application/json')

        if 'body' in kwargs:
            kwargs['body'] = json.dumps(kwargs['body'])

        connection_url = self._get_connection_url(url)
        resp, body_iter = self._cs_request(connection_url,
                                           method, **kwargs)

        return Response(resp.status_code, resp.text), resp.json_body

    def multipart_request(self, method, url, **kwargs):
        return self.upload_request_with_multipart(method, url, **kwargs)

    def raw_request(self, method, url, **kwargs):
        kwargs.setdefault('headers', {})
        kwargs['headers'].setdefault('Content-Type',
                                     'application/octet-stream')
        connection_url = self._get_connection_url(url)
        return self._cs_request(connection_url, method, **kwargs)

    def upload_request_with_multipart(self, method, url, **kwargs):
        connection_url = self._get_connection_url(url)
        if self.oidc_auth:
            self._get_oidc_token()
            kwargs['headers']['OIDC-Token'] = self.oidc_token
        else:
            kwargs['headers']['X-Auth-Token'] = self.auth_token

        if self.disable_ssl_certificate_validation:
            verify = False
        else:
            verify = self.ca_file or True

        # 'cert' is path to ssl client cert file or cert and key as a tuple
        cert = self.cert_file
        if cert and self.key_file:
            cert = (cert, self.key_file)

        response = requests.post(connection_url,
                                 data=kwargs.get('body'),
                                 headers=kwargs.get('headers'),
                                 verify=verify,
                                 cert=cert,
                                 timeout=UPLOAD_REQUEST_TIMEOUT)

        return response, response.json()

    def _extract_error_json(self, body):
        error_json = {}
        try:
            body_json = json.loads(body)
            if 'error' in body_json:
                error_json = {'faultstring': body_json.get('error'),
                              'debuginfo': body_json.get('info')}
            elif 'error_message' in body_json:
                raw_msg = body_json['error_message']
                error_json = json.loads(raw_msg)
        except ValueError:
            return {}

        return error_json

    def _strip_credentials(self, kwargs):
        if kwargs.get('body') and self.password:
            log_kwargs = kwargs.copy()
            log_kwargs['body'] = kwargs['body'].replace(self.password,
                                                        'REDACTED')
            return log_kwargs
        else:
            return kwargs

    def _get_connection_url(self, url):
        (_class, _args, _kwargs) = self.connection_params
        base_url = _args[2]
        # Since some packages send endpoint with 'v1' and some don't,
        # the postprocessing for both options will be done here
        # Instead of doing a fix in each of these packages
        endpoint = self.endpoint_url
        version = self.api_version
        # if 'v1 in both, remove 'v1' from endpoint
        if version in base_url and version in url:
            endpoint = endpoint.replace('/' + version, '', 1)
        # if 'v1 not in both, add 'v1' to endpoint
        elif version not in base_url and version not in url:
            endpoint = endpoint.rstrip('/') + '/' + version

        return endpoint.rstrip('/') + '/' + url.lstrip('/')

    @staticmethod
    def get_connection_params(endpoint, **kwargs):
        parts = urlparse(endpoint)

        _args = (parts.hostname, parts.port, parts.path)
        _kwargs = {'timeout': (float(kwargs.get('timeout'))
                               if kwargs.get('timeout') else 600)}

        if parts.scheme == 'https':
            _class = VerifiedHTTPSConnection
            _kwargs['ca_file'] = kwargs.get('ca_file', None)
            _kwargs['cert_file'] = kwargs.get('cert_file', None)
            _kwargs['key_file'] = kwargs.get('key_file', None)
            _kwargs['insecure'] = kwargs.get('insecure', False)
        elif parts.scheme == 'http':
            _class = six.moves.http_client.HTTPConnection
        else:
            msg = 'Unsupported scheme: %s' % parts.scheme
            raise exceptions.EndpointException(reason=msg)

        return (_class, _args, _kwargs)

    def get_status_code(self, response):
        """Returns the integer status code from the response.

        Either a Webob.Response (used in testing) or httplib.Response
        is returned.
        """
        if hasattr(response, 'status_int'):
            return response.status_int
        else:
            return response.status


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


def construct_http_client(endpoint, username=None, password=None,
                          endpoint_type=None, auth_url=None, **kwargs):

    # httplib2
    return HTTPClient(endpoint=endpoint, username=username,
                      password=password, endpoint_type=endpoint_type,
                      auth_url=auth_url, **kwargs)
