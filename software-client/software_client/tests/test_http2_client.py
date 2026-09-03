#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# pylint: disable=unused-argument,protected-access
# pylint: disable=wrong-import-position,ungrouped-imports,reimported
import sys
import unittest.mock
for _m in ["jwkest", "jwkest.jwk", "jwkest.jws",
           "oic", "oic.exception", "oic.oic", "oic.oic.message",
           "oic.utils", "oic.utils.keyio", "oic.utils.jwt"]:
    sys.modules.setdefault(_m, unittest.mock.MagicMock())

import unittest  # noqa: E402
from unittest.mock import patch, MagicMock  # noqa: H301,E402

from software_client.common import http2  # noqa: E402
from software_client import exc as exceptions  # noqa: E402


class TestResponse(unittest.TestCase):
    def test_init(self):
        r = http2.Response(200, '{"ok": true}')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.text, '{"ok": true}')


class TestHTTPClientInit(unittest.TestCase):
    @patch('httplib2.Http.__init__', return_value=None)
    def test_basic(self, mock_init):
        c = http2.HTTPClient("http://localhost:5497", token="tok",
                             api_version="1")
        self.assertEqual(c.endpoint_url, "http://localhost:5497")
        self.assertEqual(c.auth_token, "tok")
        self.assertEqual(c.api_version, "v1")

    @patch('httplib2.Http.__init__', return_value=None)
    def test_https(self, mock_init):
        c = http2.HTTPClient("https://localhost:5497", token="tok",
                             api_version="1", insecure=True)
        self.assertTrue(c.disable_ssl_certificate_validation)

    @patch('httplib2.Http.__init__', return_value=None)
    def test_oidc(self, mock_init):
        c = http2.HTTPClient("http://localhost:5497", token="tok",
                             api_version="1", stx_auth_type="oidc",
                             oidc_username="user")
        self.assertTrue(c.oidc_auth)
        self.assertEqual(c.oidc_username, "user")

    @patch('httplib2.Http.__init__', return_value=None)
    def test_ca_file_kwarg(self, mock_init):
        c = http2.HTTPClient("http://localhost:5497", token="tok",
                             api_version="1", ca_file="/path/ca.pem")
        self.assertEqual(c.ca_file, "/path/ca.pem")


class TestHTTPClientCsRequest(unittest.TestCase):
    @patch('httplib2.Http.__init__', return_value=None)
    def setUp(self, mock_init):  # pylint: disable=arguments-differ
        self.client = http2.HTTPClient("http://localhost:5497",
                                       token="tok", api_version="1")
        self.client.connections = {}

    @patch('httplib2.Http.request')
    def test_success(self, mock_request):
        mock_request.return_value = (
            {'status': '200'}, b'{"result": "ok"}'
        )
        resp, _body = self.client._cs_request(
            "http://localhost:5497/v1/release", "GET")
        self.assertEqual(resp.status_code, 200)

    @patch('httplib2.Http.request', side_effect=Exception("conn refused"))
    def test_connection_error(self, mock_request):
        with self.assertRaises(exceptions.CommunicationError):
            self.client._cs_request("http://localhost:5497/v1/release", "GET")

    @patch('software_client.common.http2.oidc_utils.get_oidc_token',
           return_value="oidc-tok-123")
    @patch('httplib2.Http.request')
    def test_oidc_auth(self, mock_request, mock_oidc):
        self.client.oidc_auth = True
        self.client.oidc_username = "user"
        mock_request.return_value = ({'status': '200'}, b'{}')
        self.client._cs_request("http://localhost:5497/v1/x", "GET")
        # Verify OIDC token was set
        call_kwargs = mock_request.call_args
        self.assertIn("OIDC-Token", call_kwargs[1].get('headers', {}))


class TestHTTPClientGetOidcToken(unittest.TestCase):
    @patch('httplib2.Http.__init__', return_value=None)
    def setUp(self, mock_init):  # pylint: disable=arguments-differ
        self.client = http2.HTTPClient("http://localhost:5497",
                                       token="tok", api_version="1",
                                       stx_auth_type="oidc",
                                       oidc_username="user")

    @patch('software_client.common.http2.oidc_utils.get_oidc_token',
           return_value="oidc-token")
    def test_success(self, mock_get):
        self.client._get_oidc_token()
        self.assertEqual(self.client.oidc_token, "oidc-token")

    @patch('software_client.common.http2.oidc_utils.get_oidc_token',
           return_value=None)
    def test_missing_raises(self, mock_get):
        with self.assertRaises(exceptions.OidcCredentialsMissing):
            self.client._get_oidc_token()


class TestHTTPClientJsonRequest(unittest.TestCase):
    @patch('httplib2.Http.__init__', return_value=None)
    def setUp(self, mock_init):  # pylint: disable=arguments-differ
        self.client = http2.HTTPClient("http://localhost:5497",
                                       token="tok", api_version="1")
        self.client.connections = {}

    @patch('httplib2.Http.request')
    def test_get(self, mock_request):
        mock_request.return_value = (
            {'status': '200'}, b'{"data": "value"}'
        )
        resp, _body = self.client.json_request("GET", "/v1/release")
        self.assertEqual(resp.status_code, 200)


class TestHTTPClientRawRequest(unittest.TestCase):
    @patch('httplib2.Http.__init__', return_value=None)
    def setUp(self, mock_init):  # pylint: disable=arguments-differ
        self.client = http2.HTTPClient("http://localhost:5497",
                                       token="tok", api_version="1")
        self.client.connections = {}

    @patch('httplib2.Http.request')
    def test_raw(self, mock_request):
        mock_request.return_value = ({'status': '200'}, b'binary')
        resp, _body = self.client.raw_request("GET", "/v1/file")
        self.assertEqual(resp.status_code, 200)


class TestHTTPClientUploadMultipart(unittest.TestCase):
    @patch('httplib2.Http.__init__', return_value=None)
    def setUp(self, mock_init):  # pylint: disable=arguments-differ
        self.client = http2.HTTPClient("http://localhost:5497",
                                       token="tok", api_version="1")

    @patch('software_client.common.http2.requests.post')
    def test_upload(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"info": "uploaded"}
        mock_post.return_value = mock_resp
        _resp, body = self.client.upload_request_with_multipart(
            "POST", "/v1/release",
            body=b"data", headers={"Content-Type": "multipart/form-data"})
        self.assertEqual(body, {"info": "uploaded"})

    @patch('software_client.common.http2.requests.post')
    def test_upload_with_cert(self, mock_post):
        self.client.cert_file = "/path/cert.pem"
        self.client.key_file = "/path/key.pem"
        self.client.disable_ssl_certificate_validation = False
        mock_resp = MagicMock()
        mock_resp.json.return_value = {}
        mock_post.return_value = mock_resp
        self.client.upload_request_with_multipart(
            "POST", "/v1/release",
            body=b"data", headers={})
        call_kwargs = mock_post.call_args[1]
        self.assertEqual(
            call_kwargs["cert"],
            ("/path/cert.pem", "/path/key.pem"))

    @patch('software_client.common.http2.requests.post')
    def test_upload_insecure(self, mock_post):
        self.client.disable_ssl_certificate_validation = True
        mock_resp = MagicMock()
        mock_resp.json.return_value = {}
        mock_post.return_value = mock_resp
        self.client.upload_request_with_multipart(
            "POST", "/v1/release",
            body=b"data", headers={})
        call_kwargs = mock_post.call_args[1]
        self.assertFalse(call_kwargs["verify"])


class TestHTTPClientGetConnectionUrl(unittest.TestCase):
    @patch('httplib2.Http.__init__', return_value=None)
    def test_version_in_both(self, mock_init):
        c = http2.HTTPClient(
            "http://localhost:5497/v1",
            token="t",
            api_version="1")
        url = c._get_connection_url("/v1/release")
        self.assertIn("/release", url)
        # Should not have double /v1/v1
        self.assertNotIn("/v1/v1", url)

    @patch('httplib2.Http.__init__', return_value=None)
    def test_version_in_neither(self, mock_init):
        c = http2.HTTPClient(
            "http://localhost:5497",
            token="t",
            api_version="1")
        url = c._get_connection_url("/release")
        self.assertIn("/v1/", url)


class TestGetConnectionParams(unittest.TestCase):
    def test_http(self):
        _cls, args, _kwargs = http2.HTTPClient.get_connection_params(
            "http://localhost:5497/v1")
        self.assertEqual(args[0], "localhost")
        self.assertEqual(args[1], 5497)

    def test_https(self):
        _cls, _args, kwargs = http2.HTTPClient.get_connection_params(
            "https://localhost:5497/v1", ca_file="/ca.pem")
        self.assertEqual(kwargs["ca_file"], "/ca.pem")

    def test_unsupported_scheme(self):
        with self.assertRaises(exceptions.EndpointException):
            http2.HTTPClient.get_connection_params("ftp://localhost/v1")


class TestGetStatusCode(unittest.TestCase):
    @patch('httplib2.Http.__init__', return_value=None)
    def test_status_int(self, mock_init):
        c = http2.HTTPClient(
            "http://localhost:5497",
            token="t",
            api_version="1")
        resp = MagicMock(status_int=200)
        self.assertEqual(c.get_status_code(resp), 200)

    @patch('httplib2.Http.__init__', return_value=None)
    def test_status(self, mock_init):
        c = http2.HTTPClient(
            "http://localhost:5497",
            token="t",
            api_version="1")
        resp = MagicMock(spec=['status'])
        resp.status = 404
        self.assertEqual(c.get_status_code(resp), 404)


class TestHttpLogResp(unittest.TestCase):
    def test_debug_enabled(self):
        logger = MagicMock()
        logger.isEnabledFor.return_value = True
        http2.HTTPClient.http_log_resp(logger, {'status_code': 200}, "body")
        logger.debug.assert_called()  # pylint: disable=no-member

    def test_debug_disabled(self):
        logger = MagicMock()
        logger.isEnabledFor.return_value = False
        http2.HTTPClient.http_log_resp(logger, {'status_code': 200}, "body")
        logger.debug.assert_not_called()  # pylint: disable=no-member


class TestHttpLogReq(unittest.TestCase):
    def test_debug_disabled(self):
        logger = MagicMock()
        logger.isEnabledFor.return_value = False
        http2.HTTPClient.http_log_req(
            logger, ("url", "GET"), {"headers": {}})
        logger.debug.assert_not_called()  # pylint: disable=no-member

    def test_with_body(self):
        logger = MagicMock()
        logger.isEnabledFor.return_value = True
        http2.HTTPClient.http_log_req(
            logger,
            ("http://localhost/v1/deploy", "POST"),
            {"headers": {"Content-Type": "application/json"},
             "body": '{"force": true}'})
        logger.debug.assert_called()  # pylint: disable=no-member


class TestExtractErrorJsonTextModule(unittest.TestCase):
    def test_empty_body(self):
        self.assertEqual(http2._extract_error_json_text({}), {})
