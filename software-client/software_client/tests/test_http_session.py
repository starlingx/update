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

import json  # noqa: E402
import unittest  # noqa: E402
from unittest.mock import patch, MagicMock  # noqa: H301,E402

from software_client.common import http  # noqa: E402
from software_client import exc as exceptions  # noqa: E402
import software_client.software_client as sc_mod  # noqa: E402


# ===== http.ServiceCatalog =====

class TestServiceCatalog(unittest.TestCase):
    def _make_catalog(self):
        return {
            "access": {
                "token": {"id": "tok123", "expires": "2025-01-01",
                          "tenant": {"id": "tenant1"}},
                "user": {"id": "user1"},
                "serviceCatalog": [
                    {"type": "usm", "endpoints": [
                        {"publicURL": "http://usm:5497/v1",
                         "internalURL": "http://usm-int:5497/v1",
                         "region": "RegionOne"}
                    ]}
                ]
            }
        }

    def test_get_token(self):
        sc = http.ServiceCatalog(self._make_catalog())
        token = sc.get_token()
        self.assertEqual(token["id"], "tok123")
        self.assertEqual(token["user_id"], "user1")
        self.assertEqual(token["tenant_id"], "tenant1")

    def test_get_token_no_user(self):
        cat = self._make_catalog()
        del cat["access"]["user"]
        sc = http.ServiceCatalog(cat)
        token = sc.get_token()
        self.assertEqual(token["id"], "tok123")
        self.assertNotIn("user_id", token)

    def test_url_for_public(self):
        sc = http.ServiceCatalog(self._make_catalog())
        url = sc.url_for(service_type="usm", endpoint_type="publicURL")
        self.assertEqual(url, "http://usm:5497/v1")

    def test_url_for_internal(self):
        sc = http.ServiceCatalog(self._make_catalog())
        url = sc.url_for(service_type="usm", endpoint_type="internalURL")
        self.assertEqual(url, "http://usm-int:5497/v1")

    def test_url_for_with_filter(self):
        sc = http.ServiceCatalog(self._make_catalog())
        url = sc.url_for(attr="region", filter_value="RegionOne",
                         service_type="usm")
        self.assertEqual(url, "http://usm:5497/v1")

    def test_url_for_not_found(self):
        sc = http.ServiceCatalog(self._make_catalog())
        with self.assertRaises(exceptions.EndpointNotFound):
            sc.url_for(service_type="nonexistent")

    def test_url_for_ambiguous(self):
        cat = self._make_catalog()
        cat["access"]["serviceCatalog"][0]["endpoints"].append(
            {"publicURL": "http://usm2:5497/v1", "region": "RegionTwo"})
        sc = http.ServiceCatalog(cat)
        with self.assertRaises(exceptions.AmbiguousEndpoints):
            sc.url_for(service_type="usm")

    def test_url_for_endpoint_type_not_found(self):
        sc = http.ServiceCatalog(self._make_catalog())
        with self.assertRaises(exceptions.EndpointTypeNotFound):
            sc.url_for(service_type="usm", endpoint_type="adminURL",
                       attr="region", filter_value="RegionOne")


# ===== http.Response =====

class TestHttpResponse(unittest.TestCase):
    def test_string(self):
        r = http.Response(200, "hello")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.text, "hello")

    def test_bytes(self):
        r = http.Response(201, b"bytes data")
        self.assertEqual(r.text, "bytes data")


# ===== http._extract_error_json_text =====

class TestHttpExtractErrorJsonText(unittest.TestCase):
    def test_with_error(self):
        body = {"error_message": '{"error": "fail", "info": "detail"}'}
        http._extract_error_json_text(body)

    def test_with_nested(self):
        inner = json.dumps({"faultstring": "inner", "debuginfo": "d"})
        body = {"error_message": json.dumps({"error_message": inner})}
        http._extract_error_json_text(body)

    def test_empty(self):
        self.assertEqual(http._extract_error_json_text({}), {})


# ===== http._extract_error_json =====

class TestHttpExtractErrorJson(unittest.TestCase):
    def test_json_content_type(self):
        resp = MagicMock()
        resp.headers = {"Content-Type": "application/json"}
        resp.json.return_value = {
            "error_message": '{"error": "x", "info": "y"}'}
        http._extract_error_json("", resp)

    def test_non_json_content_type_valid_body(self):
        resp = MagicMock()
        resp.headers = {"Content-Type": "text/plain"}
        body = json.dumps({"error_message": '{"error": "e", "info": "i"}'})
        http._extract_error_json(body, resp)

    def test_non_json_invalid_body(self):
        resp = MagicMock()
        resp.headers = {"Content-Type": "text/plain"}
        http._extract_error_json("not json", resp)

    def test_no_headers(self):
        resp = MagicMock(spec=[])
        http._extract_error_json("{}", resp)


# ===== http.SessionClient =====

class TestSessionClient(unittest.TestCase):
    def _make_client(self):
        with patch('keystoneauth1.adapter.LegacyJsonAdapter.__init__',
                   return_value=None):
            c = http.SessionClient(api_version="1")
        c.session = MagicMock()
        c.auth = MagicMock()
        c.endpoint_override = "http://localhost:5497/v1"
        c.interface = "internal"
        c.service_type = "usm"
        c.region_name = "RegionOne"
        return c

    def test_http_request(self):
        c = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'{"ok": true}'
        mock_resp.headers = {"content-type": "application/json"}
        c.session.request.return_value = mock_resp
        resp = c._http_request("/v1/release", "GET")
        self.assertEqual(resp.status_code, 200)

    def test_http_request_strips_version(self):
        c = self._make_client()
        mock_resp = MagicMock(status_code=200)
        c.session.request.return_value = mock_resp
        c._http_request("/v1/release", "GET")
        # URL passed to session should not start with /v1
        call_args = c.session.request.call_args[0]
        self.assertFalse(call_args[0].startswith("/v1"))

    def test_json_request_200(self):
        c = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'{"data": "val"}'
        mock_resp.text = '{"data": "val"}'
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {"data": "val"}
        c.session.request.return_value = mock_resp
        resp, body = c.json_request("GET", "/release")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(body, {"data": "val"})

    def test_json_request_204(self):
        c = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 204
        mock_resp.content = b''
        mock_resp.headers = {"content-type": "application/json"}
        c.session.request.return_value = mock_resp
        _resp, body = c.json_request("DELETE", "/deploy")
        self.assertEqual(body, [])

    def test_json_request_with_body(self):
        c = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'{}'
        mock_resp.text = '{}'
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {}
        c.session.request.return_value = mock_resp
        c.json_request("POST", "/deploy/start", body={"force": True})

    def test_multipart_request(self):
        c = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'{"info": "ok"}'
        mock_resp.text = '{"info": "ok"}'
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {"info": "ok"}
        c.session.request.return_value = mock_resp
        resp, _body = c.multipart_request("POST", "/release", body=b"data")
        self.assertEqual(resp.status_code, 200)

    def test_raw_request(self):
        c = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        c.session.request.return_value = mock_resp
        resp = c.raw_request("GET", "/file")
        self.assertEqual(resp.status_code, 200)

    def test_get_connection_url_version_in_both(self):
        c = self._make_client()
        url = c._get_connection_url("/v1/release")
        self.assertNotIn("/v1/v1", url)

    def test_get_connection_url_version_in_neither(self):
        c = self._make_client()
        c.endpoint_override = "http://localhost:5497"
        url = c._get_connection_url("/release")
        self.assertIn("/v1/", url)


# ===== software_client.py =====

class TestSoftwareCommandNotImplemented(unittest.TestCase):
    def test_prints_message(self):
        with patch('builtins.print') as mock_print:
            sc_mod.software_command_not_implemented_yet(None)
            mock_print.assert_called()


class TestSoftwareClientShell(unittest.TestCase):
    def test_get_base_parser(self):
        shell = sc_mod.SoftwareClientShell()
        parser = shell.get_base_parser()
        self.assertIsNotNone(parser)

    def test_get_subcommand_parser(self):
        shell = sc_mod.SoftwareClientShell()
        parser = shell.get_subcommand_parser("1")
        self.assertIsNotNone(parser)

    @patch('sys.stdout', new_callable=lambda: open('/dev/null', 'w'))
    def test_main_help(self, mock_stdout):
        shell = sc_mod.SoftwareClientShell()
        try:
            shell.main(["help"])
        except SystemExit:
            pass

    @patch('sys.stdout', new_callable=lambda: open('/dev/null', 'w'))
    def test_main_no_args(self, mock_stdout):
        shell = sc_mod.SoftwareClientShell()
        try:
            shell.main([])
        except SystemExit:
            pass

    def test_setup_debugging(self):
        shell = sc_mod.SoftwareClientShell()
        shell._setup_debugging(True)
