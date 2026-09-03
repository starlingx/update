#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# pylint: disable=unused-argument,protected-access,too-many-arguments
# pylint: disable=wrong-import-position,ungrouped-imports,reimported
import sys
import unittest.mock
for _m in ["jwkest", "jwkest.jwk", "jwkest.jws",
           "oic", "oic.exception", "oic.oic", "oic.oic.message",
           "oic.utils", "oic.utils.keyio", "oic.utils.jwt"]:
    sys.modules.setdefault(_m, unittest.mock.MagicMock())

import os  # noqa: E402
import unittest  # noqa: E402
from unittest.mock import patch, MagicMock  # noqa: H301,E402

from software_client.auth import oidc_client  # noqa: E402
from software_client.auth import ks_client  # noqa: E402
from software_client.auth import get_client  # noqa: E402
from software_client import exc  # noqa: E402
from software_client import constants  # noqa: E402
from software_client.common import http  # noqa: E402
import software_client.software_client as sc_mod  # noqa: E402
from software_client.v1.release import ReleaseManager as RM2  # noqa: E402


# ===== auth/__init__.py get_client =====

class TestGetClient(unittest.TestCase):
    @patch('software_client.auth.get_ks_client')
    def test_keystone(self, mock_ks):
        mock_ks.return_value = MagicMock()
        get_client("1", constants.KEYSTONE, endpoint="http://ep")
        mock_ks.assert_called()

    @patch('software_client.auth.get_http_client')
    def test_local_root(self, mock_http):
        mock_http.return_value = MagicMock()
        get_client("1", constants.LOCAL_ROOT)
        mock_http.assert_called()

    @patch('software_client.auth.get_http_client')
    def test_token(self, mock_http):
        mock_http.return_value = MagicMock()
        get_client(
            "1",
            constants.TOKEN,
            endpoint="http://ep",
            os_auth_token="tok")
        mock_http.assert_called()

    @patch('software_client.auth.validate_oidc_params')
    @patch('software_client.auth.build_oidc_endpoint',
           return_value="http://ep/v1")
    @patch('software_client.auth.get_oidc_client')
    def test_oidc(self, mock_oidc, mock_build, mock_validate):
        mock_oidc.return_value = MagicMock()
        get_client(
            "1",
            constants.OIDC,
            os_auth_url="http://ks",
            os_username="u")
        mock_oidc.assert_called()


# ===== auth/oidc_client =====

class TestValidateOidcParams(unittest.TestCase):
    def test_valid(self):
        oidc_client.validate_oidc_params(
            os_auth_url="http://ks", os_username="u")

    def test_missing_params(self):
        with self.assertRaises(exc.InvalidEndpoint):
            oidc_client.validate_oidc_params(
                os_auth_url=None, os_username=None)


class TestBuildOidcEndpoint(unittest.TestCase):
    def test_public(self):
        ep = oidc_client.build_oidc_endpoint(
            "1", os_auth_url="https://ctrl:5000/v3",
            os_endpoint_type="publicURL", os_region_name="RegionOne")
        self.assertIn("https://", ep)
        self.assertIn("/v1", ep)

    def test_internal(self):
        ep = oidc_client.build_oidc_endpoint(
            "1", os_auth_url="http://ctrl:5000/v3",
            os_endpoint_type="internalURL", os_region_name="RegionOne")
        self.assertIn("http://", ep)

    def test_ipv6(self):
        ep = oidc_client.build_oidc_endpoint(
            "1", os_auth_url="http://[::1]:5000/v3",
            os_endpoint_type="internalURL", os_region_name="RegionOne")
        self.assertIn("[", ep)


class TestNormalizeInterface(unittest.TestCase):
    def test_public_url(self):
        oidc_client._normalize_interface("publicURL")
        result = oidc_client._normalize_interface("publicURL")
        self.assertEqual(result, constants.PUBLIC)

    def test_internal_url(self):
        oidc_client._normalize_interface("internalURL")
        result = oidc_client._normalize_interface("internalURL")
        self.assertEqual(result, constants.INTERNAL)

    def test_unknown(self):
        oidc_client._normalize_interface("unknown")
        result = oidc_client._normalize_interface("unknown")
        self.assertEqual(result, constants.PUBLIC)


class TestGetOidcClient(unittest.TestCase):
    @patch('software_client.auth.oidc_client.importutils.'
           'import_versioned_module')
    @patch('software_client.auth.oidc_client.http2.construct_http_client')
    def test_success(self, mock_http, mock_import):
        mock_http.return_value = MagicMock()
        mock_module = MagicMock()
        mock_module.Client.return_value = MagicMock()
        mock_import.return_value = mock_module
        oidc_client.get_oidc_client("1", "http://ep",
                                    stx_auth_type="oidc",
                                    os_username="user")
        result = oidc_client.get_oidc_client(
            "1", "http://ep", stx_auth_type="oidc", os_username="user")
        self.assertIsNotNone(result)


# ===== auth/ks_client =====

class TestMakeSession(unittest.TestCase):
    @patch('keystoneauth1.loading.session.Session')
    @patch('keystoneauth1.loading.get_plugin_loader')
    def test_with_credentials(self, mock_loader, mock_sess_cls):
        mock_loader.return_value.load_from_options.return_value = MagicMock()
        mock_sess_cls.return_value.load_from_options.return_value = MagicMock()
        session = ks_client._make_session(
            os_username="admin", os_password="pass",
            os_auth_url="http://ks:5000/v3", os_project_name="admin")
        self.assertIsNotNone(session)

    def test_without_credentials(self):
        session = ks_client._make_session()
        self.assertIsNone(session)


class TestGetKsClient(unittest.TestCase):
    def test_with_endpoint(self):
        with patch.object(ks_client, '_make_session') as mock_session:
            with patch.object(ks_client, 'Client') as mock_client:
                mock_session.return_value = MagicMock()
                mock_client.return_value = MagicMock()
                ks_client.get_ks_client("1", endpoint="http://ep/v1",
                                        os_username="admin", os_password="p",
                                        os_auth_url="http://ks:5000",
                                        os_project_name="admin",
                                        system_api_version="1")

    def test_no_session_no_endpoint(self):
        with patch.object(ks_client, '_make_session', return_value=None):
            with self.assertRaises(exc.AmbigiousAuthSystem):  # noqa: H202
                ks_client.get_ks_client("1")

    def test_session_gets_endpoint(self):
        mock_sess = MagicMock()
        mock_sess.get_endpoint.return_value = "http://usm:5493/v1"
        with patch.object(ks_client, '_make_session', return_value=mock_sess):
            with patch.object(ks_client, 'Client') as mock_client:
                mock_client.return_value = MagicMock()
                ks_client.get_ks_client("1", os_endpoint_type="internal",
                                        os_region_name="RegionOne",
                                        system_api_version="1")


# ===== software_client.py check functions =====

class TestCheckForOsRegionName(unittest.TestCase):
    @patch.dict(os.environ, {"OS_REGION_NAME": "RegionOne"}, clear=False)
    def test_from_env(self):
        args = MagicMock(os_region_name=None)
        sc_mod.check_for_os_region_name(args)

    def test_already_set(self):
        args = MagicMock(os_region_name="R1")
        sc_mod.check_for_os_region_name(args)
        self.assertEqual(args.os_region_name, "R1")


class TestCheckKeystoneCredentials(unittest.TestCase):
    def test_all_present(self):
        args = MagicMock(os_username="admin", os_password="pass",
                         os_project_id=None, os_project_name="admin",
                         os_auth_url="http://ks:5000", os_region_name="R1")
        sc_mod.check_keystone_credentials(args)

    def test_missing_username(self):
        args = MagicMock(os_username=None)
        sc_mod.check_keystone_credentials(args)

    def test_missing_password_not_root(self):
        args = MagicMock(os_username="admin", os_password=None)
        with patch('os.geteuid', return_value=1000):
            sc_mod.check_keystone_credentials(args)

    def test_missing_project(self):
        args = MagicMock(os_username="admin", os_password="pass",
                         os_project_id=None, os_project_name=None)
        sc_mod.check_keystone_credentials(args)

    def test_missing_auth_url(self):
        args = MagicMock(os_username="admin", os_password="pass",
                         os_project_id="id", os_project_name=None,
                         os_auth_url=None)
        sc_mod.check_keystone_credentials(args)

    def test_missing_region(self):
        args = MagicMock(os_username="admin", os_password="pass",
                         os_project_id="id", os_project_name=None,
                         os_auth_url="http://ks", os_region_name=None)
        sc_mod.check_keystone_credentials(args)


# ===== http.SessionClient edge cases =====

class TestSessionClientNonJsonResponse(unittest.TestCase):
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

    def test_json_request_non_json_content(self):
        c = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'plain text'
        mock_resp.text = 'plain text'
        mock_resp.headers = {"content-type": "text/plain"}
        c.session.request.return_value = mock_resp
        _resp, body = c.json_request("GET", "/release")
        self.assertIsNone(body)

    def test_multipart_non_json_content(self):
        c = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'data'
        mock_resp.text = 'data'
        mock_resp.headers = {"content-type": "text/plain"}
        c.session.request.return_value = mock_resp
        _resp, body = c.multipart_request("POST", "/release", body=b"x")
        self.assertIsNone(body)

    def test_json_request_205(self):
        c = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 205
        mock_resp.content = b''
        mock_resp.headers = {}
        c.session.request.return_value = mock_resp
        _resp, body = c.json_request("DELETE", "/deploy")
        self.assertEqual(body, [])


# Cover commit_patch full success path and
# software_client.py main dispatch


class TestCommitPatchFullSuccess(unittest.TestCase):
    @patch('software_client.v1.release.utils.print_software_op_result')
    @patch('software_client.v1.release.signal.signal')
    @patch('builtins.input', return_value='y')
    @patch('builtins.print')
    def test_all_confirm_yes(
            self,
            mock_print,
            mock_input,
            mock_signal,
            mock_psor):
        mgr = RM2.__new__(RM2)
        resp_200 = MagicMock(status_code=200)
        mgr._list = MagicMock(
            return_value=(
                resp_200, {
                    "sd": {
                        "P1": {}, "P2": {}}}))
        mgr._create = MagicMock(return_value=(resp_200, {"info": "committed"}))

        class Args:
            sw_version = None
            all = True
            dry_run = False
            debug = False
            patch = []
        mgr.commit_patch(Args())
        self.assertTrue(mgr._create.call_count >= 2)

    @patch('software_client.v1.release.utils.print_result_debug')
    @patch('software_client.v1.release.utils.print_software_op_result')
    @patch('software_client.v1.release.signal.signal')
    @patch('builtins.input', return_value='y')
    @patch('builtins.print')
    def test_specific_confirm_yes(self, mock_print, mock_input,
                                  mock_signal, mock_psor, mock_debug):
        mgr = RM2.__new__(RM2)
        resp_200 = MagicMock(status_code=200)
        mgr._list = MagicMock(
            return_value=(
                resp_200, {
                    "patches": [
                        "P1", "P2"]}))
        mgr._create = MagicMock(return_value=(resp_200, {"info": "ok"}))

        class Args:
            sw_version = None
            all = False
            dry_run = False
            debug = True
            patch = ["P1", "P2"]
        mgr.commit_patch(Args())

    @patch('software_client.v1.release.signal.signal')
    @patch('builtins.input', return_value='y')
    @patch('builtins.print')
    def test_dry_run_fails(self, mock_print, mock_input, mock_signal):
        mgr = RM2.__new__(RM2)
        resp_200 = MagicMock(status_code=200)
        resp_500 = MagicMock(status_code=500)
        mgr._list = MagicMock(return_value=(resp_200, {"patches": ["P1"]}))
        mgr._create = MagicMock(return_value=(resp_500, {"error": "fail"}))

        class Args:
            sw_version = None
            all = False
            dry_run = False
            debug = False
            patch = ["P1"]
        rc = mgr.commit_patch(Args())
        self.assertEqual(rc, 1)


class TestReleaseShellInstallLocal(unittest.TestCase):
    @patch('builtins.print')
    def test_success(self, mock_print):
        cc = MagicMock()
        resp = MagicMock(status_code=200, text='{"info": "ok"}')
        cc.release.install_local.return_value = (resp, {"info": "ok"})
        args = MagicMock(debug=False, delete=False)
        from software_client.v1 import release_shell as rs
        rc = rs.do_install_local(cc, args)
        self.assertEqual(rc, 0)


class TestReleaseShellIsAvailableResult(unittest.TestCase):
    @patch('builtins.print')
    def test_true_result(self, mock_print):
        cc = MagicMock()
        req = MagicMock(status_code=200)
        cc.release.is_available.return_value = (req, True)
        args = MagicMock(debug=False, release=["P1"])
        from software_client.v1 import release_shell as rs
        rc = rs.do_is_available(cc, args)
        self.assertEqual(rc, 0)

    @patch('builtins.print')
    def test_false_result(self, mock_print):
        cc = MagicMock()
        req = MagicMock(status_code=200)
        cc.release.is_available.return_value = (req, False)
        args = MagicMock(debug=False, release=["P1"])
        from software_client.v1 import release_shell as rs
        rc = rs.do_is_available(cc, args)
        self.assertEqual(rc, 1)


class TestReleaseShellIsDeployedResult(unittest.TestCase):
    @patch('builtins.print')
    def test_true_result(self, mock_print):
        cc = MagicMock()
        req = MagicMock(status_code=200)
        cc.release.is_deployed.return_value = (req, True)
        args = MagicMock(debug=False, release=["P1"])
        from software_client.v1 import release_shell as rs
        rc = rs.do_is_deployed(cc, args)
        self.assertEqual(rc, 0)


class TestReleaseShellIsCommittedResult(unittest.TestCase):
    @patch('builtins.print')
    def test_true_result(self, mock_print):
        cc = MagicMock()
        req = MagicMock(status_code=200)
        cc.release.is_committed.return_value = (req, True)
        args = MagicMock(debug=False, release=["P1"])
        from software_client.v1 import release_shell as rs
        rc = rs.do_is_committed(cc, args)
        self.assertEqual(rc, 0)
