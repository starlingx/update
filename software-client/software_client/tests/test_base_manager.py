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

import copy  # noqa: E402
import unittest  # noqa: E402
from unittest.mock import patch, MagicMock  # noqa: H301,E402

from software_client.common.base import Manager  # noqa: E402
from software_client.common.base import Resource  # noqa: E402
from software_client.v1.deploy import DeployManager  # noqa: E402
from software_client.v1.release import ReleaseManager  # noqa: E402
import software_client.software_client as sc_mod  # noqa: E402
from software_client import constants  # noqa: E402


# ===== base.Manager =====

class TestManager(unittest.TestCase):
    def _make_mgr(self):
        api = MagicMock()
        return Manager(api)

    def test_create(self):
        mgr = self._make_mgr()
        mgr.api.json_request.return_value = (
            MagicMock(status_code=200), {"id": 1})
        mgr._create("/url", body={"k": "v"})
        mgr.api.json_request.assert_called_with(
            'POST', '/url', body={"k": "v"})

    def test_create_multipart(self):
        mgr = self._make_mgr()
        mgr.api.multipart_request.return_value = (MagicMock(), {})
        mgr._create_multipart("/url", body=b"data")

    def test_post(self):
        mgr = self._make_mgr()
        mgr.api.json_request.return_value = (MagicMock(), {})
        mgr._post("/url", body={})

    def test_list(self):
        mgr = self._make_mgr()
        mgr.api.json_request.return_value = (MagicMock(), {"items": [1, 2]})
        _resp, data = mgr._list("/url", response_key="items")
        self.assertEqual(data, [1, 2])

    def test_list_no_key(self):
        mgr = self._make_mgr()
        mgr.api.json_request.return_value = (MagicMock(), [1, 2])
        _resp, data = mgr._list("/url")
        self.assertEqual(data, [1, 2])

    def test_list_missing_key(self):
        mgr = self._make_mgr()
        mgr.api.json_request.return_value = (MagicMock(), {"other": "val"})
        mgr._list("/url", response_key="missing")

    def test_fetch(self):
        mgr = self._make_mgr()
        mgr.api.json_request.return_value = (MagicMock(), {"id": 1})
        _resp, data = mgr._fetch("/url")
        self.assertEqual(data, {"id": 1})

    def test_delete(self):
        mgr = self._make_mgr()
        mgr.api.json_request.return_value = (MagicMock(), {})
        mgr._delete("/url")
        mgr.api.json_request.assert_called_with('DELETE', '/url')


# ===== base.Resource =====

class TestResource(unittest.TestCase):
    def test_init(self):
        mgr = MagicMock()
        r = Resource(mgr, {"id": "1", "name": "test"}, loaded=True)
        self.assertEqual(r.id, "1")
        self.assertEqual(r.name, "test")

    def test_repr(self):
        mgr = MagicMock()
        r = Resource(mgr, {"id": "1", "name": "test"}, loaded=True)
        self.assertIn("id=1", repr(r))

    def test_to_dict(self):
        mgr = MagicMock()
        r = Resource(mgr, {"id": "1"}, loaded=True)
        self.assertEqual(r.to_dict(), {"id": "1"})

    def test_eq(self):
        mgr = MagicMock()
        r1 = Resource(mgr, {"id": "1"}, loaded=True)
        r2 = Resource(mgr, {"id": "1"}, loaded=True)
        self.assertEqual(r1, r2)

    def test_not_eq(self):
        mgr = MagicMock()
        r1 = Resource(mgr, {"id": "1"}, loaded=True)
        r2 = Resource(mgr, {"id": "2"}, loaded=True)
        self.assertNotEqual(r1, r2)

    def test_copy(self):
        mgr = MagicMock()
        r = Resource(mgr, {"id": "1"}, loaded=True)
        r2 = copy.copy(r)
        self.assertEqual(r2.id, "1")

    def test_deepcopy(self):
        mgr = MagicMock()
        r = Resource(mgr, {"id": "1"}, loaded=True)
        r2 = copy.deepcopy(r)
        self.assertEqual(r2.id, "1")

    def test_is_loaded(self):
        mgr = MagicMock()
        r = Resource(mgr, {"id": "1"}, loaded=False)
        self.assertFalse(r.is_loaded())
        r.set_loaded(True)
        self.assertTrue(r.is_loaded())

    def test_getattr_loaded(self):
        mgr = MagicMock()
        r = Resource(mgr, {"id": "1"}, loaded=True)
        with self.assertRaises(AttributeError):
            _ = r.nonexistent


# ===== deploy.wait_for_install_complete =====

class TestWaitForInstallComplete(unittest.TestCase):
    @patch('software_client.v1.deploy.time.sleep')
    def test_deploying(self, mock_sleep):
        mgr = DeployManager.__new__(DeployManager)
        mgr._list = MagicMock(return_value=(
            MagicMock(status_code=200),
            [{"hostname": "ctrl-0", "host_state": constants.DEPLOYING}]
        ))
        rc = mgr.wait_for_install_complete("ctrl-0")
        self.assertEqual(rc, 0)

    @patch('software_client.v1.deploy.time.sleep')
    def test_deployed(self, mock_sleep):
        mgr = DeployManager.__new__(DeployManager)
        mgr._list = MagicMock(return_value=(
            MagicMock(status_code=200),
            [{"hostname": "ctrl-0", "host_state": constants.DEPLOYED}]
        ))
        rc = mgr.wait_for_install_complete("ctrl-0")
        self.assertEqual(rc, 0)

    @patch('software_client.v1.deploy.time.sleep')
    def test_failed(self, mock_sleep):
        mgr = DeployManager.__new__(DeployManager)
        mgr._list = MagicMock(return_value=(
            MagicMock(status_code=200),
            [{"hostname": "ctrl-0", "host_state": constants.FAILED}]
        ))
        rc = mgr.wait_for_install_complete("ctrl-0")
        self.assertEqual(rc, 1)

    @patch('software_client.v1.deploy.time.sleep')
    def test_pending(self, mock_sleep):
        mgr = DeployManager.__new__(DeployManager)
        mgr._list = MagicMock(return_value=(
            MagicMock(status_code=200),
            [{"hostname": "ctrl-0", "host_state": constants.PENDING}]
        ))
        rc = mgr.wait_for_install_complete("ctrl-0")
        self.assertEqual(rc, 0)

    @patch('software_client.v1.deploy.time.sleep')
    def test_unknown_state(self, mock_sleep):
        mgr = DeployManager.__new__(DeployManager)
        mgr._list = MagicMock(return_value=(
            MagicMock(status_code=200),
            [{"hostname": "ctrl-0", "host_state": "weird"}]
        ))
        rc = mgr.wait_for_install_complete("ctrl-0")
        self.assertEqual(rc, 1)

    @patch('software_client.v1.deploy.time.sleep')
    def test_500(self, mock_sleep):
        mgr = DeployManager.__new__(DeployManager)
        mgr._list = MagicMock(
            return_value=(
                MagicMock(
                    status_code=500,
                    text="err"),
                {}))
        rc = mgr.wait_for_install_complete("ctrl-0")
        self.assertEqual(rc, 1)

    @patch('software_client.v1.deploy.time.sleep')
    def test_empty_data(self, mock_sleep):
        mgr = DeployManager.__new__(DeployManager)
        mgr._list = MagicMock(return_value=(MagicMock(status_code=200), []))
        rc = mgr.wait_for_install_complete("ctrl-0")
        self.assertEqual(rc, 1)

    @patch('software_client.v1.deploy.time.sleep')
    def test_connection_error_retries(self, mock_sleep):
        import requests
        mgr = DeployManager.__new__(DeployManager)
        mgr._list = MagicMock(
            side_effect=requests.exceptions.ConnectionError("lost"))
        rc = mgr.wait_for_install_complete("ctrl-0")
        self.assertEqual(rc, 1)


# ===== release.py upload with valid file =====

class TestReleaseUploadValidFile(unittest.TestCase):
    @patch('software_client.v1.release.signal.signal')
    @patch('software_client.v1.release.os.path.isfile', return_value=True)
    @patch('software_client.v1.release.os.path.splitext',
           return_value=("/f", ".patch"))
    @patch('software_client.v1.release.os.path.abspath',
           side_effect=lambda val: val)
    @patch('builtins.open', MagicMock())
    def test_upload_valid(
            self,
            mock_abs,
            mock_split,
            mock_isfile,
            mock_signal):
        mgr = ReleaseManager.__new__(ReleaseManager)
        mgr._create_multipart = MagicMock(
            return_value=(MagicMock(status_code=200), {}))

        class Args:
            release = ["/path/file.patch"]
            local = False

        with patch('software_client.v1.release.contextlib.'
                   'ExitStack') as mock_stack:
            mock_ctx = MagicMock()
            mock_stack.return_value.__enter__ = MagicMock(
                return_value=mock_ctx)
            mock_stack.return_value.__exit__ = MagicMock(return_value=False)
            mock_ctx.enter_context.return_value = MagicMock()
            with patch('software_client.v1.release.'
                       'MultipartEncoder') as mock_enc:
                mock_enc.return_value.content_type = "multipart/form-data"
                mgr.upload(Args())


# ===== release.py release_delete single =====

class TestReleaseDeleteSingle(unittest.TestCase):
    def test_delete_single(self):
        mgr = ReleaseManager.__new__(ReleaseManager)
        mgr._delete = MagicMock(
            return_value=(
                MagicMock(
                    status_code=200), {
                    "info": "ok"}))
        mgr.release_delete(["P1"], delete_all=False)
        mgr._delete.assert_called()


# ===== software_client.py main flow =====

class TestSoftwareClientMain(unittest.TestCase):
    def test_main_version(self):
        shell = sc_mod.SoftwareClientShell()
        try:
            shell.main(["--version"])
        except SystemExit:
            pass

    @patch('software_client.software_client.SoftwareClientShell.do_help')
    def test_main_bash_completion(self, mock_help):
        shell = sc_mod.SoftwareClientShell()
        shell.get_subcommand_parser("1")
        args = MagicMock(command="bash-completion")
        shell.do_bash_completion(args)


# ===== auth/ks_client =====


# ===== auth/oidc_client =====


# ===== http.VerifiedHTTPSConnection =====
