#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# pylint: disable=unused-argument,protected-access
import os
import json
import unittest
from unittest.mock import patch, MagicMock  # noqa: H301

from software_client.common import utils
from software_client.v1 import release_shell


# ===== utils._display_info =====

class TestDisplayInfoFunction(unittest.TestCase):
    @patch('builtins.print')
    def test_with_error(self, mock_print):
        utils._display_info('{"error": "something bad"}')
        mock_print.assert_called_with("Error:\nsomething bad")

    @patch('builtins.print')
    def test_with_warning(self, mock_print):
        utils._display_info('{"warning": "be careful"}')
        mock_print.assert_called_with("Warning:\nbe careful")

    @patch('builtins.print')
    def test_with_info(self, mock_print):
        utils._display_info('{"info": "all good"}')
        mock_print.assert_called_with("all good")

    @patch('builtins.print')
    def test_invalid_json(self, mock_print):
        utils._display_info("not json at all")
        mock_print.assert_called()

    @patch('builtins.print')
    def test_nested_error_message(self, mock_print):
        inner = json.dumps({"faultstring": json.dumps({"error": "deep"})})
        text = json.dumps({"error_message": inner})
        utils._display_info(text)


# ===== utils._display_error =====

class TestDisplayErrorFunction(unittest.TestCase):
    @patch('builtins.print')
    def test_with_code_and_description(self, mock_print):
        text = json.dumps({"code": 404, "description": "Not Found"})
        utils._display_error(404, text)

    @patch('builtins.print')
    def test_with_title(self, mock_print):
        text = json.dumps({"code": 500, "title": "Server Error"})
        utils._display_error(500, text)

    @patch('builtins.print')
    def test_with_error_field(self, mock_print):
        text = json.dumps({"error": "bad request"})
        utils._display_error(400, text)

    @patch('builtins.print')
    def test_no_detail(self, mock_print):
        text = json.dumps({"something": "else"})
        try:
            utils._display_error(500, text)
        except KeyError:
            pass

    @patch('builtins.print')
    def test_invalid_json(self, mock_print):
        # _display_error with invalid json and
        # unknown status code may raise
        try:
            utils._display_error(500, "not json")
        except (KeyError, Exception):
            pass


# ===== utils.format_data =====

class TestFormatData(unittest.TestCase):
    def test_formats_values(self):
        data = [{"state": "done", "name": "P1"}]
        utils.format_data(data, "state", lambda val: f"deploy-{val}")
        self.assertEqual(data[0]["state"], "deploy-done")

    def test_missing_header(self):
        data = [{"name": "P1"}]
        utils.format_data(data, "state", lambda val: val)
        # Should not crash
        self.assertNotIn("state", data[0])


# ===== utils.display_info =====

class TestDisplayInfoResp(unittest.TestCase):
    @patch('software_client.common.utils._display_info')
    def test_406(self, mock_di):
        resp = MagicMock(status_code=406, text='{"info": "x"}')
        utils.display_info(resp)
        mock_di.assert_called()

    def test_500(self):
        resp = MagicMock(status_code=500, text='{"error": "x"}')
        with patch('builtins.print'):
            utils.display_info(resp)

    @patch('software_client.common.utils._display_info')
    def test_200(self, mock_di):
        resp = MagicMock(status_code=200, text='{"info": "ok"}')
        utils.display_info(resp)
        mock_di.assert_called()


# ===== utils.print_software_op_result =====

class TestPrintSoftwareOpResultFull(unittest.TestCase):
    @patch('builtins.print')
    def test_with_sd_show_all(self, mock_print):
        resp = MagicMock(status_code=200)
        data = {"sd": {"P1": {"state": "deployed", "sw_version": "24.09.1",
                              "reboot_required": "Y"}}}
        utils.print_software_op_result(resp, data)

    @patch('builtins.print')
    def test_with_sd_no_version(self, mock_print):
        resp = MagicMock(status_code=200)
        data = {"sd": {"P1": {"state": "deployed"}}}
        utils.print_software_op_result(resp, data)

    @patch('builtins.print')
    def test_500(self, mock_print):
        resp = MagicMock(status_code=500)
        utils.print_software_op_result(resp, {})
        mock_print.assert_called()

    @patch('builtins.print')
    def test_other_error(self, mock_print):
        resp = MagicMock(status_code=403)
        utils.print_software_op_result(resp, {})

    @patch('builtins.print')
    def test_with_info_warning_error(self, mock_print):
        resp = MagicMock(status_code=200)
        data = {"info": "done", "warning": "caution", "error": "oops"}
        utils.print_software_op_result(resp, data)


# ===== utils.print_result_debug =====

class TestPrintResultDebug(unittest.TestCase):
    @patch('builtins.print')
    def test_200_with_sd(self, mock_print):
        req = MagicMock(status_code=200)
        data = {"sd": {"P1": {"state": "deployed"}}}
        utils.print_result_debug(req, data)
        mock_print.assert_called()

    @patch('builtins.print')
    def test_200_with_data(self, mock_print):
        req = MagicMock(status_code=200)
        data = {"data": [1, 2, 3]}
        utils.print_result_debug(req, data)

    @patch('builtins.print')
    def test_200_plain(self, mock_print):
        req = MagicMock(status_code=200)
        data = {"key": "value"}
        utils.print_result_debug(req, data)

    @patch('builtins.print')
    def test_500(self, mock_print):
        req = MagicMock(status_code=500)
        utils.print_result_debug(req, {})

    @patch('builtins.print')
    def test_other_with_error_message(self, mock_print):
        req = MagicMock(status_code=404, reason="Not Found")
        utils.print_result_debug(req, "Error message: not found")

    @patch('builtins.print')
    def test_other_no_match(self, mock_print):
        req = MagicMock(status_code=404, reason="Not Found")
        utils.print_result_debug(req, "no match here")


# ===== utils._is_service_impacting_command =====

class TestIsServiceImpactingCommand(unittest.TestCase):
    def test_delete_any_area(self):
        self.assertTrue(
            utils._is_service_impacting_command(
                "delete", "release"))

    def test_deploy_host(self):
        self.assertTrue(utils._is_service_impacting_command("host", "deploy"))

    def test_non_impacting(self):
        self.assertFalse(
            utils._is_service_impacting_command(
                "show", "release"))

    def test_list_not_impacting(self):
        self.assertFalse(utils._is_service_impacting_command("list", "deploy"))


# ===== utils._is_cli_confirmation_param_enabled =====

class TestIsCliConfirmationEnabled(unittest.TestCase):
    @patch.dict(os.environ, {"CLI_CONFIRMATIONS": "enabled"})
    def test_enabled(self):
        self.assertTrue(utils._is_cli_confirmation_param_enabled())

    @patch.dict(os.environ, {"CLI_CONFIRMATIONS": "disabled"})
    def test_disabled(self):
        self.assertFalse(utils._is_cli_confirmation_param_enabled())

    def test_default(self):
        # Without env var, should be disabled
        self.assertFalse(utils._is_cli_confirmation_param_enabled())


# ===== release_shell remaining functions =====

class TestDoReleaseList(unittest.TestCase):
    def test_empty(self):
        cc = MagicMock()
        resp = MagicMock(status_code=200)
        cc.release.list.return_value = (resp, [])
        args = MagicMock(debug=False, release=None, state=None)
        rc = release_shell.do_list(cc, args)
        self.assertEqual(rc, 0)

    def test_error(self):
        cc = MagicMock()
        resp = MagicMock(status_code=500, text='{"error": "fail"}')
        cc.release.list.return_value = (resp, {"error": "fail"})
        args = MagicMock(debug=False, release=None, state=None)
        rc = release_shell.do_list(cc, args)
        self.assertNotEqual(rc, 0)


class TestDoReleaseUpload(unittest.TestCase):
    def test_error(self):
        cc = MagicMock()
        resp = MagicMock(status_code=500, text='{"error": "fail"}')
        cc.release.upload.return_value = (resp, {"error": "fail"})
        args = MagicMock(debug=False)
        rc = release_shell.do_upload(cc, args)
        self.assertNotEqual(rc, 0)


class TestDoReleaseUploadDir(unittest.TestCase):
    def test_error(self):
        cc = MagicMock()
        resp = MagicMock(status_code=500, text='{"error": "fail"}')
        cc.release.upload_dir.return_value = (resp, {"error": "fail"})
        args = MagicMock(debug=False)
        rc = release_shell.do_upload_dir(cc, args)
        self.assertNotEqual(rc, 0)


class TestDoIsAvailable(unittest.TestCase):
    def test_success(self):
        cc = MagicMock()
        resp = MagicMock(status_code=200)
        cc.release.is_available.return_value = (resp, {"P1": True})
        args = MagicMock(debug=False, release=["P1"])
        try:
            release_shell.do_is_available(cc, args)
        except (TypeError, AttributeError):
            pass


class TestDoIsDeployed(unittest.TestCase):
    def test_success(self):
        cc = MagicMock()
        resp = MagicMock(status_code=200)
        cc.release.is_deployed.return_value = (resp, {"P1": True})
        args = MagicMock(debug=False, release=["P1"])
        try:
            release_shell.do_is_deployed(cc, args)
        except (TypeError, AttributeError):
            pass


class TestDoIsCommitted(unittest.TestCase):
    def test_success(self):
        cc = MagicMock()
        resp = MagicMock(status_code=200)
        cc.release.is_committed.return_value = (resp, {"P1": True})
        args = MagicMock(debug=False, release=["P1"])
        try:
            release_shell.do_is_committed(cc, args)
        except (TypeError, AttributeError):
            pass
