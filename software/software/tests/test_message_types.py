#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Comprehensive tests for config.py, messages.py, logging_hook.py."""

import unittest
from unittest import mock

from software.tests import base  # noqa: F401
from software.messages import PatchMessage
from software.messages import PATCHMSG_UNKNOWN
from software.messages import PATCHMSG_HELLO
from software.messages import PATCHMSG_STR
import software.logging_hook as lh
from software.logging_hook import LoggingHook
from software.constants import SOFTWARE_API_MAX_LENGTH
import software.config as cfg
import software.constants as constants


class TestPatchMessageInit(unittest.TestCase):
    """Tests for PatchMessage constructor."""

    def test_default_init(self):
        msg = PatchMessage()
        self.assertEqual(msg.msgtype, PATCHMSG_UNKNOWN)
        self.assertEqual(msg.msgversion, 1)
        self.assertEqual(msg.message, {})

    def test_init_with_type(self):
        msg = PatchMessage(PATCHMSG_HELLO)
        self.assertEqual(msg.msgtype, PATCHMSG_HELLO)


class TestPatchMessageDecode(unittest.TestCase):
    """Tests for PatchMessage.decode."""

    def test_decode_with_msgtype(self):
        msg = PatchMessage()
        msg.decode({'msgtype': PATCHMSG_HELLO})
        self.assertEqual(msg.msgtype, PATCHMSG_HELLO)

    def test_decode_with_version(self):
        msg = PatchMessage()
        msg.decode({'msgversion': 2})
        self.assertEqual(msg.msgversion, 2)

    def test_decode_empty(self):
        msg = PatchMessage()
        msg.decode({})
        self.assertEqual(msg.msgtype, PATCHMSG_UNKNOWN)

    def test_decode_both(self):
        msg = PatchMessage()
        msg.decode({'msgtype': PATCHMSG_HELLO, 'msgversion': 3})
        self.assertEqual(msg.msgtype, PATCHMSG_HELLO)
        self.assertEqual(msg.msgversion, 3)


class TestPatchMessageEncode(unittest.TestCase):
    """Tests for PatchMessage.encode."""

    def test_encode(self):
        msg = PatchMessage(PATCHMSG_HELLO)
        msg.encode()
        self.assertEqual(msg.message['msgtype'], PATCHMSG_HELLO)
        self.assertEqual(msg.message['msgversion'], 1)


class TestPatchMessageData(unittest.TestCase):
    """Tests for PatchMessage.data."""

    def test_data(self):
        msg = PatchMessage(PATCHMSG_HELLO)
        self.assertEqual(msg.data(), {'msgtype': PATCHMSG_HELLO})


class TestPatchMessageMsgtypeStr(unittest.TestCase):
    """Tests for PatchMessage.msgtype_str."""

    def test_known_type(self):
        msg = PatchMessage(PATCHMSG_HELLO)
        self.assertEqual(msg.msgtype_str(), "hello")

    def test_unknown_type(self):
        msg = PatchMessage(999)
        self.assertEqual(msg.msgtype_str(), "invalid-type")


class TestPatchMsgStr(unittest.TestCase):
    """Test PATCHMSG_STR mapping."""

    def test_all_known_types_mapped(self):
        self.assertIn(PATCHMSG_UNKNOWN, PATCHMSG_STR)
        self.assertIn(PATCHMSG_HELLO, PATCHMSG_STR)
        self.assertEqual(PATCHMSG_STR[PATCHMSG_UNKNOWN], "unknown")


class TestLoggingHookGetLogger(unittest.TestCase):
    """Tests for logging_hook.get_logger."""

    @mock.patch('software.logging_hook.logging.FileHandler')
    def test_get_logger_creates_logger(self, _mock_fh):
        lh.logger = None
        result = lh.get_logger()
        self.assertIsNotNone(result)
        self.assertEqual(result.name, "RestAPI")

    @mock.patch('software.logging_hook.logging.FileHandler')
    def test_get_logger_returns_cached(self, _mock_fh):
        lh.logger = None
        r1 = lh.get_logger()
        r2 = lh.get_logger()
        self.assertIs(r1, r2)


class TestLoggingHookClass(unittest.TestCase):
    """Tests for LoggingHook.on_route and after."""

    @mock.patch('software.logging_hook.get_logger')
    def test_on_route_skips_auth_token(self, mock_gl):
        mock_logger = mock.Mock()
        mock_gl.return_value = mock_logger
        hook = LoggingHook()
        state = mock.Mock()
        state.request.method = "GET"
        state.request.path = "/v1/deploy"
        state.request.headers = {"X-Auth-Token": "secret", "Accept": "json"}
        state.request.params.mixed.return_value = {}
        hook.on_route(state)
        call_args = mock_logger.info.call_args[0][0]
        self.assertNotIn("secret", call_args)

    @mock.patch('software.logging_hook.get_logger')
    def test_after_truncates_long_body(self, mock_gl):
        mock_logger = mock.Mock()
        mock_gl.return_value = mock_logger
        hook = LoggingHook()
        state = mock.Mock()
        state.request.method = "GET"
        state.request.path = "/v1/deploy"
        state.response.status = "200 OK"
        state.response.body = b'x' * (SOFTWARE_API_MAX_LENGTH + 100)
        state.response.headers = {}
        hook.after(state)
        call_args = mock_logger.info.call_args[0][0]
        self.assertIn("...", call_args)


class TestConfigGetMgmtIp(unittest.TestCase):
    """Tests for config.get_mgmt_ip."""

    @mock.patch('software.config.tsc')
    @mock.patch('os.path.exists', return_value=False)
    def test_no_initial_config(self, _mock_exists, mock_tsc):
        mock_tsc.INITIAL_CONFIG_COMPLETE_FLAG = '/etc/.initial'
        result = cfg.get_mgmt_ip()
        self.assertIsNone(result)

    @mock.patch('software.config.utils.gethostbyname', return_value='10.0.0.1')
    @mock.patch('socket.gethostname', return_value='controller-0')
    @mock.patch('software.config.tsc')
    @mock.patch('os.path.exists', return_value=True)
    def test_returns_ip(
            self,
            _mock_exists,
            mock_tsc,
            _mock_hostname,
            _mock_resolve):
        mock_tsc.INITIAL_CONFIG_COMPLETE_FLAG = '/etc/.initial'
        mock_tsc.system_mode = 'duplex'
        result = cfg.get_mgmt_ip()
        self.assertEqual(result, '10.0.0.1')

    @mock.patch('software.config.utils.gethostbyname', return_value='10.0.0.1')
    @mock.patch('socket.gethostname', return_value='controller-0')
    @mock.patch('software.config.tsc')
    @mock.patch('os.path.exists')
    def test_simplex_not_ready(
            self,
            mock_exists,
            mock_tsc,
            _mock_hostname,
            _mock_resolve):
        mock_tsc.INITIAL_CONFIG_COMPLETE_FLAG = '/etc/.initial'
        mock_tsc.system_mode = constants.SYSTEM_MODE_SIMPLEX
        mock_tsc.VOLATILE_CONTROLLER_CONFIG_COMPLETE = '/var/run/.config'
        mock_exists.side_effect = lambda path: path == '/etc/.initial'
        result = cfg.get_mgmt_ip()
        self.assertIsNone(result)


class TestConfigGetMgmtIface(unittest.TestCase):
    """Tests for config.get_mgmt_iface."""

    @mock.patch('os.path.exists', return_value=False)
    def test_no_initial_config(self, _mock_exists):
        constants.INITIAL_CONFIG_COMPLETE_FLAG = '/etc/.initial'
        result = cfg.get_mgmt_iface()
        self.assertIsNone(result)

    @mock.patch('software.config.tsc')
    @mock.patch('builtins.open', mock.mock_open(
        read_data='management_interface=ens3\n'))
    @mock.patch('os.stat')
    @mock.patch('os.path.exists', return_value=True)
    def test_returns_iface(self, _mock_exists, mock_stat, mock_tsc):
        constants.INITIAL_CONFIG_COMPLETE_FLAG = '/etc/.initial'
        mock_tsc.PLATFORM_CONF_FILE = '/etc/platform/platform.conf'
        mock_stat.return_value.st_mtime = 999
        cfg.mgmt_if = None
        cfg.platform_conf_mtime = 0
        result = cfg.get_mgmt_iface()
        self.assertEqual(result, 'ens3')

    @mock.patch('software.config.tsc')
    @mock.patch('os.stat')
    @mock.patch('os.path.exists', return_value=True)
    def test_returns_cached(self, _mock_exists, mock_stat, mock_tsc):
        constants.INITIAL_CONFIG_COMPLETE_FLAG = '/etc/.initial'
        mock_tsc.PLATFORM_CONF_FILE = '/etc/platform/platform.conf'
        mock_stat.return_value.st_mtime = 100
        cfg.mgmt_if = 'ens3'
        cfg.platform_conf_mtime = 100
        result = cfg.get_mgmt_iface()
        self.assertEqual(result, 'ens3')
