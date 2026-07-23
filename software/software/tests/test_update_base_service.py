#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for software.base module (PatchService)."""

import socket
import unittest
from unittest import mock

from software.tests import base as test_base  # noqa: F401
from software.base import PatchService


class TestPatchServiceInit(unittest.TestCase):
    """Tests for PatchService.__init__."""

    def test_default_attributes(self):
        svc = PatchService()
        self.assertIsNone(svc.sock_out)
        self.assertIsNone(svc.sock_in)
        self.assertIsNone(svc.service_type)
        self.assertIsNone(svc.port)
        self.assertIsNone(svc.mcast_addr)
        self.assertIsNone(svc.socket_lock)
        self.assertTrue(svc.pre_bootstrap)
        self.assertTrue(svc.install_local)


class TestPatchServiceMgmtIp(unittest.TestCase):
    """Tests for PatchService.mgmt_ip property."""

    @mock.patch('software.base.cfg.get_mgmt_ip', return_value='10.0.0.1')
    def test_returns_mgmt_ip(self, mock_get):
        svc = PatchService()
        self.assertEqual(svc.mgmt_ip, '10.0.0.1')
        mock_get.assert_called_once()

    @mock.patch('software.base.cfg.get_mgmt_ip', return_value=None)
    def test_returns_none(self, _mock_get):
        svc = PatchService()
        self.assertIsNone(svc.mgmt_ip)


class TestSetupSocketIpv4(unittest.TestCase):
    """Tests for PatchService.setup_socket_ipv4."""

    def _make_svc(self, _mgmt_ip='10.0.0.1', port=5494, mcast=None):
        svc = PatchService()
        svc.port = port
        svc.mcast_addr = mcast
        return svc

    @mock.patch('software.base.cfg.get_mgmt_ip', return_value=None)
    def test_no_mgmt_ip_returns_none(self, _):
        svc = self._make_svc()
        self.assertIsNone(svc.setup_socket_ipv4())

    @mock.patch('software.base.socket.socket')
    @mock.patch('software.base.socket.inet_pton',
                return_value=b'\x0a\x00\x00\x01')
    @mock.patch('software.base.cfg.get_mgmt_ip', return_value='10.0.0.1')
    def test_creates_sockets_no_mcast(self, _ip, _pton, mock_sock_cls):
        mock_sock = mock.MagicMock()
        mock_sock_cls.return_value = mock_sock
        svc = self._make_svc(mcast=None)
        result = svc.setup_socket_ipv4()
        self.assertEqual(result, mock_sock)
        self.assertEqual(mock_sock_cls.call_count, 2)
        mock_sock.setblocking.assert_called_with(0)
        mock_sock.bind.assert_called_once_with(('', 5494))

    @mock.patch('software.base.struct.pack', return_value=b'\x00' * 8)
    @mock.patch('software.base.socket.socket')
    @mock.patch('software.base.socket.inet_pton',
                return_value=b'\x0a\x00\x00\x01')
    @mock.patch('software.base.cfg.get_mgmt_ip', return_value='10.0.0.1')
    def test_creates_sockets_with_mcast(self, _ip, _pton, mock_sock_cls,
                                        _pack):
        mock_sock = mock.MagicMock()
        mock_sock_cls.return_value = mock_sock
        svc = self._make_svc(mcast='239.1.1.3')
        result = svc.setup_socket_ipv4()
        self.assertIsNotNone(result)
        # Verify multicast options set on sock_out
        calls = mock_sock.setsockopt.call_args_list
        ip_protos = [c for c in calls
                     if c[0][0] == socket.IPPROTO_IP]
        self.assertTrue(len(ip_protos) > 0)

    @mock.patch('software.base.socket.socket')
    @mock.patch('software.base.socket.inet_pton',
                return_value=b'\x0a\x00\x00\x01')
    @mock.patch('software.base.cfg.get_mgmt_ip', return_value='10.0.0.1')
    def test_closes_existing_sockets(self, _ip, _pton, mock_sock_cls):
        mock_old = mock.MagicMock()
        mock_new = mock.MagicMock()
        mock_sock_cls.return_value = mock_new
        svc = self._make_svc()
        svc.sock_out = mock_old
        svc.sock_in = mock_old
        svc.setup_socket_ipv4()
        self.assertEqual(mock_old.close.call_count, 2)


class TestSetupSocketIpv6(unittest.TestCase):
    """Tests for PatchService.setup_socket_ipv6."""

    @mock.patch('software.base.cfg.get_mgmt_ip', return_value=None)
    def test_no_mgmt_ip_returns_none(self, _):
        svc = PatchService()
        svc.port = 5494
        self.assertIsNone(svc.setup_socket_ipv6())

    @mock.patch('software.base.utils.if_nametoindex', return_value=2)
    @mock.patch('software.base.cfg.get_mgmt_iface', return_value='eth0')
    @mock.patch('software.base.socket.socket')
    @mock.patch('software.base.socket.inet_pton',
                return_value=b'\x00' * 16)
    @mock.patch('software.base.cfg.get_mgmt_ip', return_value='fd00::1')
    def test_creates_ipv6_sockets_with_mcast(self, _ip, _pton,
                                             mock_sock_cls, _iface, _idx):
        mock_sock = mock.MagicMock()
        mock_sock_cls.return_value = mock_sock
        svc = PatchService()
        svc.port = 5494
        svc.mcast_addr = 'ff05::1'
        result = svc.setup_socket_ipv6()
        self.assertIsNotNone(result)
        calls = mock_sock.setsockopt.call_args_list
        ipv6_protos = [c for c in calls
                       if c[0][0] == socket.IPPROTO_IPV6]
        self.assertTrue(len(ipv6_protos) > 0)

    @mock.patch('software.base.socket.socket')
    @mock.patch('software.base.cfg.get_mgmt_ip', return_value='fd00::1')
    def test_creates_ipv6_sockets_no_mcast(self, _ip, mock_sock_cls):
        mock_sock = mock.MagicMock()
        mock_sock_cls.return_value = mock_sock
        svc = PatchService()
        svc.port = 5494
        svc.mcast_addr = None
        result = svc.setup_socket_ipv6()
        self.assertIsNotNone(result)
        mock_sock.bind.assert_any_call(('fd00::1', 0))


class TestSetupSocketPreBootstrap(unittest.TestCase):
    """Tests for PatchService.setup_socket_pre_bootstrap."""

    @mock.patch('software.base.socket.socket')
    @mock.patch('software.base.utils.get_management_version',
                return_value=4)
    @mock.patch('software.base.utils.gethostbyname',
                return_value='127.0.0.1')
    @mock.patch('software.base.cfg')
    def test_ipv4_pre_bootstrap(self, mock_cfg, _host, _ver, mock_sock_cls):
        mock_cfg.package_feed = 'http://controller:8080/feed'
        mock_sock = mock.MagicMock()
        mock_sock_cls.return_value = mock_sock
        svc = PatchService()
        svc.port = 5494
        result = svc.setup_socket_pre_bootstrap()
        self.assertIsNotNone(result)

    @mock.patch('software.base.socket.socket')
    @mock.patch('software.base.utils.get_management_version',
                return_value=6)
    @mock.patch('software.base.utils.gethostbyname',
                return_value='::1')
    @mock.patch('software.base.cfg')
    def test_ipv6_pre_bootstrap(self, mock_cfg, _host, _ver, mock_sock_cls):
        mock_cfg.package_feed = 'http://controller:8080/feed'
        mock_sock = mock.MagicMock()
        mock_sock_cls.return_value = mock_sock
        svc = PatchService()
        svc.port = 5494
        result = svc.setup_socket_pre_bootstrap()
        self.assertIsNotNone(result)
        mock_sock.bind.assert_any_call(('::1', 0))


class TestSetupSocket(unittest.TestCase):
    """Tests for PatchService.setup_socket dispatch."""

    def _make_svc(self, pre_bootstrap=False):
        svc = PatchService()
        svc.pre_bootstrap = pre_bootstrap
        svc.port = 5494
        return svc

    @mock.patch.object(PatchService, 'setup_socket_pre_bootstrap',
                       return_value=mock.MagicMock())
    def test_dispatches_pre_bootstrap(self, mock_pre):
        svc = self._make_svc(pre_bootstrap=True)
        result = svc.setup_socket()
        mock_pre.assert_called_once()
        self.assertIsNotNone(result)

    @mock.patch('software.base.utils.get_management_version',
                return_value=6)
    @mock.patch.object(PatchService, 'setup_socket_ipv6',
                       return_value=mock.MagicMock())
    def test_dispatches_ipv6(self, mock_v6, _ver):
        svc = self._make_svc(pre_bootstrap=False)
        result = svc.setup_socket()
        mock_v6.assert_called_once()
        self.assertIsNotNone(result)

    @mock.patch('software.base.utils.get_management_version',
                return_value=4)
    @mock.patch.object(PatchService, 'setup_socket_ipv4',
                       return_value=mock.MagicMock())
    def test_dispatches_ipv4(self, mock_v4, _ver):
        svc = self._make_svc(pre_bootstrap=False)
        result = svc.setup_socket()
        mock_v4.assert_called_once()
        self.assertIsNotNone(result)

    @mock.patch('software.base.utils.get_management_version',
                side_effect=Exception("fail"))
    def test_exception_returns_none(self, _ver):
        svc = self._make_svc(pre_bootstrap=False)
        result = svc.setup_socket()
        self.assertIsNone(result)

    @mock.patch('software.base.utils.get_management_version',
                side_effect=Exception("fail"))
    def test_exception_closes_sockets(self, _ver):
        svc = self._make_svc(pre_bootstrap=False)
        mock_sock = mock.MagicMock()
        svc.sock_out = mock_sock
        svc.sock_in = mock_sock
        svc.setup_socket()
        self.assertEqual(mock_sock.close.call_count, 2)


class TestAuditSocket(unittest.TestCase):
    """Tests for PatchService.audit_socket."""

    @mock.patch('software.base.time.sleep', side_effect=StopIteration)
    @mock.patch.object(PatchService, 'setup_socket', return_value=None)
    @mock.patch('software.base.cfg.get_mgmt_iface', return_value='eth0')
    @mock.patch('subprocess.check_output', return_value=b'')
    def test_mcast_missing_triggers_reconfig(self, _check, _iface,
                                             mock_setup, _mock_sleep):
        svc = PatchService()
        svc.mcast_addr = '239.1.1.3'
        with self.assertRaises(StopIteration):
            svc.audit_socket()
        mock_setup.assert_called_once()
