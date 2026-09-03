#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import threading
import os
from unittest.mock import PropertyMock
from unittest.mock import MagicMock
from unittest.mock import patch
import unittest
import xml.etree.ElementTree as ET

from software.tests import base  # noqa: F401
from software import states
from software import constants
from software.software_controller import ControllerNeighbour
from software.software_controller import PatchController


def _make_controller():
    """Helper to create a PatchController with mocked __init__"""
    with patch.object(PatchController, '__init__', return_value=None):
        pc = PatchController()
    pc.hosts = {}
    pc.controller_neighbours = {}
    pc.app_dependencies = {}
    pc.patch_op_counter = 0
    pc.interim_state = {}
    pc.socket_lock = threading.Lock()
    pc.sock_out = MagicMock()
    pc.pre_bootstrap = False
    pc.port = 5491
    pc.mcast_addr = None
    pc.controller_address = "127.0.0.1"
    pc.agent_address = "127.0.0.1"
    return pc


class TestControllerNeighbour(unittest.TestCase):
    def test_rx_ack(self):
        cn = ControllerNeighbour()
        cn.rx_ack()
        self.assertIsNotNone(cn.last_ack)

    def test_get_age(self):
        cn = ControllerNeighbour()
        cn.rx_ack()
        age = cn.get_age()
        self.assertGreaterEqual(age, 0)

    def test_synced(self):
        cn = ControllerNeighbour()
        cn.rx_synced()
        self.assertTrue(cn.get_synced())
        cn.clear_synced()
        self.assertFalse(cn.get_synced())


class TestPatchControllerWriteReadState(unittest.TestCase):
    @patch('software.software_controller.state_file', '/tmp/test_state_file')
    def test_write_and_read_state(self):
        pc = _make_controller()
        pc.patch_op_counter = 42
        pc.write_state_file()
        pc.patch_op_counter = 0
        pc.read_state_file()
        self.assertEqual(pc.patch_op_counter, 42)
        os.unlink('/tmp/test_state_file')

    @patch('software.software_controller.state_file', '/tmp/test_bad_state')
    def test_read_bad_state_file(self):
        with open('/tmp/test_bad_state', 'w') as f:
            f.write("[runtime]\n")
        pc = _make_controller()
        pc.patch_op_counter = 5
        pc.read_state_file()
        # Missing key triggers configparser.Error, counter unchanged
        self.assertEqual(pc.patch_op_counter, 5)
        os.unlink('/tmp/test_bad_state')


class TestPatchControllerIncCounter(unittest.TestCase):
    @patch('software.software_controller.state_file', '/tmp/test_inc_state')
    def test_inc(self):
        pc = _make_controller()
        pc.patch_op_counter = 10
        pc.inc_patch_op_counter()
        self.assertEqual(pc.patch_op_counter, 11)
        os.unlink('/tmp/test_inc_state')


class TestUpdateConfig(unittest.TestCase):
    @patch('software.software_controller.cfg')
    @patch('software.software_controller.utils.gethostbyname',
           return_value="127.0.0.1")
    def test_pre_bootstrap(self, _mock_gethostbyname, mock_cfg):
        pc = _make_controller()
        pc.pre_bootstrap = True
        mock_cfg.controller_port = 5491
        mock_cfg.read_config = MagicMock()
        pc.update_config()
        self.assertIsNone(pc.mcast_addr)

    @patch('software.software_controller.cfg')
    def test_loopback(self, mock_cfg):
        pc = _make_controller()
        pc.pre_bootstrap = False
        mock_cfg.controller_port = 5491
        mock_cfg.read_config = MagicMock()
        mock_cfg.get_mgmt_iface.return_value = (
            constants.LOOPBACK_INTERFACE_NAME)
        mock_cfg.get_mgmt_ip.return_value = "127.0.0.1"
        pc.update_config()
        self.assertIsNone(pc.mcast_addr)
        self.assertEqual(pc.controller_address, "127.0.0.1")

    @patch('software.software_controller.cfg')
    def test_multicast(self, mock_cfg):
        pc = _make_controller()
        pc.pre_bootstrap = False
        mock_cfg.controller_port = 5491
        mock_cfg.read_config = MagicMock()
        mock_cfg.get_mgmt_iface.return_value = "eth0"
        mock_cfg.controller_mcast_group = "239.1.1.1"
        mock_cfg.agent_mcast_group = "239.1.1.2"
        pc.update_config()
        self.assertEqual(pc.mcast_addr, "239.1.1.1")


class TestAddTextTagToXml(unittest.TestCase):
    def test_adds_tag(self):
        pc = _make_controller()
        parent = ET.Element("root")
        pc.add_text_tag_to_xml(parent, "tag", "value")
        self.assertEqual(parent.find("tag").text, "value")


class TestCheckReleasesState(unittest.TestCase):
    def test_all_in_state(self):
        pc = _make_controller()
        mock_collection = MagicMock()
        mock_rel1 = MagicMock()
        mock_rel1.state = states.AVAILABLE
        mock_rel2 = MagicMock()
        mock_rel2.state = states.AVAILABLE
        mock_collection.get_release_by_id.side_effect = [mock_rel1, mock_rel2]
        with patch.object(
                type(pc), 'release_collection',
                new_callable=PropertyMock,
                return_value=mock_collection):
            result = pc.check_releases_state(["R1", "R2"], states.AVAILABLE)
        self.assertTrue(result)

    def test_not_all_in_state(self):
        pc = _make_controller()
        mock_collection = MagicMock()
        mock_rel1 = MagicMock()
        mock_rel1.state = states.AVAILABLE
        mock_rel2 = MagicMock()
        mock_rel2.state = states.DEPLOYED
        mock_collection.get_release_by_id.side_effect = [mock_rel1, mock_rel2]
        with patch.object(
                type(pc), 'release_collection',
                new_callable=PropertyMock,
                return_value=mock_collection):
            result = pc.check_releases_state(["R1", "R2"], states.AVAILABLE)
        self.assertFalse(result)


class TestIsAvailableDeployedCommitted(unittest.TestCase):
    def test_is_available(self):
        pc = _make_controller()
        with patch.object(
                pc, 'check_releases_state',
                return_value=True) as mock_check:
            self.assertTrue(pc.is_available(["R1"]))
            mock_check.assert_called_with(["R1"], states.AVAILABLE)

    def test_is_deployed(self):
        pc = _make_controller()
        with patch.object(
                pc, 'check_releases_state',
                return_value=False) as mock_check:
            self.assertFalse(pc.is_deployed(["R1"]))
            mock_check.assert_called_with(["R1"], states.DEPLOYED)

    def test_is_committed(self):
        pc = _make_controller()
        with patch.object(
                pc, 'check_releases_state',
                return_value=True) as mock_check:
            self.assertTrue(pc.is_committed(["R1"]))
            mock_check.assert_called_with(["R1"], states.COMMITTED)
