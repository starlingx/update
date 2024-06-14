#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2023 Wind River Systems, Inc.
#
import testtools
from unittest import mock

from software.messages import PatchMessage
from software.software_controller import PatchMessageHello
from software.software_controller import PatchMessageHelloAck
from software.software_controller import PatchMessageSyncReq
from software.software_controller import PatchMessageSyncComplete
from software.software_controller import PatchMessageHelloAgent
from software.software_controller import PatchMessageSendLatestFeedCommit
from software.software_controller import PatchMessageHelloAgentAck
from software.software_controller import PatchMessageQueryDetailed
from software.software_controller import PatchMessageQueryDetailedResp
from software.software_controller import PatchMessageAgentInstallReq
from software.software_controller import PatchMessageAgentInstallResp
from software.software_controller import PatchMessageDropHostReq
from software.states import DEPLOY_HOST_STATES

FAKE_AGENT_ADDRESS = "127.0.0.1"
FAKE_AGENT_MCAST_GROUP = "239.1.1.4"
FAKE_CONTROLLER_ADDRESS = "127.0.0.1"
FAKE_HOST_IP = "10.10.10.2"
FAKE_OSTREE_FEED_COMMIT = "12345"


class FakeSoftwareController(object):

    def __init__(self):
        self.agent_address = FAKE_AGENT_ADDRESS
        self.allow_insvc_softwareing = True
        self.controller_address = FAKE_CONTROLLER_ADDRESS
        self.controller_neighbours = {}
        self.hosts = {FAKE_HOST_IP: {"hostname": "controller-0"}}
        self.interim_state = {}
        self.latest_feed_commit = FAKE_OSTREE_FEED_COMMIT
        self.patch_op_counter = 0
        self.sock_in = None
        self.sock_out = None

        # mock all the lock objects
        self.controller_neighbours_lock = mock.Mock()
        self.hosts_lock = mock.Mock()
        self.software_data_lock = mock.Mock()
        self.socket_lock = mock.Mock()

        # mock the software data
        self.base_pkgdata = mock.Mock()
        self.software_data = mock.Mock()
        self.pre_bootstrap = False

    def check_patch_states(self):
        pass

    def drop_host(self, host_ip, sync_nbr=True):
        pass

    def sync_from_nbr(self, host):
        pass


class SoftwareControllerMessagesTestCase(testtools.TestCase):

    message_classes = [
        PatchMessageHello,
        PatchMessageHelloAck,
        PatchMessageSyncReq,
        PatchMessageSyncComplete,
        PatchMessageHelloAgent,
        PatchMessageSendLatestFeedCommit,
        PatchMessageHelloAgentAck,
        PatchMessageQueryDetailed,
        PatchMessageQueryDetailedResp,
        PatchMessageAgentInstallReq,
        PatchMessageAgentInstallResp,
        PatchMessageDropHostReq,
    ]

    def test_message_class_creation(self):
        for message_class in SoftwareControllerMessagesTestCase.message_classes:
            test_obj = message_class()
            self.assertIsNotNone(test_obj)
            self.assertIsInstance(test_obj, PatchMessage)

    @mock.patch('software.software_controller.sc', FakeSoftwareController())
    def test_message_class_encode(self):
        """'encode' method populates self.message"""
        # mock the global software_controller 'sc' variable used by encode

        # PatchMessageQueryDetailedResp does not support 'encode'
        # so it can be executed, but it will not change the message
        excluded = [
            PatchMessageQueryDetailedResp
        ]
        for message_class in SoftwareControllerMessagesTestCase.message_classes:
            test_obj = message_class()
            # message variable should be empty dict (ie: False)
            self.assertFalse(test_obj.message)
            test_obj.encode()
            # message variable no longer empty (ie: True)
            if message_class not in excluded:
                self.assertTrue(test_obj.message)
            # decode one message into another
            test_obj2 = message_class()
            test_obj2.decode(test_obj.message)
            # decode does not populate 'message' so nothing to compare

    @mock.patch('software.software_controller.sc', FakeSoftwareController())
    @mock.patch('software.config.agent_mcast_group', FAKE_AGENT_MCAST_GROUP)
    def test_message_class_send(self):
        """'send' writes to a socket"""
        mock_sock = mock.Mock()

        # socket sendto and sendall are not called by:
        # PatchMessageHelloAgentAck
        # PatchMessageQueryDetailedResp
        # PatchMessageAgentInstallResp,

        send_to = [
            PatchMessageHello,
            PatchMessageHelloAck,
            PatchMessageSyncReq,
            PatchMessageSyncComplete,
            PatchMessageHelloAgent,
            PatchMessageSendLatestFeedCommit,
            PatchMessageAgentInstallReq,
            PatchMessageDropHostReq,
        ]
        send_all = [
            PatchMessageQueryDetailed,
        ]

        for message_class in SoftwareControllerMessagesTestCase.message_classes:
            mock_sock.reset_mock()
            test_obj = message_class()
            test_obj.send(mock_sock)
            if message_class in send_to:
                mock_sock.sendto.assert_called()
            if message_class in send_all:
                mock_sock.sendall.assert_called()

    @mock.patch('software.software_controller.sc', FakeSoftwareController())
    @mock.patch('software.db.api.SoftwareAPI.get_deploy_host_by_hostname',
                return_value={"state": DEPLOY_HOST_STATES.DEPLOYING})
    @mock.patch('software.software_entities.DeployHostHandler.update', return_value=True)
    def test_message_class_handle(self, mock_get_deploy_host_by_hostname, mock_update):  # pylint: disable=unused-argument
        """'handle' method tests"""
        addr = [FAKE_CONTROLLER_ADDRESS, ]  # addr is a list
        mock_sock = mock.Mock()
        special_setup = {
            PatchMessageDropHostReq: ('ip', FAKE_HOST_IP),
            PatchMessageAgentInstallResp: ('status', True),
        }

        for message_class in SoftwareControllerMessagesTestCase.message_classes:
            mock_sock.reset_mock()
            test_obj = message_class()
            # some classes require special setup
            special = special_setup.get(message_class)
            if special:
                setattr(test_obj, special[0], special[1])
            test_obj.handle(mock_sock, addr)
