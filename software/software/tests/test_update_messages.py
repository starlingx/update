#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for software.messages module."""

import unittest

from software.tests import base  # noqa: F401
from software.messages import PATCHMSG_AGENT_INSTALL_REQ
from software.messages import PATCHMSG_AGENT_INSTALL_RESP
from software.messages import PATCHMSG_CHECK_AGENT_ALIVE_REQ
from software.messages import PATCHMSG_CHECK_AGENT_ALIVE_RESP
from software.messages import PATCHMSG_DEPLOY_DELETE_CLEANUP_REQ
from software.messages import PATCHMSG_DEPLOY_DELETE_CLEANUP_RESP
from software.messages import PATCHMSG_DEPLOY_STATE_CHANGED
from software.messages import PATCHMSG_DEPLOY_STATE_CHANGED_ACK
from software.messages import PATCHMSG_DEPLOY_STATE_UPDATE
from software.messages import PATCHMSG_DEPLOY_STATE_UPDATE_ACK
from software.messages import PATCHMSG_DROP_HOST_REQ
from software.messages import PATCHMSG_HELLO
from software.messages import PATCHMSG_HELLO_ACK
from software.messages import PATCHMSG_HELLO_AGENT
from software.messages import PATCHMSG_HELLO_AGENT_ACK
from software.messages import PATCHMSG_QUERY_DETAILED
from software.messages import PATCHMSG_QUERY_DETAILED_RESP
from software.messages import PATCHMSG_RELEASE_STATE_UPDATE
from software.messages import PATCHMSG_SEND_LATEST_FEED_COMMIT
from software.messages import PATCHMSG_STR
from software.messages import PATCHMSG_SYNC_COMPLETE
from software.messages import PATCHMSG_SYNC_REQ
from software.messages import PATCHMSG_UNKNOWN
from software.messages import PatchMessage


class TestMessageConstants(unittest.TestCase):
    """Tests for message type constants."""

    def test_wire_values_are_unique(self):
        """Message type ids go over the wire between controller and agent,
        so two types must never share an id.
            """
        ids = [PATCHMSG_UNKNOWN, PATCHMSG_HELLO, PATCHMSG_HELLO_ACK,
               PATCHMSG_SYNC_REQ, PATCHMSG_SYNC_COMPLETE,
               PATCHMSG_HELLO_AGENT, PATCHMSG_HELLO_AGENT_ACK,
               PATCHMSG_QUERY_DETAILED, PATCHMSG_QUERY_DETAILED_RESP,
               PATCHMSG_AGENT_INSTALL_REQ, PATCHMSG_AGENT_INSTALL_RESP,
               PATCHMSG_DROP_HOST_REQ, PATCHMSG_SEND_LATEST_FEED_COMMIT,
               PATCHMSG_DEPLOY_STATE_UPDATE, PATCHMSG_DEPLOY_STATE_UPDATE_ACK,
               PATCHMSG_DEPLOY_STATE_CHANGED,
               PATCHMSG_DEPLOY_STATE_CHANGED_ACK,
               PATCHMSG_DEPLOY_DELETE_CLEANUP_REQ,
               PATCHMSG_DEPLOY_DELETE_CLEANUP_RESP,
               PATCHMSG_CHECK_AGENT_ALIVE_REQ,
               PATCHMSG_CHECK_AGENT_ALIVE_RESP,
               PATCHMSG_RELEASE_STATE_UPDATE]
        self.assertEqual(len(ids), len(set(ids)))

    def test_unknown_is_the_zero_default(self):
        """PatchMessage defaults to PATCHMSG_UNKNOWN, which must stay 0 so an
        absent msgtype decodes as unknown rather than a real type.
            """
        self.assertEqual(PATCHMSG_UNKNOWN, 0)

    def test_patchmsg_str_mapping(self):
        """Test PATCHMSG_STR has all message types."""
        self.assertEqual(PATCHMSG_STR[PATCHMSG_UNKNOWN], "unknown")
        self.assertEqual(PATCHMSG_STR[PATCHMSG_HELLO], "hello")
        self.assertEqual(PATCHMSG_STR[PATCHMSG_HELLO_ACK], "hello-ack")
        self.assertEqual(PATCHMSG_STR[PATCHMSG_SYNC_REQ], "sync-req")
        self.assertEqual(PATCHMSG_STR[PATCHMSG_HELLO_AGENT], "hello-agent")
        self.assertEqual(PATCHMSG_STR[PATCHMSG_RELEASE_STATE_UPDATE],
                         "release-state-update")


class TestPatchMessage(unittest.TestCase):
    """Tests for PatchMessage class."""

    def test_default_init(self):
        """Test default initialization."""
        msg = PatchMessage()
        self.assertEqual(msg.msgtype, PATCHMSG_UNKNOWN)
        self.assertEqual(msg.msgversion, 1)
        self.assertEqual(msg.message, {})

    def test_init_with_type(self):
        """Test initialization with specific type."""
        msg = PatchMessage(PATCHMSG_HELLO)
        self.assertEqual(msg.msgtype, PATCHMSG_HELLO)

    def test_encode(self):
        """Test message encoding."""
        msg = PatchMessage(PATCHMSG_HELLO)
        msg.encode()
        self.assertEqual(msg.message['msgtype'], PATCHMSG_HELLO)
        self.assertEqual(msg.message['msgversion'], 1)

    def test_decode(self):
        """Test message decoding."""
        msg = PatchMessage()
        msg.decode({'msgtype': PATCHMSG_SYNC_REQ, 'msgversion': 2})
        self.assertEqual(msg.msgtype, PATCHMSG_SYNC_REQ)
        self.assertEqual(msg.msgversion, 2)

    def test_decode_partial(self):
        """Test decoding with partial data."""
        msg = PatchMessage()
        msg.decode({'msgtype': PATCHMSG_HELLO})
        self.assertEqual(msg.msgtype, PATCHMSG_HELLO)
        self.assertEqual(msg.msgversion, 1)  # unchanged

    def test_decode_empty(self):
        """Test decoding with empty data."""
        msg = PatchMessage()
        msg.decode({})
        self.assertEqual(msg.msgtype, PATCHMSG_UNKNOWN)

    def test_data(self):
        """Test data method."""
        msg = PatchMessage(PATCHMSG_HELLO)
        data = msg.data()
        self.assertEqual(data, {'msgtype': PATCHMSG_HELLO})

    def test_msgtype_str_known(self):
        """Test msgtype_str for known type."""
        msg = PatchMessage(PATCHMSG_HELLO)
        self.assertEqual(msg.msgtype_str(), "hello")

    def test_msgtype_str_unknown(self):
        """Test msgtype_str for unknown type."""
        msg = PatchMessage(999)
        self.assertEqual(msg.msgtype_str(), "invalid-type")
