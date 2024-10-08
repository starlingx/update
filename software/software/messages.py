"""
Copyright (c) 2023 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

from software.software_functions import LOG

PATCHMSG_UNKNOWN = 0
PATCHMSG_HELLO = 1
PATCHMSG_HELLO_ACK = 2
PATCHMSG_SYNC_REQ = 3
PATCHMSG_SYNC_COMPLETE = 4
PATCHMSG_HELLO_AGENT = 5
PATCHMSG_HELLO_AGENT_ACK = 6
PATCHMSG_QUERY_DETAILED = 7
PATCHMSG_QUERY_DETAILED_RESP = 8
PATCHMSG_AGENT_INSTALL_REQ = 9
PATCHMSG_AGENT_INSTALL_RESP = 10
PATCHMSG_DROP_HOST_REQ = 11
PATCHMSG_SEND_LATEST_FEED_COMMIT = 12
PATCHMSG_DEPLOY_STATE_UPDATE = 13
PATCHMSG_DEPLOY_STATE_UPDATE_ACK = 14
PATCHMSG_DEPLOY_STATE_CHANGED = 15
PATCHMSG_DEPLOY_STATE_CHANGED_ACK = 16
PATCHMSG_DEPLOY_DELETE_CLEANUP_REQ = 17
PATCHMSG_DEPLOY_DELETE_CLEANUP_RESP = 18
PATCHMSG_CHECK_AGENT_ALIVE_REQ = 19
PATCHMSG_CHECK_AGENT_ALIVE_RESP = 20

PATCHMSG_STR = {
    PATCHMSG_UNKNOWN: "unknown",
    PATCHMSG_HELLO: "hello",
    PATCHMSG_HELLO_ACK: "hello-ack",
    PATCHMSG_SYNC_REQ: "sync-req",
    PATCHMSG_SYNC_COMPLETE: "sync-complete",
    PATCHMSG_HELLO_AGENT: "hello-agent",
    PATCHMSG_HELLO_AGENT_ACK: "hello-agent-ack",
    PATCHMSG_QUERY_DETAILED: "query-detailed",
    PATCHMSG_QUERY_DETAILED_RESP: "query-detailed-resp",
    PATCHMSG_AGENT_INSTALL_REQ: "agent-install-req",
    PATCHMSG_AGENT_INSTALL_RESP: "agent-install-resp",
    PATCHMSG_DROP_HOST_REQ: "drop-host-req",
    PATCHMSG_SEND_LATEST_FEED_COMMIT: "send-latest-feed-commit",
    PATCHMSG_DEPLOY_STATE_UPDATE: "deploy-state-update",
    PATCHMSG_DEPLOY_STATE_UPDATE_ACK: "deploy-state-update-ack",
    PATCHMSG_DEPLOY_STATE_CHANGED: "deploy-state-changed",
    PATCHMSG_DEPLOY_STATE_CHANGED_ACK: "deploy-state-changed-ack",
    PATCHMSG_DEPLOY_DELETE_CLEANUP_REQ: "deploy-delete-cleanup-req",
    PATCHMSG_DEPLOY_DELETE_CLEANUP_RESP: "deploy-delete-cleanup-resp",
    PATCHMSG_CHECK_AGENT_ALIVE_REQ: "check-agent-alive-req",
    PATCHMSG_CHECK_AGENT_ALIVE_RESP: "check-agent-alive-resp",
}

MSG_ACK_SUCCESS = 'success'


class PatchMessage(object):
    def __init__(self, msgtype=PATCHMSG_UNKNOWN):
        self.msgtype = msgtype
        self.msgversion = 1
        self.message = {}

    def decode(self, data):
        if 'msgtype' in data:
            self.msgtype = data['msgtype']
        if 'msgversion' in data:
            self.msgversion = data['msgversion']

    def encode(self):
        self.message['msgtype'] = self.msgtype
        self.message['msgversion'] = self.msgversion

    def data(self):
        return {'msgtype': self.msgtype}

    def msgtype_str(self):
        if self.msgtype in PATCHMSG_STR:
            return PATCHMSG_STR[self.msgtype]
        return "invalid-type"

    def handle(self, sock, addr):  # pylint: disable=unused-argument
        LOG.info("Unhandled message type: %s", self.msgtype)
