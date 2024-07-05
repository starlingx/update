#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import argparse
import json
from oslo_log import log
import socket

import software.config as cfg
from software.messages import PATCHMSG_DEPLOY_STATE_CHANGED


LOG = log.getLogger(__name__)
MAX_RETRY = 3
RETRY_INTERVAL = 1
ACK_OK = "OK"


def get_udp_socket(server_addr, server_port):
    addr = socket.getaddrinfo(server_addr, server_port)
    if len(addr) > 0:
        addr_family = addr[0][0]
    else:
        err = "Invalid server address (%s) or port (%s)" % \
              (server_addr, server_port)
        raise Exception(err)

    sock = socket.socket(addr_family, socket.SOCK_DGRAM)
    return sock


def update_deploy_state(agent, deploy_state=None, host=None, host_state=None, timeout=1):
    """
    Send MessageDeployStateChanged message to software-controller via
    upd packet, wait for ack or raise exception.
    The message is a serialized json object:
    {
         "msgtype": PATCHMSG_DEPLOY_STATE_CHANGED,
         "msgversion": 1,
         "agent": "<a valid agent>",
         "deploy-state": "<deploy-state>",
         "hostname": "<hostname>",
         "host-state": "<host-deploy-substate>"
    }
    """

    server_addr = "controller"
    # Use localhost for prebootstrap case
    if not cfg.get_mgmt_ip():
        server_addr = "localhost"
    cfg.read_config()
    server_port = cfg.controller_port

    msg = {
        "msgtype": PATCHMSG_DEPLOY_STATE_CHANGED,
        "msgversion": 1,
        "agent": agent,
        "deploy-state": deploy_state,
        "hostname": host,
        "host-state": host_state
    }

    msg_txt = json.dumps(msg)

    sock = get_udp_socket(server_addr, server_port)

    if timeout >= 0:
        sock.settimeout(timeout)

    resp = ""

    for _ in range(MAX_RETRY):
        sock.sendto(str.encode(msg_txt), (server_addr, server_port))

        try:
            resp = sock.recv(64).decode()
        except socket.timeout:
            LOG.warning("timeout %s sec expired for ack" % timeout)
        else:
            break

    if resp != ACK_OK:
        err = "%s failed updating deploy state %s %s %s" % \
              (agent, deploy_state, host, host_state)
        raise Exception(err)


def update_state():
    # this is the entry point to update deploy state

    parser = argparse.ArgumentParser(add_help=False)

    parser.add_argument("agent",
                        default=False,
                        help="service agent")

    parser.add_argument('-s', '--state',
                        default=False,
                        help="deploy state")

    parser.add_argument('-h', '--host',
                        default=False,
                        help="host name")

    parser.add_argument('-t', '--host_state',
                        default=False,
                        help="host state")

    args = parser.parse_args()

    update_deploy_state(args.agent, deploy_state=args.state,
                        host=args.host, host_state=args.host_state)
