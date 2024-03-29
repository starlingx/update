"""
Copyright (c) 2023-2024 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import sys

# prevent software_controller from importing osprofiler
sys.modules['osprofiler'] = None

import configparser
import gc
import json
import os
import select
import sh
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from wsgiref import simple_server

from oslo_config import cfg as oslo_cfg

import software.apt_utils as apt_utils
import software.ostree_utils as ostree_utils
from software.api import app
from software.authapi import app as auth_app
from software.constants import DEPLOY_STATES
from software.base import PatchService
from software.dc_utils import get_subcloud_groupby_version
from software.exceptions import APTOSTreeCommandFail
from software.exceptions import InternalError
from software.exceptions import MetadataFail
from software.exceptions import UpgradeNotSupported
from software.exceptions import OSTreeCommandFail
from software.exceptions import OSTreeTarFail
from software.exceptions import SoftwareError
from software.exceptions import SoftwareFail
from software.exceptions import ReleaseInvalidRequest
from software.exceptions import ReleaseValidationFailure
from software.exceptions import ReleaseMismatchFailure
from software.exceptions import ReleaseIsoDeleteFailure
from software.exceptions import SoftwareServiceError
from software.release_data import SWReleaseCollection
from software.software_functions import collect_current_load_for_hosts
from software.software_functions import create_deploy_hosts
from software.software_functions import parse_release_metadata
from software.software_functions import configure_logging
from software.software_functions import mount_iso_load
from software.software_functions import unmount_iso_load
from software.software_functions import read_upgrade_support_versions
from software.software_functions import BasePackageData
from software.software_functions import PatchFile
from software.software_functions import package_dir
from software.software_functions import repo_dir
from software.software_functions import root_scripts_dir
from software.software_functions import SW_VERSION
from software.software_functions import LOG
from software.software_functions import audit_log_info
from software.software_functions import repo_root_dir
from software.software_functions import ReleaseData
from software.release_verify import verify_files
import software.config as cfg
import software.utils as utils
from software.sysinv_utils import get_k8s_ver
from software.sysinv_utils import is_system_controller

from software.db.api import get_instance

import software.messages as messages
import software.constants as constants

from tsconfig.tsconfig import INITIAL_CONFIG_COMPLETE_FLAG
from tsconfig.tsconfig import INITIAL_CONTROLLER_CONFIG_COMPLETE
import xml.etree.ElementTree as ET


CONF = oslo_cfg.CONF

pidfile_path = "/var/run/patch_controller.pid"

sc = None
state_file = "%s/.controller.state" % constants.SOFTWARE_STORAGE_DIR
app_dependency_basename = "app_dependencies.json"
app_dependency_filename = "%s/%s" % (constants.SOFTWARE_STORAGE_DIR, app_dependency_basename)

insvc_patch_restart_controller = "/run/software/.restart.software-controller"

ETC_HOSTS_FILE_PATH = "/etc/hosts"
ETC_HOSTS_BACKUP_FILE_PATH = "/etc/hosts.patchbak"

stale_hosts = []
pending_queries = []

thread_death = None
keep_running = True

DEPLOY_STATE_METADATA_DIR_DICT = \
    {
        constants.AVAILABLE: constants.AVAILABLE_DIR,
        constants.UNAVAILABLE: constants.UNAVAILABLE_DIR,
        constants.DEPLOYING_START: constants.DEPLOYING_START_DIR,
        constants.DEPLOYING_HOST: constants.DEPLOYING_HOST_DIR,
        constants.DEPLOYING_ACTIVATE: constants.DEPLOYING_ACTIVATE_DIR,
        constants.DEPLOYING_COMPLETE: constants.DEPLOYING_COMPLETE_DIR,
        constants.DEPLOYED: constants.DEPLOYED_DIR,
        constants.REMOVING: constants.REMOVING_DIR,
        constants.ABORTING: constants.ABORTING_DIR,
        constants.COMMITTED: constants.COMMITTED_DIR,
    }
# Limit socket blocking to 5 seconds to allow for thread to shutdown
api_socket_timeout = 5.0


class ControllerNeighbour(object):
    def __init__(self):
        self.last_ack = 0
        self.synced = False

    def rx_ack(self):
        self.last_ack = time.time()

    def get_age(self):
        return int(time.time() - self.last_ack)

    def rx_synced(self):
        self.synced = True

    def clear_synced(self):
        self.synced = False

    def get_synced(self):
        return self.synced


class AgentNeighbour(object):
    def __init__(self, ip):
        self.ip = ip
        self.last_ack = 0
        self.last_query_id = 0
        self.out_of_date = False
        self.hostname = "n/a"
        self.requires_reboot = False
        self.patch_failed = False
        self.stale = False
        self.pending_query = False
        self.latest_sysroot_commit = None
        self.nodetype = None
        self.sw_version = "unknown"
        self.subfunctions = []
        self.state = None

    def rx_ack(self,
               hostname,
               out_of_date,
               requires_reboot,
               query_id,
               patch_failed,
               sw_version,
               state):
        self.last_ack = time.time()
        self.hostname = hostname
        self.patch_failed = patch_failed
        self.sw_version = sw_version
        self.state = state

        if out_of_date != self.out_of_date or requires_reboot != self.requires_reboot:
            self.out_of_date = out_of_date
            self.requires_reboot = requires_reboot
            LOG.info("Agent %s (%s) reporting out_of_date=%s, requires_reboot=%s",
                     self.hostname,
                     self.ip,
                     self.out_of_date,
                     self.requires_reboot)

        if self.last_query_id != query_id:
            self.last_query_id = query_id
            self.stale = True
            if self.ip not in stale_hosts and self.ip not in pending_queries:
                stale_hosts.append(self.ip)

    def get_age(self):
        return int(time.time() - self.last_ack)

    def handle_query_detailed_resp(self,
                                   latest_sysroot_commit,
                                   nodetype,
                                   sw_version,
                                   subfunctions,
                                   state):
        self.latest_sysroot_commit = latest_sysroot_commit
        self.nodetype = nodetype
        self.stale = False
        self.pending_query = False
        self.sw_version = sw_version
        self.subfunctions = subfunctions
        self.state = state

        if self.ip in pending_queries:
            pending_queries.remove(self.ip)

        if self.ip in stale_hosts:
            stale_hosts.remove(self.ip)

    def get_dict(self):
        d = {"ip": self.ip,
             "hostname": self.hostname,
             "deployed": not self.out_of_date,
             "secs_since_ack": self.get_age(),
             "patch_failed": self.patch_failed,
             "stale_details": self.stale,
             "latest_sysroot_commit": self.latest_sysroot_commit,
             "nodetype": self.nodetype,
             "subfunctions": self.subfunctions,
             "sw_version": self.sw_version,
             "state": self.state}

        global sc
        if self.out_of_date and not sc.allow_insvc_patching:
            d["requires_reboot"] = True
        else:
            d["requires_reboot"] = self.requires_reboot

        # Included for future enhancement, to allow per-node determination
        # of in-service patching
        d["allow_insvc_patching"] = sc.allow_insvc_patching

        return d


class PatchMessageHello(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_HELLO)
        self.patch_op_counter = 0

    def decode(self, data):
        messages.PatchMessage.decode(self, data)
        if 'patch_op_counter' in data:
            self.patch_op_counter = data['patch_op_counter']

    def encode(self):
        global sc
        messages.PatchMessage.encode(self)
        self.message['patch_op_counter'] = sc.patch_op_counter

    def handle(self, sock, addr):
        global sc
        host = addr[0]
        if host == cfg.get_mgmt_ip():
            # Ignore messages from self
            return

        # Send response
        if self.patch_op_counter > 0:
            sc.handle_nbr_patch_op_counter(host, self.patch_op_counter)

        resp = PatchMessageHelloAck()
        resp.send(sock)

    def send(self, sock):
        global sc
        self.encode()
        message = json.dumps(self.message)
        sock.sendto(str.encode(message), (sc.controller_address, cfg.controller_port))


class PatchMessageHelloAck(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_HELLO_ACK)

    def encode(self):
        # Nothing to add, so just call the super class
        messages.PatchMessage.encode(self)

    def handle(self, sock, addr):
        global sc

        sc.controller_neighbours_lock.acquire()
        if not addr[0] in sc.controller_neighbours:
            sc.controller_neighbours[addr[0]] = ControllerNeighbour()

        sc.controller_neighbours[addr[0]].rx_ack()
        sc.controller_neighbours_lock.release()

    def send(self, sock):
        global sc
        self.encode()
        message = json.dumps(self.message)
        sock.sendto(str.encode(message), (sc.controller_address, cfg.controller_port))


class PatchMessageSyncReq(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_SYNC_REQ)

    def encode(self):
        # Nothing to add to the SYNC_REQ, so just call the super class
        messages.PatchMessage.encode(self)

    def handle(self, sock, addr):
        global sc
        host = addr[0]
        if host == cfg.get_mgmt_ip():
            # Ignore messages from self
            return

        # We may need to do this in a separate thread, so that we continue to process hellos
        LOG.info("Handling sync req")

        sc.sync_from_nbr(host)

        resp = PatchMessageSyncComplete()
        resp.send(sock)

    def send(self, sock):
        global sc
        LOG.info("sending sync req")
        self.encode()
        message = json.dumps(self.message)
        sock.sendto(str.encode(message), (sc.controller_address, cfg.controller_port))


class PatchMessageSyncComplete(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_SYNC_COMPLETE)

    def encode(self):
        # Nothing to add to the SYNC_COMPLETE, so just call the super class
        messages.PatchMessage.encode(self)

    def handle(self, sock, addr):
        global sc
        LOG.info("Handling sync complete")

        sc.controller_neighbours_lock.acquire()
        if not addr[0] in sc.controller_neighbours:
            sc.controller_neighbours[addr[0]] = ControllerNeighbour()

        sc.controller_neighbours[addr[0]].rx_synced()
        sc.controller_neighbours_lock.release()

    def send(self, sock):
        global sc
        LOG.info("sending sync complete")
        self.encode()
        message = json.dumps(self.message)
        sock.sendto(str.encode(message), (sc.controller_address, cfg.controller_port))


class PatchMessageHelloAgent(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_HELLO_AGENT)

    def encode(self):
        global sc
        messages.PatchMessage.encode(self)
        self.message['patch_op_counter'] = sc.patch_op_counter

    def handle(self, sock, addr):
        LOG.error("Should not get here")

    def send(self, sock):
        global sc
        self.encode()
        message = json.dumps(self.message)
        local_hostname = utils.ip_to_versioned_localhost(cfg.agent_mcast_group)
        sock.sendto(str.encode(message), (sc.agent_address, cfg.agent_port))
        sock.sendto(str.encode(message), (local_hostname, cfg.agent_port))


class PatchMessageSendLatestFeedCommit(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_SEND_LATEST_FEED_COMMIT)

    def encode(self):
        global sc
        messages.PatchMessage.encode(self)
        self.message['latest_feed_commit'] = sc.latest_feed_commit

    def handle(self, sock, addr):
        LOG.error("Should not get here")

    def send(self, sock):
        global sc
        self.encode()
        message = json.dumps(self.message)
        local_hostname = utils.ip_to_versioned_localhost(cfg.agent_mcast_group)
        sock.sendto(str.encode(message), (sc.agent_address, cfg.agent_port))
        sock.sendto(str.encode(message), (local_hostname, cfg.agent_port))


class PatchMessageHelloAgentAck(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_HELLO_AGENT_ACK)
        self.query_id = 0
        self.agent_out_of_date = False
        self.agent_hostname = "n/a"
        self.agent_requires_reboot = False
        self.agent_patch_failed = False
        self.agent_sw_version = "unknown"
        self.agent_state = "unknown"

    def decode(self, data):
        messages.PatchMessage.decode(self, data)
        if 'query_id' in data:
            self.query_id = data['query_id']
        if 'out_of_date' in data:
            self.agent_out_of_date = data['out_of_date']
        if 'hostname' in data:
            self.agent_hostname = data['hostname']
        if 'requires_reboot' in data:
            self.agent_requires_reboot = data['requires_reboot']
        if 'patch_failed' in data:
            self.agent_patch_failed = data['patch_failed']
        if 'sw_version' in data:
            self.agent_sw_version = data['sw_version']
        if 'state' in data:
            self.agent_state = data['state']

    def encode(self):
        # Nothing to add, so just call the super class
        messages.PatchMessage.encode(self)

    def handle(self, sock, addr):
        global sc

        sc.hosts_lock.acquire()
        if not addr[0] in sc.hosts:
            sc.hosts[addr[0]] = AgentNeighbour(addr[0])

        sc.hosts[addr[0]].rx_ack(self.agent_hostname,
                                 self.agent_out_of_date,
                                 self.agent_requires_reboot,
                                 self.query_id,
                                 self.agent_patch_failed,
                                 self.agent_sw_version,
                                 self.agent_state)
        sc.hosts_lock.release()

    def send(self, sock):  # pylint: disable=unused-argument
        LOG.error("Should not get here")


class PatchMessageQueryDetailed(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_QUERY_DETAILED)

    def encode(self):
        # Nothing to add to the message, so just call the super class
        messages.PatchMessage.encode(self)

    def handle(self, sock, addr):
        LOG.error("Should not get here")

    def send(self, sock):
        self.encode()
        message = json.dumps(self.message)
        sock.sendall(str.encode(message))


class PatchMessageQueryDetailedResp(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_QUERY_DETAILED_RESP)
        self.agent_sw_version = "unknown"
        self.latest_sysroot_commit = "unknown"
        self.subfunctions = []
        self.nodetype = "unknown"
        self.agent_sw_version = "unknown"
        self.agent_state = "unknown"

    def decode(self, data):
        messages.PatchMessage.decode(self, data)
        if 'latest_sysroot_commit' in data:
            self.latest_sysroot_commit = data['latest_sysroot_commit']
        if 'nodetype' in data:
            self.nodetype = data['nodetype']
        if 'sw_version' in data:
            self.agent_sw_version = data['sw_version']
        if 'subfunctions' in data:
            self.subfunctions = data['subfunctions']
        if 'state' in data:
            self.agent_state = data['state']

    def encode(self):
        LOG.error("Should not get here")

    def handle(self, sock, addr):
        global sc

        ip = addr[0]
        sc.hosts_lock.acquire()
        if ip in sc.hosts:
            sc.hosts[ip].handle_query_detailed_resp(self.latest_sysroot_commit,
                                                    self.nodetype,
                                                    self.agent_sw_version,
                                                    self.subfunctions,
                                                    self.agent_state)
            for patch_id in list(sc.interim_state):
                if ip in sc.interim_state[patch_id]:
                    sc.interim_state[patch_id].remove(ip)
                    if len(sc.interim_state[patch_id]) == 0:
                        del sc.interim_state[patch_id]
            sc.hosts_lock.release()
            sc.check_patch_states()
        else:
            sc.hosts_lock.release()

    def send(self, sock):  # pylint: disable=unused-argument
        LOG.error("Should not get here")


class PatchMessageAgentInstallReq(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_AGENT_INSTALL_REQ)
        self.ip = None
        self.force = False

    def encode(self):
        global sc
        messages.PatchMessage.encode(self)
        self.message['force'] = self.force

    def handle(self, sock, addr):
        LOG.error("Should not get here")

    def send(self, sock):
        LOG.info("sending install request to node: %s", self.ip)
        self.encode()
        message = json.dumps(self.message)
        sock.sendto(str.encode(message), (self.ip, cfg.agent_port))


class PatchMessageAgentInstallResp(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_AGENT_INSTALL_RESP)
        self.status = False
        self.reject_reason = None

    def decode(self, data):
        messages.PatchMessage.decode(self, data)
        if 'status' in data:
            self.status = data['status']
        if 'reject_reason' in data:
            self.reject_reason = data['reject_reason']

    def encode(self):
        # Nothing to add, so just call the super class
        messages.PatchMessage.encode(self)

    def handle(self, sock, addr):
        LOG.info("Handling install resp from %s", addr[0])
        global sc
        # LOG.info("Handling hello ack")

        sc.hosts_lock.acquire()
        if not addr[0] in sc.hosts:
            sc.hosts[addr[0]] = AgentNeighbour(addr[0])

        sc.hosts[addr[0]].install_status = self.status
        sc.hosts[addr[0]].install_pending = False
        sc.hosts[addr[0]].install_reject_reason = self.reject_reason
        sc.hosts_lock.release()

    def send(self, sock):  # pylint: disable=unused-argument
        LOG.error("Should not get here")


class PatchMessageDropHostReq(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_DROP_HOST_REQ)
        self.ip = None

    def encode(self):
        messages.PatchMessage.encode(self)
        self.message['ip'] = self.ip

    def decode(self, data):
        messages.PatchMessage.decode(self, data)
        if 'ip' in data:
            self.ip = data['ip']

    def handle(self, sock, addr):
        global sc
        host = addr[0]
        if host == cfg.get_mgmt_ip():
            # Ignore messages from self
            return

        if self.ip is None:
            LOG.error("Received PATCHMSG_DROP_HOST_REQ with no ip: %s", json.dumps(self.data))
            return

        sc.drop_host(self.ip, sync_nbr=False)
        return

    def send(self, sock):
        global sc
        self.encode()
        message = json.dumps(self.message)
        sock.sendto(str.encode(message), (sc.controller_address, cfg.controller_port))


class SoftwareMessageDeployStateUpdate(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_DEPLOY_STATE_UPDATE)

    def encode(self):
        global sc
        messages.PatchMessage.encode(self)
        filesystem_data = utils.get_software_filesystem_data()
        deploys_state = {"deploy_host": filesystem_data.get("deploy_host", {}),
                         "deploy": filesystem_data.get("deploy", {})}
        self.message["deploy_state"] = deploys_state

    def handle(self, sock, addr):  # pylint: disable=unused-argument
        LOG.error("Should not get here")

    def send(self, sock):
        global sc
        self.encode()
        message = json.dumps(self.message)
        sock.sendto(str.encode(message), (sc.agent_address, cfg.agent_port))


class SoftwareMessageDeployStateUpdateAck(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_DEPLOY_STATE_UPDATE_ACK)
        self.peer_state_data = {}

    def decode(self, data):
        messages.PatchMessage.decode(self, data)
        self.peer_state_data = data

    def encode(self):
        # Nothing to add, so just call the super class
        messages.PatchMessage.encode(self)

    def handle(self, sock, addr):
        global sc
        if self.peer_state_data["result"] == messages.MSG_ACK_SUCCESS:
            LOG.debug("Peer controller is synced with value: %s",
                      self.peer_state_data["deploy_state"])
        else:
            LOG.error("Peer controller deploy state has diverged.")


class SWMessageDeployStateChanged(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_DEPLOY_STATE_CHANGED)
        self.valid = False
        self.agent = None
        self.deploy_state = None
        self.hostname = None
        self.host_state = None

    def decode(self, data):
        """
        The message is a serialized json object:
        {
             "msgtype": "deploy-state-changed",
             "msgversion": 1,
             "agent": "<a valid agent>",
             "deploy-state": "<deploy-state>",
             "hostname": "<hostname>",
             "host-state": "<host-deploy-substate>"
        }
        """

        messages.PatchMessage.decode(self, data)

        self.valid = True
        self.agent = None

        valid_agents = ['deploy-start']
        if 'agent' in data:
            agent = data['agent']
        else:
            agent = 'unknown'

        if agent not in valid_agents:
            # ignore msg from unknown senders
            LOG.info("%s received from unknown agent %s" %
                     (messages.PATCHMSG_DEPLOY_STATE_CHANGED, agent))
            self.valid = False

        valid_state = {
            DEPLOY_STATES.START_DONE.value: DEPLOY_STATES.START_DONE,
            DEPLOY_STATES.START_FAILED.value: DEPLOY_STATES.START_FAILED
        }
        if 'deploy-state' in data and data['deploy-state']:
            deploy_state = data['deploy-state']
            if deploy_state in valid_state:
                self.deploy_state = valid_state[deploy_state]
                LOG.info("%s received from %s with deploy-state %s" %
                         (messages.PATCHMSG_DEPLOY_STATE_CHANGED, agent, deploy_state))
            else:
                self.valid = False
                LOG.error("%s received from %s with invalid deploy-state %s" %
                          (messages.PATCHMSG_DEPLOY_STATE_CHANGED, agent, deploy_state))

        if 'hostname' in data and data['hostname']:
            self.hostname = data['hostname']

        if 'host-state' in data and data['host-state']:
            host_state = data['host-state']
            if host_state not in constants.VALID_HOST_DEPLOY_STATE:
                LOG.error("%s received from %s with invalid host-state %s" %
                          (messages.PATCHMSG_DEPLOY_STATE_CHANGED, agent, host_state))
                self.valid = False
            else:
                self.host_state = host_state

        if self.valid:
            self.valid = (bool(self.host_state and self.hostname) != bool(self.deploy_state))

        if not self.valid:
            LOG.error("%s received from %s as invalid %s" %
                      (messages.PATCHMSG_DEPLOY_STATE_CHANGED, agent, data))

    def handle(self, sock, addr):
        global sc
        if not self.valid:
            # nothing to do
            return

        if self.deploy_state:
            LOG.info("Received deploy state changed to %s, agent %s" %
                     (self.deploy_state, self.agent))
            sc.deploy_state_changed(self.deploy_state)
        else:
            LOG.info("Received %s deploy state changed to %s, agent %s" %
                     (self.hostname, self.host_state, self.agent))
            sc.host_deploy_state_changed(self.hostname, self.host_state)

        sock.sendto(str.encode("OK"), addr)

    def send(self, sock):
        global sc
        LOG.info("sending sync req")
        self.encode()
        message = json.dumps(self.message)
        sock.sendto(str.encode(message), (sc.controller_address, cfg.controller_port))


class PatchController(PatchService):
    def __init__(self):
        PatchService.__init__(self)

        # Locks
        self.socket_lock = threading.RLock()
        self.controller_neighbours_lock = threading.RLock()
        self.hosts_lock = threading.RLock()
        self.release_data_lock = threading.RLock()

        self.hosts = {}
        self.controller_neighbours = {}

        self.db_api_instance = get_instance()

        # interim_state is used to track hosts that have not responded
        # with fresh queries since a patch was applied or removed, on
        # a per-patch basis. This allows the patch controller to move
        # patches immediately into a "Partial" state until all nodes
        # have responded.
        #
        self.interim_state = {}

        self.sock_out = None
        self.sock_in = None
        self.controller_address = None
        self.agent_address = None
        self.patch_op_counter = 1
        self.release_data = ReleaseData()
        self.release_data.load_all()
        try:
            self.latest_feed_commit = ostree_utils.get_feed_latest_commit(SW_VERSION)
        except OSTreeCommandFail:
            LOG.exception("Failure to fetch the feed ostree latest log while "
                          "initializing Patch Controller")
            self.latest_feed_commit = None

        self.check_patch_states()
        self.base_pkgdata = BasePackageData()

        self.allow_insvc_patching = True

        if os.path.exists(app_dependency_filename):
            try:
                with open(app_dependency_filename, 'r') as f:
                    self.app_dependencies = json.loads(f.read())
            except Exception:
                LOG.exception("Failed to read app dependencies: %s", app_dependency_filename)
        else:
            self.app_dependencies = {}

        if os.path.isfile(state_file):
            self.read_state_file()
        else:
            self.write_state_file()

    @property
    def release_collection(self):
        # for this stage, the SWReleaseCollection behaves as a broker which
        # does not hold any release data. it only last one request
        swrc = SWReleaseCollection(self.release_data)
        return swrc

    def update_config(self):
        cfg.read_config()

        if self.port != cfg.controller_port:
            self.port = cfg.controller_port

        # Loopback interface does not support multicast messaging, therefore
        # revert to using unicast messaging when configured against the
        # loopback device
        if cfg.get_mgmt_iface() == constants.LOOPBACK_INTERFACE_NAME:
            mgmt_ip = cfg.get_mgmt_ip()
            self.mcast_addr = None
            self.controller_address = mgmt_ip
            self.agent_address = mgmt_ip
        else:
            self.mcast_addr = cfg.controller_mcast_group
            self.controller_address = cfg.controller_mcast_group
            self.agent_address = cfg.agent_mcast_group

    def socket_lock_acquire(self):
        self.socket_lock.acquire()

    def socket_lock_release(self):
        try:
            self.socket_lock.release()
        except Exception:
            pass

    def write_state_file(self):
        config = configparser.ConfigParser(strict=False)

        cfgfile = open(state_file, 'w')

        config.add_section('runtime')
        config.set('runtime', 'patch_op_counter', str(self.patch_op_counter))
        config.write(cfgfile)
        cfgfile.close()

    def read_state_file(self):
        config = configparser.ConfigParser(strict=False)

        config.read(state_file)

        try:
            counter = config.getint('runtime', 'patch_op_counter')
            self.patch_op_counter = counter

            LOG.info("patch_op_counter is: %d", self.patch_op_counter)
        except configparser.Error:
            LOG.exception("Failed to read state info")

    def handle_nbr_patch_op_counter(self, host, nbr_patch_op_counter):
        if self.patch_op_counter >= nbr_patch_op_counter:
            return

        self.sync_from_nbr(host)

    def sync_from_nbr(self, host):
        # Sync the software repo
        host_url = utils.ip_to_url(host)
        try:
            output = subprocess.check_output(["rsync",
                                              "-acv",
                                              "--delete",
                                              "--exclude", "tmp",
                                              "rsync://%s/software/" % host_url,
                                              "%s/" % constants.SOFTWARE_STORAGE_DIR],
                                             stderr=subprocess.STDOUT)
            LOG.info("Synced to mate software via rsync: %s", output)
        except subprocess.CalledProcessError as e:
            LOG.error("Failed to rsync: %s", e.output)
            return False

        try:
            output = subprocess.check_output(["rsync",
                                              "-acv",
                                              "--delete",
                                              "rsync://%s/repo/" % host_url,
                                              "%s/" % repo_root_dir],
                                             stderr=subprocess.STDOUT)
            LOG.info("Synced to mate repo via rsync: %s", output)
        except subprocess.CalledProcessError:
            LOG.error("Failed to rsync: %s", output)
            return False

        try:
            for neighbour in list(self.hosts):
                if (self.hosts[neighbour].nodetype == "controller" and
                        self.hosts[neighbour].ip == host):
                    LOG.info("Starting feed sync")
                    # The output is a string that lists the directories
                    # Example output:
                    # >>> dir_names = sh.ls("/var/www/pages/feed/")
                    # >>> dir_names.stdout
                    # b'rel-22.12  rel-22.5\n'
                    dir_names = sh.ls(constants.FEED_OSTREE_BASE_DIR)

                    # Convert the output above into a list that can be iterated
                    # >>> list_of_dirs = dir_names.stdout.decode().rstrip().split()
                    # >>> print(list_of_dirs)
                    # ['rel-22.12', 'rel-22.5']

                    list_of_dirs = dir_names.stdout.decode("utf-8").rstrip().split()

                    for rel_dir in list_of_dirs:
                        feed_ostree = "%s/%s/ostree_repo/" % (constants.FEED_OSTREE_BASE_DIR, rel_dir)
                        if not os.path.isdir(feed_ostree):
                            LOG.info("Skipping feed dir %s", feed_ostree)
                            continue
                        LOG.info("Syncing %s", feed_ostree)
                        output = subprocess.check_output(["ostree",
                                                          "--repo=%s" % feed_ostree,
                                                          "pull",
                                                          "--depth=-1",
                                                          "--mirror",
                                                          "starlingx"],
                                                         stderr=subprocess.STDOUT)
                        output = subprocess.check_output(["ostree",
                                                          "summary",
                                                          "--update",
                                                          "--repo=%s" % feed_ostree],
                                                         stderr=subprocess.STDOUT)
            LOG.info("Synced to mate feed via ostree pull: %s", output)
        except subprocess.CalledProcessError:
            LOG.error("Failed to sync feed repo between controllers: %s", output)
            return False

        self.read_state_file()

        with self.release_data_lock:
            with self.hosts_lock:
                self.interim_state = {}
                self.release_data.load_all()
                self.check_patch_states()

            if os.path.exists(app_dependency_filename):
                try:
                    with open(app_dependency_filename, 'r') as f:
                        self.app_dependencies = json.loads(f.read())
                except Exception:
                    LOG.exception("Failed to read app dependencies: %s", app_dependency_filename)
            else:
                self.app_dependencies = {}

        return True

    def inc_patch_op_counter(self):
        self.patch_op_counter += 1
        self.write_state_file()

    def check_patch_states(self):
        # Default to allowing in-service patching
        self.allow_insvc_patching = True

        for ip in (ip for ip in list(self.hosts) if self.hosts[ip].out_of_date):
            for release_id in self.release_data.metadata:
                if self.release_data.metadata[release_id].get("reboot_required") != "N" and \
                   self.release_data.metadata[release_id]["state"] == constants.DEPLOYING_START:
                    self.allow_insvc_patching = False

    def get_release_dependency_list(self, release):
        """
        Returns a list of software releases that are required by this
        release.
        Example: If R3 requires R2 and R2 requires R1,
                 then this patch will return ['R2', 'R1'] for
                 input param patch_id='R3'
        :param release: The software release version
        """
        if not self.release_data.metadata[release]["requires"]:
            return []
        else:
            release_dependency_list = []
            for req_release in self.release_data.metadata[release]["requires"]:
                release_dependency_list.append(req_release)
                release_dependency_list = release_dependency_list + \
                    self.get_release_dependency_list(req_release)
            return release_dependency_list

    def get_release_required_by_list(self, release):
        """
        Returns a list of software releases that require this
        release.
        Example: If R3 requires R2 and R2 requires R1,
                 then this method will return ['R3', 'R2'] for
                 input param patch_id='R1'
        :param release: The software release version
        """
        if release in self.release_data.metadata:
            release_required_by_list = []
            for req_release in self.release_data.metadata:
                if release in self.release_data.metadata[req_release]["requires"]:
                    release_required_by_list.append(req_release)
                    release_required_by_list = release_required_by_list + \
                        self.get_release_required_by_list(req_release)
            return release_required_by_list
        return []

    def get_ostree_tar_filename(self, patch_sw_version, patch_id):
        '''
        Returns the path of the ostree tarball
        :param patch_sw_version: sw version this patch must be applied to
        :param patch_id: The patch ID
        '''
        ostree_tar_dir = package_dir[patch_sw_version]
        ostree_tar_filename = "%s/%s-software.tar" % (ostree_tar_dir, patch_id)
        return ostree_tar_filename

    def delete_restart_script(self, patch_id):
        '''
        Deletes the restart script (if any) associated with the patch
        :param patch_id: The patch ID
        '''
        if not self.release_data.metadata[patch_id].get("restart_script"):
            return

        restart_script_path = "%s/%s" % (root_scripts_dir, self.release_data.metadata[patch_id]["restart_script"])
        try:
            # Delete the metadata
            os.remove(restart_script_path)
        except OSError:
            msg = "Failed to remove restart script for %s" % patch_id
            LOG.exception(msg)
            raise SoftwareError(msg)

    def run_semantic_check(self, action, patch_list):
        if not os.path.exists(INITIAL_CONFIG_COMPLETE_FLAG):
            # Skip semantic checks if initial configuration isn't complete
            return

        # Pass the current patch state to the semantic check as a series of args
        patch_state_args = []
        for patch_id in list(self.release_data.metadata):
            patch_state = '%s=%s' % (patch_id, self.release_data.metadata[patch_id]["state"])
            patch_state_args += ['-p', patch_state]

        # Run semantic checks, if any
        for patch_id in patch_list:
            semchk = os.path.join(constants.SEMANTICS_DIR, action, patch_id)

            if os.path.exists(semchk):
                try:
                    LOG.info("Running semantic check: %s", semchk)
                    subprocess.check_output([semchk] + patch_state_args,
                                            stderr=subprocess.STDOUT)
                    LOG.info("Semantic check %s passed", semchk)
                except subprocess.CalledProcessError as e:
                    msg = "Semantic check failed for %s:\n%s" % (patch_id, e.output)
                    LOG.exception(msg)
                    raise SoftwareFail(msg)

    def software_install_local_api(self):
        """
        Trigger patch installation prior to configuration
        :return: dict of info, warning and error messages
        """
        msg_info = ""
        msg_warning = ""
        msg_error = ""

        # Check to see if initial configuration has completed
        if os.path.isfile(INITIAL_CONTROLLER_CONFIG_COMPLETE):
            # Disallow the install
            msg = "This command can only be used before initial system configuration."
            LOG.exception(msg)
            raise SoftwareFail(msg)

        update_hosts_file = False

        # Check to see if the controller hostname is already known.
        if not utils.gethostbyname(constants.CONTROLLER_FLOATING_HOSTNAME):
            update_hosts_file = True

        # To allow software installation to occur before configuration, we need
        # to alias controller to localhost
        # There is a HOSTALIASES feature that would be preferred here, but it
        # unfortunately requires dnsmasq to be running, which it is not at this point.

        if update_hosts_file:
            # Make a backup of /etc/hosts
            try:
                shutil.copy2(ETC_HOSTS_FILE_PATH, ETC_HOSTS_BACKUP_FILE_PATH)
            except Exception:
                msg = f"Error occurred while copying {ETC_HOSTS_FILE_PATH}."
                LOG.exception(msg)
                raise SoftwareFail(msg)

        # Update /etc/hosts
        with open(ETC_HOSTS_FILE_PATH, 'a') as f:
            f.write("127.0.0.1 controller\n")

        # Run the software install
        try:
            # Use the restart option of the sw-patch init script, which will
            # install patches but won't automatically reboot if the RR flag is set
            subprocess.check_output(['/etc/init.d/sw-patch', 'restart'])
        except subprocess.CalledProcessError:
            msg = "Failed to install patches."
            LOG.exception(msg)
            raise SoftwareFail(msg)

        if update_hosts_file:
            # Restore /etc/hosts
            os.rename(ETC_HOSTS_BACKUP_FILE_PATH, ETC_HOSTS_FILE_PATH)

        for release in sorted(list(self.release_data.metadata)):
            if self.release_data.metadata[release]["state"] == constants.DEPLOYING_START:
                self.release_data.metadata[release]["state"] = constants.DEPLOYED
                try:
                    shutil.move("%s/%s-metadata.xml" % (constants.DEPLOYING_START_DIR, release),
                                "%s/%s-metadata.xml" % (constants.DEPLOYED_DIR, release))
                except shutil.Error:
                    msg = "Failed to move the metadata for %s" % release
                    LOG.exception(msg)
                    raise MetadataFail(msg)
            elif self.release_data.metadata[release]["state"] == constants.REMOVING:
                self.release_data.metadata[release]["state"] = constants.AVAILABLE
                try:
                    shutil.move("%s/%s-metadata.xml" % (constants.REMOVING_DIR, release),
                                "%s/%s-metadata.xml" % (constants.AVAILABLE_DIR, release))
                except shutil.Error:
                    msg = "Failed to move the metadata for %s" % release
                    LOG.exception(msg)
                    raise MetadataFail(msg)

        msg_info += "Software installation is complete.\n"
        msg_info += "Please reboot before continuing with configuration."

        return dict(info=msg_info, warning=msg_warning, error=msg_error)

    def major_release_upload_check(self):
        """
        major release upload semantic check
        """
        valid_controllers = ['controller-0']
        if socket.gethostname() not in valid_controllers:
            msg = f"Upload rejected, major release must be uploaded to {valid_controllers}"
            LOG.info(msg)
            raise SoftwareServiceError(error=msg)

        max_major_releases = 2
        major_releases = []
        for rel in self.release_collection.iterate_releases():
            major_rel = rel.sw_version
            if major_rel not in major_releases:
                major_releases.append(major_rel)

        if len(major_releases) >= max_major_releases:
            msg = f"Major releases {major_releases} have already been uploaded. " + \
                  f"Max major releases is {max_major_releases}"
            LOG.info(msg)
            raise SoftwareServiceError(error=msg)

    def _process_upload_upgrade_files(self, upgrade_files, release_data):
        """
        Process the uploaded upgrade files
        :param upgrade_files: dict of upgrade files
        :param release_data: ReleaseData object
        :return: info, warning, error messages
        """
        local_info = ""
        local_warning = ""
        local_error = ""
        release_meta_info = {}

        # validate this major release upload
        self.major_release_upload_check()

        to_release = None
        iso_mount_dir = None
        try:
            if not verify_files([upgrade_files[constants.ISO_EXTENSION]],
                                upgrade_files[constants.SIG_EXTENSION]):
                raise ReleaseValidationFailure("Invalid signature file")

            msg = ("iso and signature files upload completed\n"
                   "Importing iso is in progress\n")
            LOG.info(msg)
            local_info += msg

            iso_file = upgrade_files.get(constants.ISO_EXTENSION)

            # Mount the iso file after signature verification
            iso_mount_dir = mount_iso_load(iso_file, constants.TMP_DIR)
            LOG.info("Mounted iso file %s to %s", iso_file, iso_mount_dir)

            # Read the metadata from the iso file
            to_release, supported_from_releases = read_upgrade_support_versions(iso_mount_dir)
            LOG.info("Reading metadata from iso file %s completed", iso_file)
            # Validate that the current release is supported to upgrade to the new release
            supported_versions = [v.get("version") for v in supported_from_releases]
            if SW_VERSION not in supported_versions:
                raise UpgradeNotSupported("Current release %s not supported to upgrade to %s"
                                          % (SW_VERSION, to_release))

            # Copy iso /upgrades/software-deploy/ to /opt/software/rel-<rel>/bin/
            to_release_bin_dir = os.path.join(
                constants.SOFTWARE_STORAGE_DIR, ("rel-%s" % to_release), "bin")
            if os.path.exists(to_release_bin_dir):
                shutil.rmtree(to_release_bin_dir)
            shutil.copytree(os.path.join(iso_mount_dir, "upgrades",
                            constants.SOFTWARE_DEPLOY_FOLDER), to_release_bin_dir)

            # Run usm_load_import script
            LOG.info("Starting load import from %s", iso_file)
            import_script = os.path.join(to_release_bin_dir, 'usm_load_import')
            load_import_cmd = [import_script,
                               "--from-release=%s" % SW_VERSION,
                               "--to-release=%s" % to_release,
                               "--iso-dir=%s" % iso_mount_dir]
            LOG.info("Running load import command: %s", " ".join(load_import_cmd))
            load_import_return = subprocess.run(load_import_cmd,
                                                stdout=subprocess.PIPE,
                                                stderr=subprocess.STDOUT,
                                                check=True,
                                                text=True)
            if load_import_return.returncode != 0:
                local_error += load_import_return.stdout
            else:
                local_info += load_import_return.stdout

            # Copy metadata.xml to /opt/software/rel-<rel>/
            to_file = os.path.join(constants.SOFTWARE_STORAGE_DIR, ("rel-%s" % to_release), "metadata.xml")
            metadata_file = os.path.join(iso_mount_dir, "upgrades", "metadata.xml")
            shutil.copyfile(metadata_file, to_file)

            # Update the release metadata
            abs_stx_release_metadata_file = os.path.join(
                iso_mount_dir, 'upgrades', f"{constants.RELEASE_GA_NAME % to_release}-metadata.xml")
            release_data.parse_metadata(abs_stx_release_metadata_file, state=constants.AVAILABLE)
            LOG.info("Updated release metadata for %s", to_release)

            # Get release metadata
            all_release_meta_info = parse_release_metadata(abs_stx_release_metadata_file)
            release_meta_info = {
                os.path.basename(upgrade_files[constants.ISO_EXTENSION]): {
                    "id": all_release_meta_info.get("id"),
                    "sw_version": all_release_meta_info.get("sw_version"),
                },
                os.path.basename(upgrade_files[constants.SIG_EXTENSION]): {
                    "id": None,
                    "sw_version": None,
                }
            }

        except ReleaseValidationFailure:
            msg = "Upgrade file signature verification failed"
            LOG.exception(msg)
            local_error += msg + "\n"
        except Exception as e:
            msg = "Failed to process upgrade files. Error: %s" % str(e)
            LOG.exception(msg)
            local_error += msg + "\n"
            # delete versioned directory
            if to_release:
                to_release_dir = os.path.join(constants.SOFTWARE_STORAGE_DIR, "rel-%s" % to_release)
                shutil.rmtree(to_release_dir, ignore_errors=True)
        finally:
            # Unmount the iso file
            if iso_mount_dir:
                unmount_iso_load(iso_mount_dir)
                LOG.info("Unmounted iso file %s", iso_file)

        return local_info, local_warning, local_error, release_meta_info

    def _process_upload_patch_files(self, patch_files):
        """
        Process the uploaded patch files
        :param patch_files: list of patch files
        :return: info, warning, error messages
        """

        local_info = ""
        local_warning = ""
        local_error = ""
        upload_patch_info = []
        try:
            # Create the directories
            for state_dir in constants.DEPLOY_STATE_METADATA_DIR:
                os.makedirs(state_dir, exist_ok=True)
        except os.error:
            msg = "Failed to create directories"
            LOG.exception(msg)
            raise SoftwareFail(msg)

        for patch_file in patch_files:

            base_patch_filename = os.path.basename(patch_file)

            # Get the release_id from the filename
            # and check to see if it's already uploaded
            # todo(abailey) We should not require the ID as part of the file
            (release_id, _) = os.path.splitext(base_patch_filename)

            patch_metadata = self.release_data.metadata.get(release_id, None)

            if patch_metadata:
                if patch_metadata["state"] != constants.AVAILABLE:
                    msg = "%s is being or has already been deployed." % release_id
                    LOG.info(msg)
                    local_info += msg + "\n"
                elif patch_metadata["state"] == constants.COMMITTED:
                    msg = "%s is committed. Metadata not updated" % release_id
                    LOG.info(msg)
                    local_info += msg + "\n"
                else:
                    try:
                        # todo(abailey) PatchFile / extract_patch should be renamed
                        this_release = PatchFile.extract_patch(patch_file,
                                                               metadata_dir=constants.AVAILABLE_DIR,
                                                               metadata_only=True,
                                                               existing_content=self.release_data.contents[release_id],
                                                               base_pkgdata=self.base_pkgdata)
                        PatchFile.unpack_patch(patch_file)
                        self.release_data.update_release(this_release)
                        msg = "%s is already uploaded. Updated metadata only" % release_id
                        LOG.info(msg)
                        local_info += msg + "\n"
                    except ReleaseMismatchFailure:
                        msg = "Contents of %s do not match re-uploaded release" % release_id
                        LOG.exception(msg)
                        local_error += msg + "\n"
                    except ReleaseValidationFailure as e:
                        msg = "Release validation failed for %s" % release_id
                        if str(e) is not None and str(e) != '':
                            msg += ":\n%s" % str(e)
                        LOG.exception(msg)
                        local_error += msg + "\n"
                    except SoftwareFail:
                        msg = "Failed to upload release %s" % release_id
                        LOG.exception(msg)
                        local_error += msg + "\n"
            else:
                try:
                    this_release = PatchFile.extract_patch(patch_file,
                                                           metadata_dir=constants.AVAILABLE_DIR,
                                                           base_pkgdata=self.base_pkgdata)
                    PatchFile.unpack_patch(patch_file)
                    local_info += "%s is now uploaded\n" % release_id
                    self.release_data.add_release(this_release)

                    if not os.path.isfile(INITIAL_CONTROLLER_CONFIG_COMPLETE):
                        self.release_data.metadata[release_id]["state"] = constants.AVAILABLE
                    elif len(self.hosts) > 0:
                        self.release_data.metadata[release_id]["state"] = constants.AVAILABLE
                    else:
                        self.release_data.metadata[release_id]["state"] = constants.UNKNOWN
                except ReleaseValidationFailure as e:
                    msg = "Release validation failed for %s" % release_id
                    if str(e) is not None and str(e) != '':
                        msg += ":\n%s" % str(e)
                    LOG.exception(msg)
                    local_error += msg + "\n"
                    continue
                except SoftwareFail:
                    msg = "Failed to upload release %s" % release_id
                    LOG.exception(msg)
                    local_error += msg + "\n"
                    continue

            upload_patch_info.append({
                base_patch_filename: {
                    "id": release_id,
                    "sw_version": self.release_data.metadata[release_id].get("sw_version", None),
                }
            })

        # create versioned precheck for uploaded patches
        for patch in upload_patch_info:
            filename, values = list(patch.items())[0]
            LOG.info("Creating precheck for release %s..." % values.get("id"))
            for pf in patch_files:
                if filename in pf:
                    patch_file = pf

            sw_version = values.get("sw_version")
            required_patches = self.release_data.metadata[values.get("id")].get("requires")

            # sort the required patches list and get the latest, if available
            req_patch_id = None
            req_patch_metadata = None
            req_patch_version = None
            if required_patches:
                req_patch_id = sorted(required_patches)[-1]
            if req_patch_id:
                req_patch_metadata = self.release_data.metadata.get(req_patch_id)
            if req_patch_metadata:
                req_patch_version = req_patch_metadata.get("sw_version")
            if req_patch_id and not req_patch_metadata:
                LOG.warning("Required patch '%s' is not uploaded." % req_patch_id)

            PatchFile.create_versioned_precheck(patch_file, sw_version, req_patch_version=req_patch_version)

        return local_info, local_warning, local_error, upload_patch_info

    def software_release_upload(self, release_files):
        """
        Upload software release files
        :return: dict of info, warning and error messages
        """
        msg_info = ""
        msg_warning = ""
        msg_error = ""

        upload_info = []

        # Refresh data, if needed
        self.base_pkgdata.loaddirs()

        msg = "Uploading files: %s" % ",".join(release_files)
        audit_log_info(msg)

        # We now need to put the files in the category (patch or upgrade)
        patch_files = []
        upgrade_files = {}

        for uploaded_file in release_files:
            (_, ext) = os.path.splitext(uploaded_file)
            if ext in [constants.PATCH_EXTENSION]:
                patch_files.append(uploaded_file)
            elif ext == constants.ISO_EXTENSION:
                upgrade_files[constants.ISO_EXTENSION] = uploaded_file
            elif ext == constants.SIG_EXTENSION:
                upgrade_files[constants.SIG_EXTENSION] = uploaded_file
            else:
                LOG.exception(
                    "The file extension is not supported. Supported extensions include .patch, .iso and .sig")

        if len(upgrade_files) == 1:  # Only one upgrade file uploaded
            msg = "Missing upgrade file or signature file"
            LOG.error(msg)
            msg_error += msg + "\n"
        elif len(upgrade_files) == 2:  # Two upgrade files uploaded
            tmp_info, tmp_warning, tmp_error, tmp_release_meta_info = self._process_upload_upgrade_files(
                upgrade_files, self.release_data)
            msg_info += tmp_info
            msg_warning += tmp_warning
            msg_error += tmp_error
            upload_info.append(tmp_release_meta_info)

        if len(patch_files) > 0:
            tmp_info, tmp_warning, tmp_error, tmp_patch_meta_info = self._process_upload_patch_files(
                patch_files)
            msg_info += tmp_info
            msg_warning += tmp_warning
            msg_error += tmp_error
            upload_info += tmp_patch_meta_info

        return dict(info=msg_info, warning=msg_warning, error=msg_error, upload_info=upload_info)

    def release_apply_remove_order(self, release, running_sw_version, reverse=False):

        # If R4 requires R3, R3 requires R2 and R2 requires R1,
        # then release_order = ['R4', 'R3', 'R2', 'R1']

        if reverse:
            release_order = [release] + self.get_release_dependency_list(release)
            # If release_order = ['R4', 'R3', 'R2', 'R1']
            # and running_sw_version is the sw_version for R2
            # After the operation below, release_order = ['R4', 'R3']
            for i, rel in enumerate(release_order):
                if self.release_data.metadata[rel]["sw_version"] == running_sw_version:
                    val = i - len(release_order) + 1
                    while val >= 0:
                        release_order.pop()
                        val = val - 1
                    break

        else:
            release_order = [release] + self.get_release_required_by_list(release)
        # reverse = True is for apply operation
        # In this case, the release_order = ['R3', 'R4']
        # reverse = False is for remove operation
        # In this case, the release_order = ['R3']
        if reverse:
            release_order.reverse()
        else:
            release_order.pop(0)
        return release_order

    def software_release_delete_api(self, release_ids):
        """
        Delete release(s)
        :return: dict of info, warning and error messages
        """
        msg_info = ""
        msg_warning = ""
        msg_error = ""

        # Protect against duplications
        full_list = sorted(list(set(release_ids)))

        not_founds = []
        cannot_del = []
        used_by_subcloud = []
        release_list = []
        for rel_id in full_list:
            rel = self.release_collection.get_release_by_id(rel_id)
            if rel is None:
                not_founds.append(rel_id)
            else:
                if not rel.is_deletable:
                    cannot_del.append(rel_id)
                elif rel.is_ga_release and is_system_controller():
                    subcloud_by_sw_version = get_subcloud_groupby_version()
                    if rel.sw_version in subcloud_by_sw_version:
                        used_by_subcloud.append(rel_id)
                    else:
                        release_list.append(rel_id)
                else:
                    release_list.append(rel_id)

        err_msg = ""
        if len(not_founds) > 0:
            list_str = ','.join(not_founds)
            err_msg = f"Releases {list_str} can not be found\n"

        if len(cannot_del) > 0:
            list_str = ','.join(cannot_del)
            err_msg = err_msg + f"Releases {list_str} are not ready to delete\n"

        if len(used_by_subcloud) > 0:
            list_str = ','.join(used_by_subcloud)
            err_msg = err_msg + f"Releases {list_str} are still used by subcloud(s)"

        if len(err_msg) > 0:
            raise SoftwareServiceError(error=err_msg)

        msg = "Deleting releases: %s" % ",".join(release_list)
        LOG.info(msg)
        audit_log_info(msg)

        # Verify releases exist and are in proper state first
        id_verification = all(release_id in self.release_data.metadata for release_id in release_list)
        for release_id in release_list:
            if release_id not in self.release_data.metadata:
                msg = "Release %s does not exist" % release_id
                LOG.error(msg)
                msg_error += msg + "\n"
                id_verification = False
                continue

            deploystate = self.release_data.metadata[release_id]["state"]
            ignore_states = [constants.AVAILABLE,
                             constants.DEPLOYING_START,
                             constants.DEPLOYING_ACTIVATE,
                             constants.DEPLOYING_COMPLETE,
                             constants.DEPLOYING_HOST,
                             constants.DEPLOYED]

            if deploystate not in ignore_states:
                msg = f"Release {release_id} is {deploystate} and cannot be deleted."
                LOG.error(msg)
                msg_error += msg + "\n"
                id_verification = False
                continue

        if not id_verification:
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # Handle operation
        for release_id in release_list:
            release_sw_version = utils.get_major_release_version(
                self.release_data.metadata[release_id]["sw_version"])

            # Need to support delete of older centos patches (metadata) from upgrades.
            # todo(abailey): do we need to be concerned about this since this component is new.

            # Delete ostree content if it exists.
            # RPM based patches (from upgrades) will not have ostree contents
            ostree_tar_filename = self.get_ostree_tar_filename(release_sw_version, release_id)
            if os.path.isfile(ostree_tar_filename):
                try:
                    os.remove(ostree_tar_filename)
                except OSError:
                    msg = "Failed to remove ostree tarball %s" % ostree_tar_filename
                    LOG.exception(msg)
                    raise OSTreeTarFail(msg)

            package_repo_dir = "%s/rel-%s" % (constants.PACKAGE_FEED_DIR, release_sw_version)
            packages = [pkg.split("_")[0] for pkg in self.release_data.metadata[release_id].get("packages")]
            if packages:
                apt_utils.package_remove(package_repo_dir, packages)

            # Delete upgrade iso file in folder
            # TODO(heitormatsui): treat the prepatched iso scenario
            metadata_file = "%s-metadata.xml" % release_id
            delete_feed = False
            to_release_iso_dir = os.path.join(constants.FEED_OSTREE_BASE_DIR, ("rel-%s" % release_sw_version))
            if os.path.isdir(to_release_iso_dir):
                # check if the release being deleted is related to this feed
                if os.path.isfile("%s/upgrades/%s" % (to_release_iso_dir, metadata_file)):
                    delete_feed = True
                if delete_feed:
                    try:
                        shutil.rmtree(to_release_iso_dir)
                    except OSError:
                        msg = "Failed to remove release iso %s folder" % to_release_iso_dir
                        LOG.exception(msg)
                        raise ReleaseIsoDeleteFailure(msg)
                    msg = "Deleted feed directory %s" % to_release_iso_dir
                    LOG.info(msg)
                    msg_info += msg + "\n"

            # TODO(lbonatti): treat the upcoming versioning changes
            PatchFile.delete_versioned_directory(self.release_data.metadata[release_id]["sw_version"])

            try:
                # Delete the metadata
                deploystate = self.release_data.metadata[release_id]["state"]
                metadata_dir = DEPLOY_STATE_METADATA_DIR_DICT[deploystate]
                os.remove("%s/%s" % (metadata_dir, metadata_file))
            except OSError:
                msg = "Failed to remove metadata for %s" % release_id
                LOG.exception(msg)
                raise MetadataFail(msg)

            self.delete_restart_script(release_id)
            self.release_data.delete_release(release_id)
            msg = "%s has been deleted" % release_id
            LOG.info(msg)
            msg_info += msg + "\n"

        # Refresh data, if needed
        self.base_pkgdata.loaddirs()

        return dict(info=msg_info, warning=msg_warning, error=msg_error)

    def in_sync_controller_api(self):
        """
        Check if both controllers are in sync
        by checking the database JSON file
        """
        is_in_sync = False

        does_synced_software_exist = os.path.isfile(constants.SYNCED_SOFTWARE_JSON_FILE)
        does_software_exist = os.path.isfile(constants.SOFTWARE_JSON_FILE)

        if does_synced_software_exist and does_software_exist:
            # both files exist, compare them
            with open(constants.SYNCED_SOFTWARE_JSON_FILE, 'r') as f:
                synced_software = json.load(f)
            with open(constants.SOFTWARE_JSON_FILE, 'r') as f:
                software = json.load(f)
            LOG.debug("Synced software: %s", synced_software)
            LOG.debug("Software: %s", software)

            is_in_sync = synced_software == software
        elif not does_synced_software_exist and not does_software_exist:
            # neither file exists, it is not in deploying state
            is_in_sync = True
        else:
            # either file does not exist, it is in deploying state
            is_in_sync = False

        return {"in_sync": is_in_sync}

    def patch_init_release_api(self, release):
        """
        Create an empty repo for a new release
        :return: dict of info, warning and error messages
        """
        msg_info = ""
        msg_warning = ""
        msg_error = ""

        msg = "Initializing repo for: %s" % release
        LOG.info(msg)
        audit_log_info(msg)

        if release == SW_VERSION:
            msg = "Rejected: Requested release %s is running release" % release
            msg_error += msg + "\n"
            LOG.info(msg)
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # Refresh data
        self.base_pkgdata.loaddirs()

        self.release_data.load_all_metadata(constants.AVAILABLE_DIR, state=constants.AVAILABLE)
        self.release_data.load_all_metadata(constants.UNAVAILABLE_DIR, state=constants.UNAVAILABLE)
        self.release_data.load_all_metadata(constants.DEPLOYING_START_DIR, state=constants.DEPLOYING_START)
        self.release_data.load_all_metadata(constants.DEPLOYING_HOST_DIR, state=constants.DEPLOYING_HOST)
        self.release_data.load_all_metadata(constants.DEPLOYING_ACTIVATE_DIR, state=constants.DEPLOYING_ACTIVATE)
        self.release_data.load_all_metadata(constants.DEPLOYING_COMPLETE_DIR, state=constants.DEPLOYING_COMPLETE)
        self.release_data.load_all_metadata(constants.DEPLOYED_DIR, state=constants.DEPLOYED)
        self.release_data.load_all_metadata(constants.REMOVING_DIR, state=constants.REMOVING)
        self.release_data.load_all_metadata(constants.ABORTING_DIR, state=constants.ABORTING)
        self.release_data.load_all_metadata(constants.COMMITTED_DIR, state=constants.COMMITTED)

        repo_dir[release] = "%s/rel-%s" % (repo_root_dir, release)

        # Verify the release doesn't already exist
        if os.path.exists(repo_dir[release]):
            msg = "Patch repository for %s already exists" % release
            msg_info += msg + "\n"
            LOG.info(msg)
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # Create the repo
        try:
            # todo(jcasteli)  determine if ostree change needs a createrepo equivalent
            output = "UNDER CONSTRUCTION for OSTREE"
            LOG.info("Repo[%s] updated:\n%s", release, output)
        except Exception:
            msg = "Failed to update the repo for %s" % release
            LOG.exception(msg)

            # Wipe out what was created
            shutil.rmtree(repo_dir[release])
            del repo_dir[release]

            raise SoftwareFail(msg)

        return dict(info=msg_info, warning=msg_warning, error=msg_error)

    def patch_query_what_requires(self, patch_ids):
        """
        Query the known patches to see which have dependencies on the specified patches
        :return: dict of info, warning and error messages
        """
        msg_info = ""
        msg_warning = ""
        msg_error = ""

        msg = "Querying what requires patches: %s" % ",".join(patch_ids)
        LOG.info(msg)
        audit_log_info(msg)

        # First, verify that all specified patches exist
        id_verification = True
        for patch_id in patch_ids:
            if patch_id not in self.release_data.metadata:
                msg = "Patch %s does not exist" % patch_id
                LOG.error(msg)
                msg_error += msg + "\n"
                id_verification = False

        if not id_verification:
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        required_patches = {}
        for patch_iter in list(self.release_data.metadata):
            for req_patch in self.release_data.metadata[patch_iter]["requires"]:
                if req_patch not in patch_ids:
                    continue

                if req_patch not in required_patches:
                    required_patches[req_patch] = []

                required_patches[req_patch].append(patch_iter)

        for patch_id in patch_ids:
            if patch_id in required_patches:
                iter_patch_list = required_patches[patch_id]
                msg_info += "%s is required by: %s\n" % (patch_id, ", ".join(sorted(iter_patch_list)))
            else:
                msg_info += "%s is not required by any patches.\n" % patch_id

        return dict(info=msg_info, warning=msg_warning, error=msg_error)

    def send_latest_feed_commit_to_agent(self):
        """
        Notify the patch agent that the latest commit on the feed
        repo has been updated
        """
        # Skip sending messages if host not yet provisioned
        if self.sock_out is None:
            LOG.info("Skipping send feed commit to agent")
            return

        send_commit_to_agent = PatchMessageSendLatestFeedCommit()
        self.socket_lock.acquire()
        send_commit_to_agent.send(self.sock_out)
        self.socket_lock.release()

    def software_sync(self):
        # Increment the software_op_counter here
        self.inc_patch_op_counter()

        self.release_data_lock.acquire()
        # self.release_data.load_all()
        self.check_patch_states()
        self.release_data_lock.release()

        if self.sock_out is None:
            return True

        # Send the sync requests

        self.controller_neighbours_lock.acquire()
        for n in self.controller_neighbours:
            self.controller_neighbours[n].clear_synced()
        self.controller_neighbours_lock.release()

        msg = PatchMessageSyncReq()
        self.socket_lock.acquire()
        msg.send(self.sock_out)
        self.socket_lock.release()

        # Now we wait, up to two mins. future enhancement: Wait on a condition
        my_ip = cfg.get_mgmt_ip()
        sync_rc = False
        max_time = time.time() + 120
        while time.time() < max_time:
            all_done = True
            self.controller_neighbours_lock.acquire()
            for n in self.controller_neighbours:
                if n != my_ip and not self.controller_neighbours[n].get_synced():
                    all_done = False
            self.controller_neighbours_lock.release()

            if all_done:
                LOG.info("Sync complete")
                sync_rc = True
                break

            time.sleep(0.5)

        # Send hellos to the hosts now, to get queries performed
        hello_agent = PatchMessageHelloAgent()
        self.socket_lock.acquire()
        hello_agent.send(self.sock_out)
        self.socket_lock.release()

        if not sync_rc:
            LOG.info("Timed out waiting for sync completion")
        return sync_rc

    def software_release_query_cached(self, **kwargs):
        query_state = None
        if "show" in kwargs:
            if kwargs["show"] == "available":
                query_state = constants.AVAILABLE
            if kwargs["show"] == "unavailable":
                query_state = constants.UNAVAILABLE
            elif kwargs["show"] == "deploying_start":
                query_state = constants.DEPLOYING_START
            elif kwargs["show"] == "deploying_host":
                query_state = constants.DEPLOYING_HOST
            elif kwargs["show"] == "deploying_activate":
                query_state = constants.DEPLOYING_ACTIVATE
            elif kwargs["show"] == "deploying_complete":
                query_state = constants.DEPLOYING_COMPLETE
            elif kwargs["show"] == "deployed":
                query_state = constants.DEPLOYED
            elif kwargs["show"] == "removing":
                query_state = constants.REMOVING
            elif kwargs["show"] == "aborting":
                query_state = constants.ABORTING
            elif kwargs["show"] == "committed":
                query_state = constants.COMMITTED

        query_release = None
        if "release" in kwargs:
            query_release = kwargs["release"]

        results = {}
        self.release_data_lock.acquire()
        if query_state is None and query_release is None:
            # Return everything
            results = self.release_data.metadata
        else:
            # Filter results
            for release_id, data in self.release_data.metadata.items():
                if query_state is not None and data["state"] != query_state:
                    continue
                if query_release is not None and data["sw_version"] != query_release:
                    continue
                results[release_id] = data
        self.release_data_lock.release()

        return results

    def software_release_query_specific_cached(self, release_ids):
        audit_log_info("software release show")

        results = {"metadata": {},
                   "contents": {},
                   "error": ""}

        with self.release_data_lock:

            for release_id in release_ids:
                if release_id not in list(self.release_data.metadata):
                    results["error"] += "%s is unrecognized\n" % release_id

            for release_id, data in self.release_data.metadata.items():
                if release_id in release_ids:
                    results["metadata"][release_id] = data
            for release_id, data in self.release_data.contents.items():
                if release_id in release_ids:
                    results["contents"][release_id] = data

        return results

    def get_dependencies(self, patch_ids, recursive):
        dependencies = set()
        patch_added = False

        with self.release_data_lock:

            # Add patches to workset
            for patch_id in sorted(patch_ids):
                dependencies.add(patch_id)
                patch_added = True

            while patch_added:
                patch_added = False
                for patch_id in sorted(dependencies):
                    for req in self.release_data.metadata[patch_id]["requires"]:
                        if req not in dependencies:
                            dependencies.add(req)
                            patch_added = recursive

        return sorted(dependencies)

    def patch_query_dependencies(self, patch_ids, **kwargs):
        msg = "Patch query-dependencies %s" % patch_ids
        LOG.info(msg)
        audit_log_info(msg)

        failure = False

        results = {"patches": [],
                   "error": ""}

        recursive = False
        if kwargs.get("recursive") == "yes":
            recursive = True

        with self.release_data_lock:

            # Verify patch IDs
            for patch_id in sorted(patch_ids):
                if patch_id not in list(self.release_data.metadata):
                    errormsg = "%s is unrecognized\n" % patch_id
                    LOG.info("patch_query_dependencies: %s", errormsg)
                    results["error"] += errormsg
                    failure = True

        if failure:
            LOG.info("patch_query_dependencies failed")
            return results

        results["patches"] = self.get_dependencies(patch_ids, recursive)

        return results

    def patch_commit(self, patch_ids, dry_run=False):
        msg = "Patch commit %s" % patch_ids
        LOG.info(msg)
        audit_log_info(msg)

        try:
            if not os.path.exists(constants.COMMITTED_DIR):
                os.makedirs(constants.COMMITTED_DIR)
        except os.error:
            msg = "Failed to create %s" % constants.COMMITTED_DIR
            LOG.exception(msg)
            raise SoftwareFail(msg)

        failure = False
        recursive = True
        cleanup_files = set()
        results = {"info": "",
                   "error": ""}

        # Ensure there are only REL patches
        non_rel_list = []
        with self.release_data_lock:
            for patch_id in self.release_data.metadata:
                if self.release_data.metadata[patch_id]['status'] != constants.STATUS_RELEASED:
                    non_rel_list.append(patch_id)

        if len(non_rel_list) > 0:
            errormsg = "A commit cannot be performed with non-REL status patches in the system:\n"
            for patch_id in non_rel_list:
                errormsg += "    %s\n" % patch_id
            LOG.info("patch_commit rejected: %s", errormsg)
            results["error"] += errormsg
            return results

        # Verify Release IDs
        with self.release_data_lock:
            for patch_id in sorted(patch_ids):
                if patch_id not in list(self.release_data.metadata):
                    errormsg = "%s is unrecognized\n" % patch_id
                    LOG.info("patch_commit: %s", errormsg)
                    results["error"] += errormsg
                    failure = True

        if failure:
            LOG.info("patch_commit: Failed patch ID check")
            return results

        commit_list = self.get_dependencies(patch_ids, recursive)

        # Check patch states
        avail_list = []
        with self.release_data_lock:
            for patch_id in commit_list:
                if self.release_data.metadata[patch_id]['state'] != constants.DEPLOYED \
                        and self.release_data.metadata[patch_id]['state'] != constants.COMMITTED:
                    avail_list.append(patch_id)

        if len(avail_list) > 0:
            errormsg = "The following patches are not applied and cannot be committed:\n"
            for patch_id in avail_list:
                errormsg += "    %s\n" % patch_id
            LOG.info("patch_commit rejected: %s", errormsg)
            results["error"] += errormsg
            return results

        with self.release_data_lock:
            for patch_id in commit_list:
                # Fetch file paths that need to be cleaned up to
                # free patch storage disk space
                if self.release_data.metadata[patch_id].get("restart_script"):
                    restart_script_path = "%s/%s" % \
                        (root_scripts_dir,
                         self.release_data.metadata[patch_id]["restart_script"])
                    if os.path.exists(restart_script_path):
                        cleanup_files.add(restart_script_path)
                patch_sw_version = utils.get_major_release_version(
                    self.release_data.metadata[patch_id]["sw_version"])
                abs_ostree_tar_dir = package_dir[patch_sw_version]
                software_tar_path = "%s/%s-software.tar" % (abs_ostree_tar_dir, patch_id)
                if os.path.exists(software_tar_path):
                    cleanup_files.add(software_tar_path)

        # Calculate disk space
        disk_space = 0
        for file in cleanup_files:
            statinfo = os.stat(file)
            disk_space += statinfo.st_size

        if dry_run:
            results["info"] = "This commit operation would free %0.2f MiB" % (disk_space / (1024.0 * 1024.0))
            return results

        # Do the commit

        # Move the metadata to the committed dir
        for patch_id in commit_list:
            metadata_fname = "%s-metadata.xml" % patch_id
            deployed_fname = os.path.join(constants.DEPLOYED_DIR, metadata_fname)
            committed_fname = os.path.join(constants.COMMITTED_DIR, metadata_fname)
            if os.path.exists(deployed_fname):
                try:
                    shutil.move(deployed_fname, committed_fname)
                except shutil.Error:
                    msg = "Failed to move the metadata for %s" % patch_id
                    LOG.exception(msg)
                    raise MetadataFail(msg)

        # Delete the files
        for file in cleanup_files:
            try:
                os.remove(file)
            except OSError:
                msg = "Failed to remove: %s" % file
                LOG.exception(msg)
                raise MetadataFail(msg)

        self.release_data.load_all()

        results["info"] = "The releases have been committed."
        return results

    def query_host_cache(self):
        output = []

        self.hosts_lock.acquire()
        for nbr in list(self.hosts):
            host = self.hosts[nbr].get_dict()
            host["interim_state"] = False
            for patch_id in list(sc.interim_state):
                if nbr in sc.interim_state[patch_id]:
                    host["interim_state"] = True

            output.append(host)

        self.hosts_lock.release()

        return output

    def any_patch_host_installing(self):
        rc = False

        with self.hosts_lock:
            for host in self.hosts.values():
                if host.state == constants.PATCH_AGENT_STATE_INSTALLING:
                    rc = True
                    break
        return rc

    def copy_restart_scripts(self):
        with self.release_data_lock:
            for patch_id in self.release_data.metadata:
                if self.release_data.metadata[patch_id]["state"] in \
                   [constants.DEPLOYING_START, constants.REMOVING] \
                   and self.release_data.metadata[patch_id].get("restart_script"):
                    try:
                        restart_script_name = self.release_data.metadata[patch_id]["restart_script"]
                        restart_script_path = "%s/%s" \
                            % (root_scripts_dir, restart_script_name)
                        dest_path = constants.PATCH_SCRIPTS_STAGING_DIR
                        dest_script_file = "%s/%s" \
                            % (constants.PATCH_SCRIPTS_STAGING_DIR, restart_script_name)
                        if not os.path.exists(dest_path):
                            os.makedirs(dest_path, 0o700)
                        shutil.copyfile(restart_script_path, dest_script_file)
                        os.chmod(dest_script_file, 0o700)
                        msg = "Creating restart script for %s" % patch_id
                        LOG.info(msg)
                    except shutil.Error:
                        msg = "Failed to copy the restart script for %s" % patch_id
                        LOG.exception(msg)
                        raise SoftwareError(msg)
                elif self.release_data.metadata[patch_id].get("restart_script"):
                    try:
                        restart_script_name = self.release_data.metadata[patch_id]["restart_script"]
                        restart_script_path = "%s/%s" \
                            % (constants.PATCH_SCRIPTS_STAGING_DIR, restart_script_name)
                        if os.path.exists(restart_script_path):
                            os.remove(restart_script_path)
                            msg = "Removing restart script for %s" % patch_id
                            LOG.info(msg)
                    except shutil.Error:
                        msg = "Failed to delete the restart script for %s" % patch_id
                        LOG.exception(msg)

    def _update_state_to_peer(self):
        state_update_msg = SoftwareMessageDeployStateUpdate()
        self.socket_lock.acquire()
        try:
            state_update_msg.send(self.sock_out)
        finally:
            self.socket_lock.release()

    def _release_basic_checks(self, deployment):
        """
        Does basic sanity checks on the release data
        :param deployment: release to be checked
        :return: release dict (if exists),
                 bool with success output,
                 strings with info, warning and error messages
        """
        msg_info = ""
        msg_warning = ""
        msg_error = ""
        success = True

        # We need to verify that the software release exists
        release = self.release_data.metadata.get(deployment, None)
        if not release:
            msg = "Software release version corresponding to the specified release " \
                  "%s does not exist." % deployment
            LOG.error(msg)
            msg_error += msg + " Try deleting and re-uploading the software for recovery."
            success = False

        # Check if release state is valid
        elif release["state"] not in constants.VALID_DEPLOY_START_STATES:
            msg = "Software release state is invalid: %s" % release["state"]
            LOG.error(msg)
            msg_error += msg
            success = False

        return release, success, msg_info, msg_warning, msg_error

    def _deploy_precheck(self, release_version: str, force: bool = False,
                         region_name: str = "RegionOne", patch: bool = False) -> dict:
        """
        Verify if system satisfy the requisites to upgrade to a specified deployment.
        :param release_version: full release name, e.g. starlingx-MM.mm.pp
        :param force: if True will ignore minor alarms during precheck
        :param region_name: region_name
        :param patch: if True then indicate precheck is for patch release
        :return: dict of info, warning and error messages
        """

        msg_info = ""
        msg_warning = ""
        msg_error = ""

        precheck_script = utils.get_precheck_script(release_version)

        if not os.path.isfile(precheck_script):
            msg = "Release files for deployment %s are not present on the system, " \
                  "cannot proceed with the precheck." % release_version
            LOG.error(msg)
            msg_error = "Fail to perform deploy precheck. " \
                        "Uploaded release may have been damaged. " \
                        "Try delete and re-upload the release.\n"
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # parse local config file to pass parameters to precheck script
        try:
            cp = configparser.ConfigParser()
            cp.read(constants.SOFTWARE_CONFIG_FILE_LOCAL)
            ks_section = cp["keystone_authtoken"]
            auth_url = ks_section["auth_url"]
            username = ks_section["username"]
            password = ks_section["password"]
            project_name = ks_section["project_name"]
            user_domain_name = ks_section["user_domain_name"]
            project_domain_name = ks_section["project_domain_name"]
        except Exception as e:
            msg = "Error parsing config file: %s." % str(e)
            LOG.error(msg)
            msg_error = "Fail to perform deploy precheck. Internal error has occured." \
                        "Try lock and unlock the controller for recovery.\n"
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # TODO(heitormatsui) if different region was passed as parameter then
        #  need to discover the subcloud auth_url to pass to precheck script
        if region_name != "RegionOne":
            pass

        cmd = [precheck_script,
               "--auth_url=%s" % auth_url,
               "--username=%s" % username,
               "--password=%s" % password,
               "--project_name=%s" % project_name,
               "--user_domain_name=%s" % user_domain_name,
               "--project_domain_name=%s" % project_domain_name,
               "--region_name=%s" % region_name]
        if force:
            cmd.append("--force")
        if patch:
            cmd.append("--patch")

        # Call precheck from the deployment files
        precheck_return = subprocess.run(
            cmd,
            stderr=subprocess.STDOUT,
            stdout=subprocess.PIPE,
            check=False,
            text=True,
        )
        system_healthy = None
        if precheck_return.returncode in [constants.RC_SUCCESS, constants.RC_UNHEALTHY]:
            system_healthy = precheck_return.returncode == constants.RC_SUCCESS
            msg_info += precheck_return.stdout
        else:
            msg_error += precheck_return.stdout

        return dict(info=msg_info, warning=msg_warning, error=msg_error, system_healthy=system_healthy)

    def software_deploy_precheck_api(self, deployment: str, force: bool = False, **kwargs) -> dict:
        """
        Verify if system satisfy the requisites to upgrade to a specified deployment.
        :param deployment: full release name, e.g. starlingx-MM.mm.pp
        :param force: if True will ignore minor alarms during precheck
        :return: dict of info, warning and error messages
        """
        release, success, msg_info, msg_warning, msg_error = self._release_basic_checks(deployment)
        if not success:
            return dict(info=msg_info, warning=msg_warning, error=msg_error)
        region_name = kwargs["region_name"]
        release_version = release["sw_version"]
        patch = not utils.is_upgrade_deploy(SW_VERSION, release_version)
        return self._deploy_precheck(release_version, force, region_name, patch)

    def _deploy_upgrade_start(self, to_release):
        LOG.info("start deploy upgrade to %s from %s" % (to_release, SW_VERSION))
        deploy_script_name = constants.DEPLOY_START_SCRIPT
        cmd_path = utils.get_software_deploy_script(to_release, deploy_script_name)
        if not os.path.isfile(cmd_path):
            msg = f"{deploy_script_name} was not found"
            LOG.error(msg)
            raise SoftwareServiceError(f"{deploy_script_name} was not found. "
                                       "The uploaded software could have been damaged. "
                                       "Please delete the software and re-upload it")
        major_to_release = utils.get_major_release_version(to_release)
        k8s_ver = get_k8s_ver()
        postgresql_port = str(cfg.alt_postgresql_port)
        feed = os.path.join(constants.FEED_DIR,
                            "rel-%s/ostree_repo" % major_to_release)
        commit_id = None

        LOG.info("k8s version %s" % k8s_ver)
        upgrade_start_cmd = [cmd_path, SW_VERSION, major_to_release, k8s_ver, postgresql_port,
                             feed]
        if commit_id is not None:
            upgrade_start_cmd.append(commit_id)
        # pass in keystone auth through environment variables
        # OS_AUTH_URL, OS_USERNAME, OS_PASSWORD, OS_PROJECT_NAME, OS_USER_DOMAIN_NAME,
        # OS_PROJECT_DOMAIN_NAME, OS_REGION_NAME are in env variables.
        keystone_auth = CONF.get('keystone_authtoken')
        env = {}
        env["OS_AUTH_URL"] = keystone_auth["auth_url"] + '/v3'
        env["OS_USERNAME"] = keystone_auth["username"]
        env["OS_PASSWORD"] = keystone_auth["password"]
        env["OS_PROJECT_NAME"] = keystone_auth["project_name"]
        env["OS_USER_DOMAIN_NAME"] = keystone_auth["user_domain_name"]
        env["OS_PROJECT_DOMAIN_NAME"] = keystone_auth["project_domain_name"]
        env["OS_REGION_NAME"] = keystone_auth["region_name"]

        try:
            LOG.info("starting subprocess %s" % ' '.join(upgrade_start_cmd))
            subprocess.Popen(' '.join(upgrade_start_cmd), start_new_session=True, shell=True, env=env)
            LOG.info("subprocess started")
            return True
        except subprocess.SubprocessError as e:
            LOG.error("Failed to start command: %s. Error %s" % (' '.join(upgrade_start_cmd), e))
            return False

    def deploy_state_changed(self, deploy_state):
        '''Handle 'deploy state change' event, invoked when operations complete. '''
        self.db_api_instance.update_deploy(deploy_state)

    def host_deploy_state_changed(self, hostname, host_deploy_state):
        '''Handle 'host deploy state change' event. '''
        self.db_api_instance.update_deploy_host(hostname, host_deploy_state)

    def add_text_tag_to_xml(self, parent, name, text):
        tag = ET.SubElement(parent, name)
        tag.text = text
        return tag

    def software_deploy_start_api(self, deployment: str, force: bool, **kwargs) -> dict:
        """
        Start deployment by applying the changes to the feed ostree
        return: dict of info, warning and error messages
        """
        release, success, msg_info, msg_warning, msg_error = self._release_basic_checks(deployment)

        if not success:
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # TODO(heitormatsui) Enforce deploy-precheck for patch release
        patch_release = True
        if utils.is_upgrade_deploy(SW_VERSION, release["sw_version"]):
            patch_release = False
            to_release = release["sw_version"]
            ret = self._deploy_precheck(to_release, force, patch=patch_release)
            if ret["system_healthy"] is None:
                ret["error"] = "Fail to perform deploy precheck. Internal error has occurred.\n" + \
                               ret["error"]
                return ret
            elif not ret["system_healthy"]:
                ret["info"] = "The following issues have been detected, which prevent " \
                               "deploying %s\n" % deployment + ret["info"] + \
                               "Please fix above issues then retry the deploy.\n"
                return ret

            if self._deploy_upgrade_start(to_release):
                collect_current_load_for_hosts()
                create_deploy_hosts()
                self.db_api_instance.begin_update()
                try:
                    self.update_and_sync_deploy_state(self.db_api_instance.create_deploy,
                                                      SW_VERSION, to_release, True)
                    self.update_and_sync_deploy_state(self.db_api_instance.update_deploy,
                                                      DEPLOY_STATES.START)
                finally:
                    self.db_api_instance.end_update()

                sw_rel = self.release_collection.get_release_by_id(deployment)
                if sw_rel is None:
                    raise InternalError("%s cannot be found" % to_release)
                sw_rel.update_state(constants.DEPLOYING)
                msg_info = "Deployment for %s started" % deployment
            else:
                msg_error = "Deployment for %s failed to start" % deployment

            return dict(info=msg_info, warning=msg_warning, error=msg_error)
        # Identify if this is apply or remove operation
        # todo(jcasteli) Remove once the logic to include major release version
        # in release list is implemented
        running_sw_version = "23.09.0"

        # todo(chuck) Remove once to determine how we are associating a patch
        # with a release.
        # release in release metadata.xml file represents the latest commit
        # for release_id in sorted(list(self.release_data.metadata)):
        #    if SW_VERSION == self.release_data.contents[release_id]["release"]:
        #        running_sw_version = self.release_data.metadata[release_id]["sw_version"]
        #        LOG.info("Running software version: %s", running_sw_version)

        higher = utils.compare_release_version(self.release_data.metadata[deployment]["sw_version"],
                                               running_sw_version)

        if higher is None:
            msg_error += "The software version format for this release is not correct.\n"
            return dict(info=msg_info, warning=msg_warning, error=msg_error)
        elif higher:
            operation = "apply"
        else:
            operation = "remove"

        # If releases are such that:
        # R2 requires R1, R3 requires R2, R4 requires R3
        # If current running release is R2 and command issued is "software deploy start R4"
        # operation is "apply" with order [R3, R4]
        # If current running release is R4 and command issued is "software deploy start R2"
        # operation is "remove" with order [R4, R3]
        if operation == "apply":

            collect_current_load_for_hosts()
            create_deploy_hosts()

            # reverse = True is used for apply operation
            deployment_list = self.release_apply_remove_order(deployment, running_sw_version, reverse=True)

            msg = "Deploy start order for apply operation: %s" % ",".join(deployment_list)
            LOG.info(msg)
            audit_log_info(msg)

            # todo(jcasteli) Do we need this block below?
            # Check for patches that can't be applied during an upgrade
            upgrade_check = True
            for release in deployment_list:
                if self.release_data.metadata[release]["sw_version"] != SW_VERSION \
                        and self.release_data.metadata[release].get("apply_active_release_only") == "Y":
                    msg = "%s cannot be created during an upgrade" % release
                    LOG.error(msg)
                    msg_error += msg + "\n"
                    upgrade_check = False

            if not upgrade_check:
                return dict(info=msg_info, warning=msg_warning, error=msg_error)

            if kwargs.get("skip-semantic") != "yes":
                self.run_semantic_check(constants.SEMANTIC_PREAPPLY, deployment_list)

            # Start applying the releases
            for release in deployment_list:
                msg = "Starting deployment for: %s" % release
                LOG.info(msg)
                audit_log_info(msg)

                packages = [pkg.split("_")[0] for pkg in self.release_data.metadata[release].get("packages")]
                if packages is None:
                    msg = "Unable to determine packages to install"
                    LOG.error(msg)
                    raise MetadataFail(msg)

                if self.release_data.metadata[release]["state"] != constants.AVAILABLE \
                   or self.release_data.metadata[release]["state"] == constants.COMMITTED:
                    msg = "%s is already being deployed" % release
                    LOG.info(msg)
                    msg_info += msg + "\n"
                    continue

                release_sw_version = utils.get_major_release_version(
                    self.release_data.metadata[release]["sw_version"])

                latest_commit = ""
                try:
                    latest_commit = ostree_utils.get_feed_latest_commit(release_sw_version)
                    LOG.info("Latest commit: %s" % latest_commit)
                except OSTreeCommandFail:
                    LOG.exception("Failure during commit consistency check for %s.", release)

                feed_ostree = "%s/rel-%s/ostree_repo" % (constants.FEED_OSTREE_BASE_DIR, release_sw_version)

                try:
                    apt_utils.run_install(feed_ostree, packages)
                except APTOSTreeCommandFail:
                    LOG.exception("Failed to intall Debian package.")
                    raise APTOSTreeCommandFail(msg)

                # Update the feed ostree summary
                ostree_utils.update_repo_summary_file(feed_ostree)

                # Get the latest commit after performing "apt-ostree install".
                self.latest_feed_commit = ostree_utils.get_feed_latest_commit(SW_VERSION)

                try:
                    # Move the release metadata to deploying dir
                    deploystate = self.release_data.metadata[release]["state"]
                    metadata_dir = DEPLOY_STATE_METADATA_DIR_DICT[deploystate]

                    metadata_file = "%s/%s-metadata.xml" % (metadata_dir, release)
                    tree = ET.parse(metadata_file)
                    root = tree.getroot()

                    # ostree = ET.SubElement(root, "ostree")
                    self.add_text_tag_to_xml(root, "number_of_commits", "1")
                    self.add_text_tag_to_xml(root, "previous_commit", latest_commit)
                    self.add_text_tag_to_xml(root, "commit", self.latest_feed_commit)

                    ET.indent(tree, '  ')
                    with open(metadata_file, "wb") as outfile:
                        tree = ET.tostring(root)
                        outfile.write(tree)

                    LOG.info("Latest feed commit: %s added to metadata file" % self.latest_feed_commit)

                    shutil.move(metadata_file,
                                "%s/%s-metadata.xml" % (constants.DEPLOYING_START_DIR, release))

                    msg_info += "%s is now in the repo\n" % release
                except shutil.Error:
                    msg = "Failed to move the metadata for %s" % release
                    LOG.exception(msg)
                    raise MetadataFail(msg)

                if not os.path.isfile(INITIAL_CONTROLLER_CONFIG_COMPLETE):
                    self.release_data.metadata[release]["state"] = constants.DEPLOYING_START
                elif len(self.hosts) > 0:
                    self.release_data.metadata[release]["state"] = constants.DEPLOYING_START
                else:
                    self.release_data.metadata[release]["state"] = constants.UNKNOWN

                with self.hosts_lock:
                    self.interim_state[release] = list(self.hosts)

        elif operation == "remove":
            collect_current_load_for_hosts()
            create_deploy_hosts()
            removed = False
            deployment_list = self.release_apply_remove_order(deployment, running_sw_version)
            msg = "Deploy start order for remove operation: %s" % ",".join(deployment_list)
            LOG.info(msg)
            audit_log_info(msg)

            remove_unremovable = False

            if kwargs.get("removeunremovable") == "yes":
                remove_unremovable = True

            # See if any of the patches are marked as unremovable
            unremovable_verification = True
            for release in deployment_list:
                if self.release_data.metadata[release].get("unremovable") == "Y":
                    if remove_unremovable:
                        msg = "Unremovable release %s being removed" % release
                        LOG.warning(msg)
                        msg_warning += msg + "\n"
                    else:
                        msg = "Release %s is not removable" % release
                        LOG.error(msg)
                        msg_error += msg + "\n"
                        unremovable_verification = False
                elif self.release_data.metadata[release]['state'] == constants.COMMITTED:
                    msg = "Release %s is committed and cannot be removed" % release
                    LOG.error(msg)
                    msg_error += msg + "\n"
                    unremovable_verification = False

            if not unremovable_verification:
                return dict(info=msg_info, warning=msg_warning, error=msg_error)

            if kwargs.get("skipappcheck") != "yes":
                # Check application dependencies before removing
                required_releases = {}
                for release in deployment_list:
                    for appname, iter_release_list in self.app_dependencies.items():
                        if release in iter_release_list:
                            if release not in required_releases:
                                required_releases[release] = []
                            required_releases[release].append(appname)

                if len(required_releases) > 0:
                    for req_release, app_list in required_releases.items():
                        msg = "%s is required by application(s): %s" % (req_release, ", ".join(sorted(app_list)))
                        msg_error += msg + "\n"
                        LOG.info(msg)

                    return dict(info=msg_info, warning=msg_warning, error=msg_error)

            if kwargs.get("skip-semantic") != "yes":
                self.run_semantic_check(constants.SEMANTIC_PREREMOVE, deployment_list)

            for release in deployment_list:
                removed = True
                msg = "Removing release: %s" % release
                LOG.info(msg)
                audit_log_info(msg)

                if self.release_data.metadata[release]["state"] == constants.AVAILABLE:
                    msg = "The deployment for %s has not been created" % release
                    LOG.info(msg)
                    msg_info += msg + "\n"
                    continue

                major_release_sw_version = utils.get_major_release_version(
                    self.release_data.metadata[release]["sw_version"])
                # this is an ostree patch
                # Base commit is fetched from the patch metadata
                base_commit = self.release_data.contents[release]["base"]["commit"]
                feed_ostree = "%s/rel-%s/ostree_repo" % (constants.FEED_OSTREE_BASE_DIR, major_release_sw_version)
                try:
                    # Reset the ostree HEAD
                    ostree_utils.reset_ostree_repo_head(base_commit, feed_ostree)

                    # Delete all commits that belong to this release
                    for i in range(int(self.release_data.contents[release]["number_of_commits"])):
                        commit_to_delete = self.release_data.contents[release]["commit%s" % (i + 1)]["commit"]
                        ostree_utils.delete_ostree_repo_commit(commit_to_delete, feed_ostree)

                    # Update the feed ostree summary
                    ostree_utils.update_repo_summary_file(feed_ostree)

                except OSTreeCommandFail:
                    LOG.exception("Failure while removing release %s.", release)
                try:
                    # Move the metadata to the deleted dir
                    deploystate = self.release_data.metadata[release]["state"]
                    metadata_dir = DEPLOY_STATE_METADATA_DIR_DICT[deploystate]
                    shutil.move("%s/%s-metadata.xml" % (metadata_dir, release),
                                "%s/%s-metadata.xml" % (constants.REMOVING_DIR, release))
                    msg_info += "%s has been removed from the repo\n" % release
                except shutil.Error:
                    msg = "Failed to move the metadata for %s" % release
                    LOG.exception(msg)
                    raise MetadataFail(msg)

                # update state
                if not os.path.isfile(INITIAL_CONTROLLER_CONFIG_COMPLETE):
                    self.release_data.metadata[release]["state"] = constants.REMOVING
                elif len(self.hosts) > 0:
                    self.release_data.metadata[release]["state"] = constants.REMOVING
                else:
                    self.release_data.metadata[release]["state"] = constants.UNKNOWN

                # only update lastest_feed_commit if it is an ostree patch
                if self.release_data.contents[release].get("base") is not None:
                    # Base Commit in this release's metadata.xml file represents the latest commit
                    # after this release has been removed from the feed repo
                    self.latest_feed_commit = self.release_data.contents[release]["base"]["commit"]

                with self.hosts_lock:
                    self.interim_state[release] = list(self.hosts)

            if removed:
                try:
                    metadata_dir = DEPLOY_STATE_METADATA_DIR_DICT[deploystate]
                    shutil.move("%s/%s-metadata.xml" % (metadata_dir, deployment),
                                "%s/%s-metadata.xml" % (constants.DEPLOYING_START_DIR, deployment))
                    msg_info += "Deployment started for %s\n" % deployment
                except shutil.Error:
                    msg = "Failed to move the metadata for %s" % deployment
                    LOG.exception(msg)
                    raise MetadataFail(msg)

                # update state
                if not os.path.isfile(INITIAL_CONTROLLER_CONFIG_COMPLETE):
                    self.release_data.metadata[deployment]["state"] = constants.DEPLOYING_START
                elif len(self.hosts) > 0:
                    self.release_data.metadata[deployment]["state"] = constants.DEPLOYING_START
                else:
                    self.release_data.metadata[deployment]["state"] = constants.UNKNOWN

        return dict(info=msg_info, warning=msg_warning, error=msg_error)

    def software_deploy_complete_api(self, release: str) -> dict:
        """
        Completes a deployment associated with the release
        :return: dict of info, warning and error messages
        """
        msg_info = ""
        msg_warning = ""
        msg_error = ""
        if self.release_data.metadata[release]["state"] not in \
                [constants.DEPLOYING_ACTIVATE, constants.DEPLOYING_COMPLETE]:
            msg = "%s is not activated yet" % release
            LOG.info(msg)
            msg_info += msg + "\n"
        else:
            # Set the state to deploying-complete
            for release_id in sorted(list(self.release_data.metadata)):
                if self.release_data.metadata[release_id]["state"] == constants.DEPLOYING_ACTIVATE:
                    self.release_data.metadata[release_id]["state"] = constants.DEPLOYING_COMPLETE
                    try:
                        shutil.move("%s/%s-metadata.xml" % (constants.DEPLOYING_ACTIVATE_DIR, release_id),
                                    "%s/%s-metadata.xml" % (constants.DEPLOYING_COMPLETE_DIR, release_id))
                    except shutil.Error:
                        msg = "Failed to move the metadata for %s" % release_id
                        LOG.exception(msg)
                        raise MetadataFail(msg)

            # The code for deploy complete is going to execute
            # Once deploy complete is successfully executed, we move the metadata to their
            # respective folders
            for release_id in sorted(list(self.release_data.metadata)):
                if self.release_data.metadata[release_id]["state"] == constants.REMOVING:
                    self.release_data.metadata[release_id]["state"] = constants.AVAILABLE
                    try:
                        shutil.move("%s/%s-metadata.xml" % (constants.REMOVING_DIR, release_id),
                                    "%s/%s-metadata.xml" % (constants.AVAILABLE_DIR, release_id))
                        msg_info += "%s is available\n" % release_id
                    except shutil.Error:
                        msg = "Failed to move the metadata for %s" % release_id
                        LOG.exception(msg)
                        raise MetadataFail(msg)
                elif self.release_data.metadata[release_id]["state"] == constants.DEPLOYING_COMPLETE:
                    self.release_data.metadata[release_id]["state"] = constants.DEPLOYED

                    try:
                        shutil.move("%s/%s-metadata.xml" % (constants.DEPLOYING_COMPLETE_DIR, release_id),
                                    "%s/%s-metadata.xml" % (constants.DEPLOYED_DIR, release_id))
                        msg_info += "%s has been deployed\n" % release_id
                    except shutil.Error:
                        msg = "Failed to move the metadata for %s" % release_id
                        LOG.exception(msg)
                        raise MetadataFail(msg)

        return dict(info=msg_info, warning=msg_warning, error=msg_error)

    def software_deploy_activate_api(self, release: str) -> dict:
        """
        Activates the deployment associated with the release
        :return: dict of info, warning and error messages
        """
        msg_info = ""
        msg_warning = ""
        msg_error = ""
        if self.release_data.metadata[release]["state"] != constants.DEPLOYING_HOST:
            msg = "%s is not deployed on host" % release
            LOG.info(msg)
            msg_info += msg + "\n"
        else:
            try:
                shutil.move("%s/%s-metadata.xml" % (constants.DEPLOYING_HOST_DIR, release),
                            "%s/%s-metadata.xml" % (constants.DEPLOYING_ACTIVATE_DIR, release))
            except shutil.Error:
                msg = "Failed to move the metadata for %s" % release
                LOG.exception(msg)
                raise MetadataFail(msg)

            msg_info += "Deployment for %s has been activated\n" % release
            self.release_data.metadata[release]["state"] = constants.DEPLOYING_ACTIVATE

        return dict(info=msg_info, warning=msg_warning, error=msg_error)

    def software_deploy_show_api(self, from_release=None, to_release=None):
        # Retrieve deploy state from db
        if from_release and to_release:
            return self.db_api_instance.get_deploy(from_release, to_release)
        else:
            # Retrieve deploy state from db in list format
            return self.db_api_instance.get_deploy_all()

    def software_deploy_host_api(self, host_ip, force, async_req=False):
        msg_info = ""
        msg_warning = ""
        msg_error = ""

        ip = host_ip

        self.hosts_lock.acquire()
        # If not in hosts table, maybe a hostname was used instead
        if host_ip not in self.hosts:
            try:
                ip = utils.gethostbyname(host_ip)
                if ip not in self.hosts:
                    # Translated successfully, but IP isn't in the table.
                    # Raise an exception to drop out to the failure handling
                    raise SoftwareError("Host IP (%s) not in table" % ip)
            except Exception:
                self.hosts_lock.release()
                msg = "Unknown host specified: %s" % host_ip
                msg_error += msg + "\n"
                LOG.error("Error in host-install: %s", msg)
                return dict(info=msg_info, warning=msg_warning, error=msg_error)

        msg = "Running software deploy host for %s (%s), force=%s, async_req=%s" % (host_ip, ip, force, async_req)
        LOG.info(msg)
        audit_log_info(msg)

        if self.allow_insvc_patching:
            LOG.info("Allowing in-service patching")
            force = True
            self.copy_restart_scripts()

        self.hosts[ip].install_pending = True
        self.hosts[ip].install_status = False
        self.hosts[ip].install_reject_reason = None
        self.hosts_lock.release()

        installreq = PatchMessageAgentInstallReq()
        installreq.ip = ip
        installreq.force = force
        installreq.encode()
        self.socket_lock.acquire()
        installreq.send(self.sock_out)
        self.socket_lock.release()

        if async_req:
            # async_req install requested, so return now
            msg = "Host installation request sent to %s." % self.hosts[ip].hostname
            msg_info += msg + "\n"
            LOG.info("host-install async_req: %s", msg)
            for release in sorted(list(self.release_data.metadata)):
                if self.release_data.metadata[release]["state"] == constants.DEPLOYING_START:
                    try:
                        shutil.move("%s/%s-metadata.xml" % (constants.DEPLOYING_START_DIR, release),
                                    "%s/%s-metadata.xml" % (constants.DEPLOYING_HOST_DIR, release))
                        msg_info += "%s has been activated\n" % release
                    except shutil.Error:
                        msg = "Failed to move the metadata for %s" % release
                        LOG.exception(msg)
                        raise MetadataFail(msg)
                    self.release_data.metadata[release]["state"] = constants.DEPLOYING_HOST
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # Now we wait, up to ten mins. future enhancement: Wait on a condition
        resp_rx = False
        max_time = time.time() + 600
        while time.time() < max_time:
            self.hosts_lock.acquire()
            if ip not in self.hosts:
                # The host aged out while we were waiting
                self.hosts_lock.release()
                msg = "Agent expired while waiting: %s" % ip
                msg_error += msg + "\n"
                LOG.error("Error in host-install: %s", msg)
                break

            if not self.hosts[ip].install_pending:
                # We got a response
                resp_rx = True
                if self.hosts[ip].install_status:
                    msg = "Host installation was successful on %s." % self.hosts[ip].hostname
                    msg_info += msg + "\n"
                    LOG.info("host-install: %s", msg)
                elif self.hosts[ip].install_reject_reason:
                    msg = "Host installation rejected by %s. %s" % (
                        self.hosts[ip].hostname,
                        self.hosts[ip].install_reject_reason)
                    msg_error += msg + "\n"
                    LOG.error("Error in host-install: %s", msg)
                else:
                    msg = "Host installation failed on %s." % self.hosts[ip].hostname
                    msg_error += msg + "\n"
                    LOG.error("Error in host-install: %s", msg)

                self.hosts_lock.release()
                break

            self.hosts_lock.release()

            time.sleep(0.5)

        if not resp_rx:
            msg = "Timeout occurred while waiting response from %s." % ip
            msg_error += msg + "\n"
            LOG.error("Error in host-install: %s", msg)

        for release in sorted(list(self.release_data.metadata)):
            if self.release_data.metadata[release]["state"] == constants.DEPLOYING_START:
                try:
                    shutil.move("%s/%s-metadata.xml" % (constants.DEPLOYING_START_DIR, release),
                                "%s/%s-metadata.xml" % (constants.DEPLOYING_HOST_DIR, release))
                    msg_info += "%s has been activated\n" % release
                except shutil.Error:
                    msg = "Failed to move the metadata for %s" % release
                    LOG.exception(msg)
                    raise MetadataFail(msg)
                self.release_data.metadata[release]["state"] = constants.DEPLOYING_HOST
        return dict(info=msg_info, warning=msg_warning, error=msg_error)

    def drop_host(self, host_ip, sync_nbr=True):
        msg_info = ""
        msg_warning = ""
        msg_error = ""

        ip = host_ip

        self.hosts_lock.acquire()
        # If not in hosts table, maybe a hostname was used instead
        if host_ip not in self.hosts:
            try:
                # Because the host may be getting dropped due to deletion,
                # we may be unable to do a hostname lookup. Instead, we'll
                # iterate through the table here.
                for host in list(self.hosts):
                    if host_ip == self.hosts[host].hostname:
                        ip = host
                        break

                if ip not in self.hosts:
                    # Translated successfully, but IP isn't in the table.
                    # Raise an exception to drop out to the failure handling
                    raise SoftwareError("Host IP (%s) not in table" % ip)
            except Exception:
                self.hosts_lock.release()
                msg = "Unknown host specified: %s" % host_ip
                msg_error += msg + "\n"
                LOG.error("Error in drop-host: %s", msg)
                return dict(info=msg_info, warning=msg_warning, error=msg_error)

        msg = "Running drop-host for %s (%s)" % (host_ip, ip)
        LOG.info(msg)
        audit_log_info(msg)

        del self.hosts[ip]
        for patch_id in list(self.interim_state):
            if ip in self.interim_state[patch_id]:
                self.interim_state[patch_id].remove(ip)

        self.hosts_lock.release()

        if sync_nbr:
            sync_msg = PatchMessageDropHostReq()
            sync_msg.ip = ip
            self.socket_lock.acquire()
            sync_msg.send(self.sock_out)
            self.socket_lock.release()

        return dict(info=msg_info, warning=msg_warning, error=msg_error)

    def is_available(self, release_ids):
        all_available = True

        with self.release_data_lock:

            for release_id in release_ids:
                if release_id not in self.release_data.metadata:
                    all_available = False
                    break

                if self.release_data.metadata[release_id]["state"] != \
                        constants.AVAILABLE:
                    all_available = False
                    break

        return all_available

    def is_deployed(self, release_ids):
        all_deployed = True

        with self.release_data_lock:

            for release_id in release_ids:
                if release_id not in self.release_data.metadata:
                    all_deployed = False
                    break

                if self.release_data.metadata[release_id]["state"] != constants.DEPLOYED:
                    all_deployed = False
                    break

        return all_deployed

    def is_committed(self, release_ids):
        all_committed = True

        with self.release_data_lock:

            for release_id in release_ids:
                if release_id not in self.release_data.metadata:
                    all_committed = False
                    break

                if self.release_data.metadata[release_id]["state"] != \
                        constants.COMMITTED:
                    all_committed = False
                    break

        return all_committed

    def report_app_dependencies(self, patch_ids, **kwargs):
        """
        Handle report of application dependencies
        """
        if "app" not in kwargs:
            raise ReleaseInvalidRequest

        appname = kwargs.get("app")

        LOG.info("Handling app dependencies report: app=%s, patch_ids=%s",
                 appname, ','.join(patch_ids))

        self.release_data_lock.acquire()

        if len(patch_ids) == 0:
            if appname in self.app_dependencies:
                del self.app_dependencies[appname]
        else:
            self.app_dependencies[appname] = patch_ids

        try:
            tmpfile, tmpfname = tempfile.mkstemp(
                prefix=app_dependency_basename,
                dir=constants.SOFTWARE_STORAGE_DIR)

            os.write(tmpfile, json.dumps(self.app_dependencies).encode())
            os.close(tmpfile)

            os.rename(tmpfname, app_dependency_filename)
        except Exception:
            LOG.exception("Failed in report_app_dependencies")
            raise SoftwareFail("Internal failure")
        finally:
            self.release_data_lock.release()

        return True

    def query_app_dependencies(self):
        """
        Query application dependencies
        """
        self.release_data_lock.acquire()

        data = self.app_dependencies

        self.release_data_lock.release()

        return dict(data)

    def deploy_host_list(self):
        deploy_hosts = self.db_api_instance.get_deploy_host()
        deploy = self.db_api_instance.get_deploy_all()
        if not deploy:
            return None
        deploy = deploy[0]

        deploy_host_list = []
        for host in deploy_hosts:
            state = host.get("state")
            deploy_host = {
                "hostname": host.get("hostname"),
                "software_release": deploy.get("from_release"),
                "target_release": deploy.get("to_release") if state else None,
                "reboot_required": deploy.get("reboot_required") if state else None,
                "host_state": state
            }
            deploy_host_list.append(deploy_host)
        return deploy_host_list

    def update_and_sync_deploy_state(self, func, *args, **kwargs):
        """
        :param func: SoftwareApi method
        :param args: arguments passed related to func
        :param kwargs: keyword arguments passed related to func

        Example:
        -------

        Usage of *args:
        update_and_sync_deploy_state(self.db_api_instance.create_deploy,
                                     release_version, to_release, bool)
        Usage of **kwargs:
        update_and_sync_deploy_state(self.db_api_instance.update_deploy_host,
                                     hostname=hostname, state=state)
        """

        func(*args, **kwargs)
        self._update_state_to_peer()


class PatchControllerApiThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.wsgi = None

    def run(self):
        host = "127.0.0.1"
        port = cfg.api_port

        try:
            # In order to support IPv6, server_class.address_family must be
            # set to the correct address family.  Because the unauthenticated
            # API always uses IPv4 for the loopback address, the address_family
            # variable cannot be set directly in the WSGIServer class, so a
            # local subclass needs to be created for the call to make_server,
            # where the correct address_family can be specified.
            class server_class(simple_server.WSGIServer):
                pass

            server_class.address_family = socket.AF_INET
            self.wsgi = simple_server.make_server(
                host, port,
                app.VersionSelectorApplication(),
                server_class=server_class)

            self.wsgi.socket.settimeout(api_socket_timeout)
            global keep_running
            while keep_running:
                self.wsgi.handle_request()

                # Call garbage collect after wsgi request is handled,
                # to ensure any open file handles are closed in the case
                # of an upload.
                gc.collect()
        except Exception:
            # Log all exceptions
            LOG.exception("Error occurred during request processing")

        global thread_death
        thread_death.set()

    def kill(self):
        # Must run from other thread
        if self.wsgi is not None:
            self.wsgi.shutdown()


class PatchControllerAuthApiThread(threading.Thread):
    def __init__(self, port):
        threading.Thread.__init__(self)
        # LOG.info ("Initializing Authenticated API thread")
        self.wsgi = None
        self.port = port

    def run(self):
        host = CONF.auth_api_bind_ip
        if host is None:
            host = utils.get_versioned_address_all()
        try:
            # Can only launch authenticated server post-config
            while not os.path.exists('/etc/platform/.initial_config_complete'):
                time.sleep(5)

            # In order to support IPv6, server_class.address_family must be
            # set to the correct address family.  Because the unauthenticated
            # API always uses IPv4 for the loopback address, the address_family
            # variable cannot be set directly in the WSGIServer class, so a
            # local subclass needs to be created for the call to make_server,
            # where the correct address_family can be specified.
            class server_class(simple_server.WSGIServer):
                pass

            server_class.address_family = utils.get_management_family()
            self.wsgi = simple_server.make_server(
                host, self.port,
                auth_app.VersionSelectorApplication(),
                server_class=server_class)

            # self.wsgi.serve_forever()
            self.wsgi.socket.settimeout(api_socket_timeout)

            global keep_running
            while keep_running:
                self.wsgi.handle_request()

                # Call garbage collect after wsgi request is handled,
                # to ensure any open file handles are closed in the case
                # of an upload.
                gc.collect()
        except Exception:
            # Log all exceptions
            LOG.exception("Authorized API failure: Error occurred during request processing")

    def kill(self):
        # Must run from other thread
        if self.wsgi is not None:
            self.wsgi.shutdown()


class PatchControllerMainThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        # LOG.info ("Initializing Main thread")

    def run(self):
        global sc
        global thread_death

        # Send periodic messages to the agents
        # We only can use one inverval
        SEND_MSG_INTERVAL_IN_SECONDS = 30.0

        try:
            sock_in = sc.setup_socket()

            while sock_in is None:
                # Check every thirty seconds?
                # Once we've got a conf file, tied into packstack,
                # we'll get restarted when the file is updated,
                # and this should be unnecessary.
                time.sleep(30)
                sock_in = sc.setup_socket()

            # Ok, now we've got our socket. Let's start with a hello!
            sc.socket_lock.acquire()

            hello = PatchMessageHello()
            hello.send(sc.sock_out)

            hello_agent = PatchMessageHelloAgent()
            hello_agent.send(sc.sock_out)

            sc.socket_lock.release()

            # Send hello every thirty seconds
            hello_timeout = time.time() + SEND_MSG_INTERVAL_IN_SECONDS
            # Send deploy state update every thirty seconds
            deploy_state_update_timeout = time.time() + SEND_MSG_INTERVAL_IN_SECONDS
            remaining = int(SEND_MSG_INTERVAL_IN_SECONDS)

            agent_query_conns = []

            while True:
                # Check to see if any other thread has died
                if thread_death.is_set():
                    LOG.info("Detected thread death. Terminating")
                    return

                # Check for in-service patch restart flag
                if os.path.exists(insvc_patch_restart_controller):
                    LOG.info("In-service patch restart flag detected. Exiting.")
                    global keep_running
                    keep_running = False
                    os.remove(insvc_patch_restart_controller)
                    return

                inputs = [sc.sock_in] + agent_query_conns
                outputs = []

                rlist, wlist, xlist = select.select(
                    inputs, outputs, inputs, SEND_MSG_INTERVAL_IN_SECONDS)

                if (len(rlist) == 0 and
                        len(wlist) == 0 and
                        len(xlist) == 0):
                    # Timeout hit
                    sc.audit_socket()

                for s in rlist:
                    data = ''
                    addr = None
                    msg = None

                    if s == sc.sock_in:
                        # Receive from UDP
                        sc.socket_lock.acquire()
                        data, addr = s.recvfrom(1024)
                        sc.socket_lock.release()
                    else:
                        # Receive from TCP
                        while True:
                            try:
                                packet = s.recv(1024)
                            except socket.error:
                                LOG.exception("Socket error on recv")
                                data = ''
                                break

                            if packet:
                                data += packet.decode()

                                if data == '':
                                    break
                                try:
                                    json.loads(data)
                                    break
                                except ValueError:
                                    # Message is incomplete
                                    continue
                            else:
                                LOG.info('End of TCP message received')
                                break

                        if data == '':
                            # Connection dropped
                            agent_query_conns.remove(s)
                            s.close()
                            continue

                        # Get the TCP endpoint address
                        addr = s.getpeername()

                    msgdata = json.loads(data)

                    # For now, discard any messages that are not msgversion==1
                    if 'msgversion' in msgdata and msgdata['msgversion'] != 1:
                        continue

                    if 'msgtype' in msgdata:
                        if msgdata['msgtype'] == messages.PATCHMSG_HELLO:
                            msg = PatchMessageHello()
                        elif msgdata['msgtype'] == messages.PATCHMSG_HELLO_ACK:
                            msg = PatchMessageHelloAck()
                        elif msgdata['msgtype'] == messages.PATCHMSG_SYNC_REQ:
                            msg = PatchMessageSyncReq()
                        elif msgdata['msgtype'] == messages.PATCHMSG_SYNC_COMPLETE:
                            msg = PatchMessageSyncComplete()
                        elif msgdata['msgtype'] == messages.PATCHMSG_HELLO_AGENT_ACK:
                            msg = PatchMessageHelloAgentAck()
                        elif msgdata['msgtype'] == messages.PATCHMSG_QUERY_DETAILED_RESP:
                            msg = PatchMessageQueryDetailedResp()
                        elif msgdata['msgtype'] == messages.PATCHMSG_AGENT_INSTALL_RESP:
                            msg = PatchMessageAgentInstallResp()
                        elif msgdata['msgtype'] == messages.PATCHMSG_DROP_HOST_REQ:
                            msg = PatchMessageDropHostReq()
                        elif msgdata['msgtype'] == messages.PATCHMSG_DEPLOY_STATE_UPDATE_ACK:
                            msg = SoftwareMessageDeployStateUpdateAck()
                        elif msgdata['msgtype'] == messages.PATCHMSG_DEPLOY_STATE_CHANGED:
                            msg = SWMessageDeployStateChanged()

                    if msg is None:
                        msg = messages.PatchMessage()

                    msg.decode(msgdata)
                    if s == sc.sock_in:
                        msg.handle(sc.sock_out, addr)
                    else:
                        msg.handle(s, addr)

                    # We can drop the connection after a query response
                    if msg.msgtype == messages.PATCHMSG_QUERY_DETAILED_RESP and s != sc.sock_in:
                        agent_query_conns.remove(s)
                        s.shutdown(socket.SHUT_RDWR)
                        s.close()

                while len(stale_hosts) > 0 and len(agent_query_conns) <= 5:
                    ip = stale_hosts.pop()
                    try:
                        agent_sock = socket.create_connection((ip, cfg.agent_port))
                        query = PatchMessageQueryDetailed()
                        query.send(agent_sock)
                        agent_query_conns.append(agent_sock)
                    except Exception:
                        # Put it back on the list
                        stale_hosts.append(ip)

                remaining = int(hello_timeout - time.time())
                if remaining <= 0 or remaining > int(SEND_MSG_INTERVAL_IN_SECONDS):
                    hello_timeout = time.time() + SEND_MSG_INTERVAL_IN_SECONDS
                    remaining = int(SEND_MSG_INTERVAL_IN_SECONDS)

                    sc.socket_lock.acquire()

                    hello = PatchMessageHello()
                    hello.send(sc.sock_out)

                    hello_agent = PatchMessageHelloAgent()
                    hello_agent.send(sc.sock_out)

                    sc.socket_lock.release()

                    # Age out neighbours
                    sc.controller_neighbours_lock.acquire()
                    nbrs = list(sc.controller_neighbours)
                    for n in nbrs:
                        # Age out controllers after 2 minutes
                        if sc.controller_neighbours[n].get_age() >= 120:
                            LOG.info("Aging out controller %s from table", n)
                            del sc.controller_neighbours[n]
                    sc.controller_neighbours_lock.release()

                    sc.hosts_lock.acquire()
                    nbrs = list(sc.hosts)
                    for n in nbrs:
                        # Age out hosts after 1 hour
                        if sc.hosts[n].get_age() >= 3600:
                            LOG.info("Aging out host %s from table", n)
                            del sc.hosts[n]
                            for patch_id in list(sc.interim_state):
                                if n in sc.interim_state[patch_id]:
                                    sc.interim_state[patch_id].remove(n)

                    sc.hosts_lock.release()

                deploy_state_update_remaining = int(deploy_state_update_timeout - time.time())
                # Only send the deploy state update from the active controller
                if deploy_state_update_remaining <= 0 or deploy_state_update_remaining > int(
                        SEND_MSG_INTERVAL_IN_SECONDS):
                    deploy_state_update_timeout = time.time() + SEND_MSG_INTERVAL_IN_SECONDS
                    deploy_state_update_remaining = int(
                        SEND_MSG_INTERVAL_IN_SECONDS)

                    # Only send the deploy state update from the active controller
                    if utils.is_active_controller():
                        try:
                            sc.socket_lock.acquire()
                            deploy_state_update = SoftwareMessageDeployStateUpdate()
                            deploy_state_update.send(sc.sock_out)
                        except Exception as e:
                            LOG.exception("Failed to send deploy state update. Error: %s", str(e))
                        finally:
                            sc.socket_lock.release()
        except Exception:
            # Log all exceptions
            LOG.exception("Error occurred during request processing")
            thread_death.set()


def main():
    # The following call to CONF is to ensure the oslo config
    # has been called to specify a valid config dir.
    # Otherwise oslo_policy will fail when it looks for its files.
    CONF(
        (),  # Required to load an anonymous configuration
        default_config_files=['/etc/software/software.conf', ]
    )

    configure_logging()

    cfg.read_config()

    # daemon.pidlockfile.write_pid_to_pidfile(pidfile_path)

    global thread_death
    thread_death = threading.Event()

    # Set the TMPDIR environment variable to /scratch so that any modules
    # that create directories with tempfile will not use /tmp
    os.environ['TMPDIR'] = '/scratch'

    global sc
    sc = PatchController()

    LOG.info("launching")
    api_thread = PatchControllerApiThread()
    auth_api_thread = PatchControllerAuthApiThread(CONF.auth_api_port)
    auth_api_alt_thread = PatchControllerAuthApiThread(CONF.auth_api_alt_port)
    main_thread = PatchControllerMainThread()

    api_thread.start()
    auth_api_thread.start()
    auth_api_alt_thread.start()
    main_thread.start()

    thread_death.wait()
    global keep_running
    keep_running = False

    api_thread.join()
    auth_api_thread.join()
    auth_api_alt_thread.join()
    main_thread.join()
