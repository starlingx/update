"""
Copyright (c) 2023 Wind River Systems, Inc.

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
import tarfile
import tempfile
import threading
import time
from wsgiref import simple_server

from oslo_config import cfg as oslo_cfg

from software import ostree_utils
from software.api import app
from software.authapi import app as auth_app
from software.base import PatchService
from software.exceptions import MetadataFail
from software.exceptions import OSTreeCommandFail
from software.exceptions import OSTreeTarFail
from software.exceptions import PatchError
from software.exceptions import PatchFail
from software.exceptions import PatchInvalidRequest
from software.exceptions import PatchValidationFailure
from software.exceptions import PatchMismatchFailure
from software.exceptions import SemanticFail
from software.software_functions import configure_logging
from software.software_functions import BasePackageData
from software.software_functions import avail_dir
from software.software_functions import applied_dir
from software.software_functions import committed_dir
from software.software_functions import PatchFile
from software.software_functions import package_dir
from software.software_functions import repo_dir
from software.software_functions import root_scripts_dir
from software.software_functions import semantics_dir
from software.software_functions import SW_VERSION
from software.software_functions import root_package_dir
from software.software_functions import LOG
from software.software_functions import audit_log_info
from software.software_functions import patch_dir
from software.software_functions import repo_root_dir
from software.software_functions import PatchData

import software.software_config as cfg
import software.utils as utils

import software.messages as messages
import software.constants as constants

from tsconfig.tsconfig import INITIAL_CONFIG_COMPLETE_FLAG

CONF = oslo_cfg.CONF

pidfile_path = "/var/run/patch_controller.pid"

pc = None
state_file = "%s/.controller.state" % constants.PATCH_STORAGE_DIR
app_dependency_basename = "app_dependencies.json"
app_dependency_filename = "%s/%s" % (constants.PATCH_STORAGE_DIR, app_dependency_basename)

insvc_patch_restart_controller = "/run/software/.restart.software-controller"

stale_hosts = []
pending_queries = []

thread_death = None
keep_running = True

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
             "patch_current": not self.out_of_date,
             "secs_since_ack": self.get_age(),
             "patch_failed": self.patch_failed,
             "stale_details": self.stale,
             "latest_sysroot_commit": self.latest_sysroot_commit,
             "nodetype": self.nodetype,
             "subfunctions": self.subfunctions,
             "sw_version": self.sw_version,
             "state": self.state}

        global pc
        if self.out_of_date and not pc.allow_insvc_patching:
            d["requires_reboot"] = True
        else:
            d["requires_reboot"] = self.requires_reboot

        # Included for future enhancement, to allow per-node determination
        # of in-service patching
        d["allow_insvc_patching"] = pc.allow_insvc_patching

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
        global pc
        messages.PatchMessage.encode(self)
        self.message['patch_op_counter'] = pc.patch_op_counter

    def handle(self, sock, addr):
        global pc
        host = addr[0]
        if host == cfg.get_mgmt_ip():
            # Ignore messages from self
            return

        # Send response
        if self.patch_op_counter > 0:
            pc.handle_nbr_patch_op_counter(host, self.patch_op_counter)

        resp = PatchMessageHelloAck()
        resp.send(sock)

    def send(self, sock):
        global pc
        self.encode()
        message = json.dumps(self.message)
        sock.sendto(str.encode(message), (pc.controller_address, cfg.controller_port))


class PatchMessageHelloAck(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_HELLO_ACK)

    def encode(self):
        # Nothing to add, so just call the super class
        messages.PatchMessage.encode(self)

    def handle(self, sock, addr):
        global pc

        pc.controller_neighbours_lock.acquire()
        if not addr[0] in pc.controller_neighbours:
            pc.controller_neighbours[addr[0]] = ControllerNeighbour()

        pc.controller_neighbours[addr[0]].rx_ack()
        pc.controller_neighbours_lock.release()

    def send(self, sock):
        global pc
        self.encode()
        message = json.dumps(self.message)
        sock.sendto(str.encode(message), (pc.controller_address, cfg.controller_port))


class PatchMessageSyncReq(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_SYNC_REQ)

    def encode(self):
        # Nothing to add to the SYNC_REQ, so just call the super class
        messages.PatchMessage.encode(self)

    def handle(self, sock, addr):
        global pc
        host = addr[0]
        if host == cfg.get_mgmt_ip():
            # Ignore messages from self
            return

        # We may need to do this in a separate thread, so that we continue to process hellos
        LOG.info("Handling sync req")

        pc.sync_from_nbr(host)

        resp = PatchMessageSyncComplete()
        resp.send(sock)

    def send(self, sock):
        global pc
        LOG.info("sending sync req")
        self.encode()
        message = json.dumps(self.message)
        sock.sendto(str.encode(message), (pc.controller_address, cfg.controller_port))


class PatchMessageSyncComplete(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_SYNC_COMPLETE)

    def encode(self):
        # Nothing to add to the SYNC_COMPLETE, so just call the super class
        messages.PatchMessage.encode(self)

    def handle(self, sock, addr):
        global pc
        LOG.info("Handling sync complete")

        pc.controller_neighbours_lock.acquire()
        if not addr[0] in pc.controller_neighbours:
            pc.controller_neighbours[addr[0]] = ControllerNeighbour()

        pc.controller_neighbours[addr[0]].rx_synced()
        pc.controller_neighbours_lock.release()

    def send(self, sock):
        global pc
        LOG.info("sending sync complete")
        self.encode()
        message = json.dumps(self.message)
        sock.sendto(str.encode(message), (pc.controller_address, cfg.controller_port))


class PatchMessageHelloAgent(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_HELLO_AGENT)

    def encode(self):
        global pc
        messages.PatchMessage.encode(self)
        self.message['patch_op_counter'] = pc.patch_op_counter

    def handle(self, sock, addr):
        LOG.error("Should not get here")

    def send(self, sock):
        global pc
        self.encode()
        message = json.dumps(self.message)
        local_hostname = utils.ip_to_versioned_localhost(cfg.agent_mcast_group)
        sock.sendto(str.encode(message), (pc.agent_address, cfg.agent_port))
        sock.sendto(str.encode(message), (local_hostname, cfg.agent_port))


class PatchMessageSendLatestFeedCommit(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_SEND_LATEST_FEED_COMMIT)

    def encode(self):
        global pc
        messages.PatchMessage.encode(self)
        self.message['latest_feed_commit'] = pc.latest_feed_commit

    def handle(self, sock, addr):
        LOG.error("Should not get here")

    def send(self, sock):
        global pc
        self.encode()
        message = json.dumps(self.message)
        local_hostname = utils.ip_to_versioned_localhost(cfg.agent_mcast_group)
        sock.sendto(str.encode(message), (pc.agent_address, cfg.agent_port))
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
        global pc

        pc.hosts_lock.acquire()
        if not addr[0] in pc.hosts:
            pc.hosts[addr[0]] = AgentNeighbour(addr[0])

        pc.hosts[addr[0]].rx_ack(self.agent_hostname,
                                 self.agent_out_of_date,
                                 self.agent_requires_reboot,
                                 self.query_id,
                                 self.agent_patch_failed,
                                 self.agent_sw_version,
                                 self.agent_state)
        pc.hosts_lock.release()

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
        global pc

        ip = addr[0]
        pc.hosts_lock.acquire()
        if ip in pc.hosts:
            pc.hosts[ip].handle_query_detailed_resp(self.latest_sysroot_commit,
                                                    self.nodetype,
                                                    self.agent_sw_version,
                                                    self.subfunctions,
                                                    self.agent_state)
            for patch_id in list(pc.interim_state):
                if ip in pc.interim_state[patch_id]:
                    pc.interim_state[patch_id].remove(ip)
                    if len(pc.interim_state[patch_id]) == 0:
                        del pc.interim_state[patch_id]
            pc.hosts_lock.release()
            pc.check_patch_states()
        else:
            pc.hosts_lock.release()

    def send(self, sock):  # pylint: disable=unused-argument
        LOG.error("Should not get here")


class PatchMessageAgentInstallReq(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_AGENT_INSTALL_REQ)
        self.ip = None
        self.force = False

    def encode(self):
        global pc
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
        global pc
        # LOG.info("Handling hello ack")

        pc.hosts_lock.acquire()
        if not addr[0] in pc.hosts:
            pc.hosts[addr[0]] = AgentNeighbour(addr[0])

        pc.hosts[addr[0]].install_status = self.status
        pc.hosts[addr[0]].install_pending = False
        pc.hosts[addr[0]].install_reject_reason = self.reject_reason
        pc.hosts_lock.release()

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
        global pc
        host = addr[0]
        if host == cfg.get_mgmt_ip():
            # Ignore messages from self
            return

        if self.ip is None:
            LOG.error("Received PATCHMSG_DROP_HOST_REQ with no ip: %s", json.dumps(self.data))
            return

        pc.drop_host(self.ip, sync_nbr=False)
        return

    def send(self, sock):
        global pc
        self.encode()
        message = json.dumps(self.message)
        sock.sendto(str.encode(message), (pc.controller_address, cfg.controller_port))


class PatchController(PatchService):
    def __init__(self):
        PatchService.__init__(self)

        # Locks
        self.socket_lock = threading.RLock()
        self.controller_neighbours_lock = threading.RLock()
        self.hosts_lock = threading.RLock()
        self.patch_data_lock = threading.RLock()

        self.hosts = {}
        self.controller_neighbours = {}

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
        self.patch_data = PatchData()
        self.patch_data.load_all()
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
                                              "%s/" % patch_dir],
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

        self.patch_data_lock.acquire()
        self.hosts_lock.acquire()
        self.interim_state = {}
        self.patch_data.load_all()
        self.check_patch_states()
        self.hosts_lock.release()

        if os.path.exists(app_dependency_filename):
            try:
                with open(app_dependency_filename, 'r') as f:
                    self.app_dependencies = json.loads(f.read())
            except Exception:
                LOG.exception("Failed to read app dependencies: %s", app_dependency_filename)
        else:
            self.app_dependencies = {}

        self.patch_data_lock.release()

        return True

    def inc_patch_op_counter(self):
        self.patch_op_counter += 1
        self.write_state_file()

    def check_patch_states(self):
        # If we have no hosts, we can't be sure of the current patch state
        if len(self.hosts) == 0:
            for patch_id in self.patch_data.metadata:
                self.patch_data.metadata[patch_id]["patchstate"] = constants.UNKNOWN
            return

        # Default to allowing in-service patching
        self.allow_insvc_patching = True

        # Take the detailed query results from the hosts and merge with the patch data

        self.hosts_lock.acquire()

        # Initialize patch state data based on repo state and interim_state presence
        for patch_id in self.patch_data.metadata:
            if patch_id in self.interim_state:
                if self.patch_data.metadata[patch_id]["repostate"] == constants.AVAILABLE:
                    self.patch_data.metadata[patch_id]["patchstate"] = constants.PARTIAL_REMOVE
                elif self.patch_data.metadata[patch_id]["repostate"] == constants.APPLIED:
                    self.patch_data.metadata[patch_id]["patchstate"] = constants.PARTIAL_APPLY
                if self.patch_data.metadata[patch_id].get("reboot_required") != "N":
                    self.allow_insvc_patching = False
            else:
                self.patch_data.metadata[patch_id]["patchstate"] = \
                    self.patch_data.metadata[patch_id]["repostate"]

        for ip in (ip for ip in list(self.hosts) if self.hosts[ip].out_of_date):
            # If a host is out-of-date, the patch repostate is APPLIED and the patch's first
            # commit doesn't match the active sysroot commit on the host, then change
            # patchstate to PARTIAL-APPLY.
            # If a host is out-of-date, the patch repostate is AVAILABLE and the patch's first
            # commit is equal to the active sysroot commit on the host, then change the
            # patchstate to PARTIAL-REMOVE. Additionally, change the patchstates of the
            # patch required (directly or a chain dependency) by the current patch.
            skip_patch = []
            for patch_id in self.patch_data.metadata:
                # If the patch is on a different release than the host, skip it.
                if self.patch_data.metadata[patch_id]["sw_version"] != self.hosts[ip].sw_version:
                    continue

                if patch_id not in skip_patch:
                    if self.patch_data.metadata[patch_id]["repostate"] == constants.AVAILABLE and \
                            self.hosts[ip].latest_sysroot_commit == \
                            self.patch_data.contents[patch_id]["commit1"]["commit"]:
                        self.patch_data.metadata[patch_id]["patchstate"] = constants.PARTIAL_REMOVE
                        patch_dependency_list = self.get_patch_dependency_list(patch_id)
                        for req_patch in patch_dependency_list:
                            if self.patch_data.metadata[req_patch]["repostate"] == constants.AVAILABLE:
                                self.patch_data.metadata[req_patch]["patchstate"] = constants.PARTIAL_REMOVE
                            else:
                                self.patch_data.metadata[req_patch]["patchstate"] = constants.APPLIED
                            skip_patch.append(req_patch)
                    elif self.patch_data.metadata[patch_id]["repostate"] == constants.APPLIED and \
                            self.hosts[ip].latest_sysroot_commit != \
                            self.patch_data.contents[patch_id]["commit1"]["commit"]:
                        self.patch_data.metadata[patch_id]["patchstate"] = constants.PARTIAL_APPLY
                    if self.patch_data.metadata[patch_id].get("reboot_required") != "N" and \
                            (self.patch_data.metadata[patch_id]["patchstate"] == constants.PARTIAL_APPLY or
                             self.patch_data.metadata[patch_id]["patchstate"] == constants.PARTIAL_REMOVE):
                        self.allow_insvc_patching = False

        self.hosts_lock.release()

    def get_patch_dependency_list(self, patch_id):
        """
        Returns a list of patch IDs that are required by this patch.
        Example: If patch3 requires patch2 and patch2 requires patch1,
                 then this patch will return ['patch2', 'patch1'] for
                 input param patch_id='patch3'
        :param patch_id: The patch ID
        """
        if not self.patch_data.metadata[patch_id]["requires"]:
            return []
        else:
            patch_dependency_list = []
            for req_patch in self.patch_data.metadata[patch_id]["requires"]:
                patch_dependency_list.append(req_patch)
                patch_dependency_list = patch_dependency_list + self.get_patch_dependency_list(req_patch)
            return patch_dependency_list

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
        if not self.patch_data.metadata[patch_id].get("restart_script"):
            return

        restart_script_path = "%s/%s" % (root_scripts_dir, self.patch_data.metadata[patch_id]["restart_script"])
        try:
            # Delete the metadata
            os.remove(restart_script_path)
        except OSError:
            msg = "Failed to remove restart script for %s" % patch_id
            LOG.exception(msg)
            raise PatchError(msg)

    def run_semantic_check(self, action, patch_list):
        if not os.path.exists(INITIAL_CONFIG_COMPLETE_FLAG):
            # Skip semantic checks if initial configuration isn't complete
            return

        # Pass the current patch state to the semantic check as a series of args
        patch_state_args = []
        for patch_id in list(self.patch_data.metadata):
            patch_state = '%s=%s' % (patch_id, self.patch_data.metadata[patch_id]["patchstate"])
            patch_state_args += ['-p', patch_state]

        # Run semantic checks, if any
        for patch_id in patch_list:
            semchk = os.path.join(semantics_dir, action, patch_id)

            if os.path.exists(semchk):
                try:
                    LOG.info("Running semantic check: %s", semchk)
                    subprocess.check_output([semchk] + patch_state_args,
                                            stderr=subprocess.STDOUT)
                    LOG.info("Semantic check %s passed", semchk)
                except subprocess.CalledProcessError as e:
                    msg = "Semantic check failed for %s:\n%s" % (patch_id, e.output)
                    LOG.exception(msg)
                    raise PatchFail(msg)

    def patch_import_api(self, patches):
        """
        Import patches
        :return:
        """
        msg_info = ""
        msg_warning = ""
        msg_error = ""

        # Refresh data, if needed
        self.base_pkgdata.loaddirs()

        # Protect against duplications
        patch_list = sorted(list(set(patches)))

        # First, make sure the specified files exist
        for patch in patch_list:
            if not os.path.isfile(patch):
                raise PatchFail("File does not exist: %s" % patch)

        try:
            if not os.path.exists(avail_dir):
                os.makedirs(avail_dir)
            if not os.path.exists(applied_dir):
                os.makedirs(applied_dir)
            if not os.path.exists(committed_dir):
                os.makedirs(committed_dir)
        except os.error:
            msg = "Failed to create directories"
            LOG.exception(msg)
            raise PatchFail(msg)

        msg = "Importing patches: %s" % ",".join(patch_list)
        LOG.info(msg)
        audit_log_info(msg)

        for patch in patch_list:
            msg = "Importing patch: %s" % patch
            LOG.info(msg)
            audit_log_info(msg)

            # Get the patch_id from the filename
            # and check to see if it's already imported
            (patch_id, ext) = os.path.splitext(os.path.basename(patch))
            if patch_id in self.patch_data.metadata:
                if self.patch_data.metadata[patch_id]["repostate"] == constants.APPLIED:
                    mdir = applied_dir
                elif self.patch_data.metadata[patch_id]["repostate"] == constants.COMMITTED:
                    msg = "%s is committed. Metadata not updated" % patch_id
                    LOG.info(msg)
                    msg_info += msg + "\n"
                    continue
                else:
                    mdir = avail_dir

                try:
                    thispatch = PatchFile.extract_patch(patch,
                                                        metadata_dir=mdir,
                                                        metadata_only=True,
                                                        existing_content=self.patch_data.contents[patch_id],
                                                        base_pkgdata=self.base_pkgdata)
                    self.patch_data.update_patch(thispatch)
                    msg = "%s is already imported. Updated metadata only" % patch_id
                    LOG.info(msg)
                    msg_info += msg + "\n"
                except PatchMismatchFailure:
                    msg = "Contents of %s do not match re-imported patch" % patch_id
                    LOG.exception(msg)
                    msg_error += msg + "\n"
                    continue
                except PatchValidationFailure as e:
                    msg = "Patch validation failed for %s" % patch_id
                    if str(e) is not None and str(e) != '':
                        msg += ":\n%s" % str(e)
                    LOG.exception(msg)
                    msg_error += msg + "\n"
                    continue
                except PatchFail:
                    msg = "Failed to import patch %s" % patch_id
                    LOG.exception(msg)
                    msg_error += msg + "\n"

                continue

            if ext != ".patch":
                msg = "File must end in .patch extension: %s" \
                      % os.path.basename(patch)
                LOG.exception(msg)
                msg_error += msg + "\n"
                continue

            try:
                thispatch = PatchFile.extract_patch(patch,
                                                    metadata_dir=avail_dir,
                                                    base_pkgdata=self.base_pkgdata)

                msg_info += "%s is now available\n" % patch_id
                self.patch_data.add_patch(thispatch)

                self.patch_data.metadata[patch_id]["repostate"] = constants.AVAILABLE
                if len(self.hosts) > 0:
                    self.patch_data.metadata[patch_id]["patchstate"] = constants.AVAILABLE
                else:
                    self.patch_data.metadata[patch_id]["patchstate"] = constants.UNKNOWN
            except PatchValidationFailure as e:
                msg = "Patch validation failed for %s" % patch_id
                if str(e) is not None and str(e) != '':
                    msg += ":\n%s" % str(e)
                LOG.exception(msg)
                msg_error += msg + "\n"
                continue
            except PatchFail:
                msg = "Failed to import patch %s" % patch_id
                LOG.exception(msg)
                msg_error += msg + "\n"
                continue

        return dict(info=msg_info, warning=msg_warning, error=msg_error)

    def patch_apply_api(self, patch_ids, **kwargs):
        """
        Apply patches, moving patches from available to applied and updating repo
        :return:
        """
        msg_info = ""
        msg_warning = ""
        msg_error = ""

        # Protect against duplications
        patch_list = sorted(list(set(patch_ids)))

        msg = "Applying patches: %s" % ",".join(patch_list)
        LOG.info(msg)
        audit_log_info(msg)

        if "--all" in patch_list:
            # Set patch_ids to list of all available patches
            # We're getting this list now, before we load the applied patches
            patch_list = []
            for patch_id in sorted(list(self.patch_data.metadata)):
                if self.patch_data.metadata[patch_id]["repostate"] == constants.AVAILABLE:
                    patch_list.append(patch_id)

            if len(patch_list) == 0:
                msg_info += "There are no available patches to be applied.\n"
                return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # First, verify that all specified patches exist
        id_verification = True
        for patch_id in patch_list:
            if patch_id not in self.patch_data.metadata:
                msg = "Patch %s does not exist" % patch_id
                LOG.error(msg)
                msg_error += msg + "\n"
                id_verification = False

        if not id_verification:
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # Order patches such that
        # If P2 requires P1
        # P3 requires P2
        # P4 requires P3
        # Apply order: [P1, P2, P3, P4]
        # Patch with lowest dependency gets applied first.
        patch_list = self.patch_apply_remove_order(patch_list, reverse=True)

        msg = "Patch Apply order: %s" % ",".join(patch_list)
        LOG.info(msg)
        audit_log_info(msg)

        # Check for patches that can't be applied during an upgrade
        upgrade_check = True
        for patch_id in patch_list:
            if self.patch_data.metadata[patch_id]["sw_version"] != SW_VERSION \
                    and self.patch_data.metadata[patch_id].get("apply_active_release_only") == "Y":
                msg = "%s cannot be applied in an upgrade" % patch_id
                LOG.error(msg)
                msg_error += msg + "\n"
                upgrade_check = False

        if not upgrade_check:
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # Next, check the patch dependencies
        # required_patches will map the required patch to the patches that need it
        required_patches = {}
        for patch_id in patch_list:
            for req_patch in self.patch_data.metadata[patch_id]["requires"]:
                # Ignore patches in the op set
                if req_patch in patch_list:
                    continue

                if req_patch not in required_patches:
                    required_patches[req_patch] = []

                required_patches[req_patch].append(patch_id)

        # Now verify the state of the required patches
        req_verification = True
        for req_patch, iter_patch_list in required_patches.items():
            if req_patch not in self.patch_data.metadata \
                    or self.patch_data.metadata[req_patch]["repostate"] == constants.AVAILABLE:
                msg = "%s is required by: %s" % (req_patch, ", ".join(sorted(iter_patch_list)))
                msg_error += msg + "\n"
                LOG.info(msg)
                req_verification = False

        if not req_verification:
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        if kwargs.get("skip-semantic") != "yes":
            self.run_semantic_check(constants.SEMANTIC_PREAPPLY, patch_list)

        # Start applying the patches
        for patch_id in patch_list:
            msg = "Applying patch: %s" % patch_id
            LOG.info(msg)
            audit_log_info(msg)

            if self.patch_data.metadata[patch_id]["repostate"] == constants.APPLIED \
               or self.patch_data.metadata[patch_id]["repostate"] == constants.COMMITTED:
                msg = "%s is already in the repo" % patch_id
                LOG.info(msg)
                msg_info += msg + "\n"
                continue

            patch_sw_version = self.patch_data.metadata[patch_id]["sw_version"]

            # STX R7.0 is the first version to support ostree
            # earlier formats will not have "base" and are unsupported
            if self.patch_data.contents[patch_id].get("base") is None:
                msg = "%s is an unsupported patch format" % patch_id
                LOG.info(msg)
                msg_info += msg + "\n"
                continue

            latest_commit = ""
            try:
                latest_commit = ostree_utils.get_feed_latest_commit(patch_sw_version)
            except OSTreeCommandFail:
                LOG.exception("Failure during commit consistency check for %s.", patch_id)

            if self.patch_data.contents[patch_id]["base"]["commit"] != latest_commit:
                msg = "The base commit %s for %s does not match the latest commit %s " \
                      "on this system." \
                      % (self.patch_data.contents[patch_id]["base"]["commit"],
                         patch_id,
                         latest_commit)
                LOG.info(msg)
                msg_info += msg + "\n"
                continue

            ostree_tar_filename = self.get_ostree_tar_filename(patch_sw_version, patch_id)

            # Create a temporary working directory
            tmpdir = tempfile.mkdtemp(prefix="patch_")

            # Save the current directory, so we can chdir back after
            orig_wd = os.getcwd()

            # Change to the tmpdir
            os.chdir(tmpdir)

            try:
                # Extract the software.tar
                tar = tarfile.open(ostree_tar_filename)
                tar.extractall()
                feed_ostree = "%s/rel-%s/ostree_repo" % (constants.FEED_OSTREE_BASE_DIR, patch_sw_version)
                # Copy extracted folders of software.tar to the feed ostree repo
                shutil.copytree(tmpdir, feed_ostree, dirs_exist_ok=True)
            except tarfile.TarError:
                msg = "Failed to extract the ostree tarball for %s" % patch_id
                LOG.exception(msg)
                raise OSTreeTarFail(msg)
            except shutil.Error:
                msg = "Failed to copy the ostree tarball for %s" % patch_id
                LOG.exception(msg)
                raise OSTreeTarFail(msg)
            finally:
                # Change back to original working dir
                os.chdir(orig_wd)
                shutil.rmtree(tmpdir, ignore_errors=True)

            try:
                # Move the metadata from avail to applied dir
                shutil.move("%s/%s-metadata.xml" % (avail_dir, patch_id),
                            "%s/%s-metadata.xml" % (applied_dir, patch_id))

                msg_info += "%s is now in the repo\n" % patch_id
            except shutil.Error:
                msg = "Failed to move the metadata for %s" % patch_id
                LOG.exception(msg)
                raise MetadataFail(msg)

            self.patch_data.metadata[patch_id]["repostate"] = constants.APPLIED
            if len(self.hosts) > 0:
                self.patch_data.metadata[patch_id]["patchstate"] = constants.PARTIAL_APPLY
            else:
                self.patch_data.metadata[patch_id]["patchstate"] = constants.UNKNOWN

            # Commit1 in patch metadata.xml file represents the latest commit
            # after this patch has been applied to the feed repo
            self.latest_feed_commit = self.patch_data.contents[patch_id]["commit1"]["commit"]

            self.hosts_lock.acquire()
            self.interim_state[patch_id] = list(self.hosts)
            self.hosts_lock.release()

        return dict(info=msg_info, warning=msg_warning, error=msg_error)

    def patch_apply_remove_order(self, patch_ids, reverse=False):
        # Protect against duplications
        patch_list = sorted(list(set(patch_ids)))

        # single patch
        if len(patch_list) == 1:
            return patch_list

        # versions of patches in the list don't match
        ver = None
        for patch_id in patch_list:
            if ver is None:
                ver = self.patch_data.metadata[patch_id]["sw_version"]
            elif self.patch_data.metadata[patch_id]["sw_version"] != ver:
                return None

        # Multiple patches with require dependencies
        highest_dependency = 0
        patch_remove_order = None
        patch_with_highest_dependency = None

        for patch_id in patch_list:
            dependency_list = self.get_patch_dependency_list(patch_id)
            if len(dependency_list) > highest_dependency:
                highest_dependency = len(dependency_list)
                patch_with_highest_dependency = patch_id
                patch_remove_order = dependency_list

        patch_list = [patch_with_highest_dependency] + patch_remove_order
        if reverse:
            patch_list.reverse()
        return patch_list

    def patch_remove_api(self, patch_ids, **kwargs):
        """
        Remove patches, moving patches from applied to available and updating repo
        :return:
        """
        msg_info = ""
        msg_warning = ""
        msg_error = ""
        remove_unremovable = False

        # First, verify that all specified patches exist
        id_verification = True
        for patch_id in sorted(list(set(patch_ids))):
            if patch_id not in self.patch_data.metadata:
                msg = "Patch %s does not exist" % patch_id
                LOG.error(msg)
                msg_error += msg + "\n"
                id_verification = False

        if not id_verification:
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        patch_list = self.patch_apply_remove_order(patch_ids)

        if patch_list is None:
            msg = "Patch list provided belongs to different software versions."
            LOG.error(msg)
            msg_error += msg + "\n"
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        msg = "Removing patches: %s" % ",".join(patch_list)
        LOG.info(msg)
        audit_log_info(msg)

        if kwargs.get("removeunremovable") == "yes":
            remove_unremovable = True

        # See if any of the patches are marked as unremovable
        unremovable_verification = True
        for patch_id in patch_list:
            if self.patch_data.metadata[patch_id].get("unremovable") == "Y":
                if remove_unremovable:
                    msg = "Unremovable patch %s being removed" % patch_id
                    LOG.warning(msg)
                    msg_warning += msg + "\n"
                else:
                    msg = "Patch %s is not removable" % patch_id
                    LOG.error(msg)
                    msg_error += msg + "\n"
                    unremovable_verification = False
            elif self.patch_data.metadata[patch_id]['repostate'] == constants.COMMITTED:
                msg = "Patch %s is committed and cannot be removed" % patch_id
                LOG.error(msg)
                msg_error += msg + "\n"
                unremovable_verification = False

        if not unremovable_verification:
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # Next, see if any of the patches are required by applied patches
        # required_patches will map the required patch to the patches that need it
        required_patches = {}
        for patch_iter in list(self.patch_data.metadata):
            # Ignore patches in the op set
            if patch_iter in patch_list:
                continue

            # Only check applied patches
            if self.patch_data.metadata[patch_iter]["repostate"] == constants.AVAILABLE:
                continue

            for req_patch in self.patch_data.metadata[patch_iter]["requires"]:
                if req_patch not in patch_list:
                    continue

                if req_patch not in required_patches:
                    required_patches[req_patch] = []

                required_patches[req_patch].append(patch_iter)

        if len(required_patches) > 0:
            for req_patch, iter_patch_list in required_patches.items():
                msg = "%s is required by: %s" % (req_patch, ", ".join(sorted(iter_patch_list)))
                msg_error += msg + "\n"
                LOG.info(msg)

            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        if kwargs.get("skipappcheck") != "yes":
            # Check application dependencies before removing
            required_patches = {}
            for patch_id in patch_list:
                for appname, iter_patch_list in self.app_dependencies.items():
                    if patch_id in iter_patch_list:
                        if patch_id not in required_patches:
                            required_patches[patch_id] = []
                        required_patches[patch_id].append(appname)

            if len(required_patches) > 0:
                for req_patch, app_list in required_patches.items():
                    msg = "%s is required by application(s): %s" % (req_patch, ", ".join(sorted(app_list)))
                    msg_error += msg + "\n"
                    LOG.info(msg)

                return dict(info=msg_info, warning=msg_warning, error=msg_error)

        if kwargs.get("skip-semantic") != "yes":
            self.run_semantic_check(constants.SEMANTIC_PREREMOVE, patch_list)

        for patch_id in patch_list:
            msg = "Removing patch: %s" % patch_id
            LOG.info(msg)
            audit_log_info(msg)

            if self.patch_data.metadata[patch_id]["repostate"] == constants.AVAILABLE:
                msg = "%s is not in the repo" % patch_id
                LOG.info(msg)
                msg_info += msg + "\n"
                continue

            patch_sw_version = self.patch_data.metadata[patch_id]["sw_version"]
            # 22.12 is the first version to support ostree
            # earlier formats will not have "base" and are unsupported
            # simply move them to 'available and skip to the next patch
            if self.patch_data.contents[patch_id].get("base") is None:
                msg = "%s is an unsupported patch format" % patch_id
                LOG.info(msg)
                msg_info += msg + "\n"

            else:
                # this is an ostree patch
                # Base commit is fetched from the patch metadata
                base_commit = self.patch_data.contents[patch_id]["base"]["commit"]
                feed_ostree = "%s/rel-%s/ostree_repo" % (constants.FEED_OSTREE_BASE_DIR, patch_sw_version)
                try:
                    # Reset the ostree HEAD
                    ostree_utils.reset_ostree_repo_head(base_commit, feed_ostree)

                    # Delete all commits that belong to this patch
                    for i in range(int(self.patch_data.contents[patch_id]["number_of_commits"])):
                        commit_to_delete = self.patch_data.contents[patch_id]["commit%s" % (i + 1)]["commit"]
                        ostree_utils.delete_ostree_repo_commit(commit_to_delete, feed_ostree)

                    # Update the feed ostree summary
                    ostree_utils.update_repo_summary_file(feed_ostree)

                except OSTreeCommandFail:
                    LOG.exception("Failure during patch remove for %s.", patch_id)

            # update metadata
            try:
                # Move the metadata to the available dir
                shutil.move("%s/%s-metadata.xml" % (applied_dir, patch_id),
                            "%s/%s-metadata.xml" % (avail_dir, patch_id))
                msg_info += "%s has been removed from the repo\n" % patch_id
            except shutil.Error:
                msg = "Failed to move the metadata for %s" % patch_id
                LOG.exception(msg)
                raise MetadataFail(msg)

            # update patchstate and repostate
            self.patch_data.metadata[patch_id]["repostate"] = constants.AVAILABLE
            if len(self.hosts) > 0:
                self.patch_data.metadata[patch_id]["patchstate"] = constants.PARTIAL_REMOVE
            else:
                self.patch_data.metadata[patch_id]["patchstate"] = constants.UNKNOWN

            # only update lastest_feed_commit if it is an ostree patch
            if self.patch_data.contents[patch_id].get("base") is not None:
                # Base Commit in patch metadata.xml file represents the latest commit
                # after this patch has been removed from the feed repo
                self.latest_feed_commit = self.patch_data.contents[patch_id]["base"]["commit"]

            self.hosts_lock.acquire()
            self.interim_state[patch_id] = list(self.hosts)
            self.hosts_lock.release()

        return dict(info=msg_info, warning=msg_warning, error=msg_error)

    def patch_delete_api(self, patch_ids):
        """
        Delete patches
        :return:
        """
        msg_info = ""
        msg_warning = ""
        msg_error = ""

        # Protect against duplications
        patch_list = sorted(list(set(patch_ids)))

        msg = "Deleting patches: %s" % ",".join(patch_list)
        LOG.info(msg)
        audit_log_info(msg)

        # Verify patches exist and are in proper state first
        id_verification = True
        for patch_id in patch_list:
            if patch_id not in self.patch_data.metadata:
                msg = "Patch %s does not exist" % patch_id
                LOG.error(msg)
                msg_error += msg + "\n"
                id_verification = False
                continue

            # Get the aggregated patch state, if possible
            patchstate = constants.UNKNOWN
            if patch_id in self.patch_data.metadata:
                patchstate = self.patch_data.metadata[patch_id]["patchstate"]

            if self.patch_data.metadata[patch_id]["repostate"] != constants.AVAILABLE or \
                    (patchstate != constants.AVAILABLE and patchstate != constants.UNKNOWN):
                msg = "Patch %s not in Available state" % patch_id
                LOG.error(msg)
                msg_error += msg + "\n"
                id_verification = False
                continue

        if not id_verification:
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # Handle operation
        for patch_id in patch_list:
            patch_sw_version = self.patch_data.metadata[patch_id]["sw_version"]

            # Need to support delete of older centos patches (metadata) from upgrades.

            # Delete ostree content if it exists.
            # RPM based patches (from upgrades) will not have ostree contents
            ostree_tar_filename = self.get_ostree_tar_filename(patch_sw_version, patch_id)
            if os.path.isfile(ostree_tar_filename):
                try:
                    os.remove(ostree_tar_filename)
                except OSError:
                    msg = "Failed to remove ostree tarball %s" % ostree_tar_filename
                    LOG.exception(msg)
                    raise OSTreeTarFail(msg)

            try:
                # Delete the metadata
                os.remove("%s/%s-metadata.xml" % (avail_dir, patch_id))
            except OSError:
                msg = "Failed to remove metadata for %s" % patch_id
                LOG.exception(msg)
                raise MetadataFail(msg)

            self.delete_restart_script(patch_id)
            self.patch_data.delete_patch(patch_id)
            msg = "%s has been deleted" % patch_id
            LOG.info(msg)
            msg_info += msg + "\n"

        return dict(info=msg_info, warning=msg_warning, error=msg_error)

    def patch_init_release_api(self, release):
        """
        Create an empty repo for a new release
        :return:
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

        self.patch_data.load_all_metadata(avail_dir, repostate=constants.AVAILABLE)
        self.patch_data.load_all_metadata(applied_dir, repostate=constants.APPLIED)
        self.patch_data.load_all_metadata(committed_dir, repostate=constants.COMMITTED)

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

            raise PatchFail(msg)

        return dict(info=msg_info, warning=msg_warning, error=msg_error)

    def patch_del_release_api(self, release):
        """
        Delete the repo and patches for second release
        :return:
        """
        msg_info = ""
        msg_warning = ""
        msg_error = ""

        msg = "Deleting repo and patches for: %s" % release
        LOG.info(msg)
        audit_log_info(msg)

        if release == SW_VERSION:
            msg = "Rejected: Requested release %s is running release" % release
            msg_error += msg + "\n"
            LOG.info(msg)
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # Delete patch XML files
        for patch_id in list(self.patch_data.metadata):
            if self.patch_data.metadata[patch_id]["sw_version"] != release:
                continue

            if self.patch_data.metadata[patch_id]["repostate"] == constants.APPLIED:
                mdir = applied_dir
            elif self.patch_data.metadata[patch_id]["repostate"] == constants.COMMITTED:
                mdir = committed_dir
            else:
                mdir = avail_dir

            for action in constants.SEMANTIC_ACTIONS:
                action_file = os.path.join(semantics_dir, action, patch_id)
                if not os.path.isfile(action_file):
                    continue

                try:
                    os.remove(action_file)
                except OSError:
                    msg = "Failed to remove semantic %s" % action_file
                    LOG.exception(msg)
                    raise SemanticFail(msg)

            try:
                # Delete the metadata
                os.remove("%s/%s-metadata.xml" % (mdir, patch_id))
            except OSError:
                msg = "Failed to remove metadata for %s" % patch_id
                LOG.exception(msg)

                # Refresh patch data
                self.patch_data = PatchData()
                self.patch_data.load_all_metadata(avail_dir, repostate=constants.AVAILABLE)
                self.patch_data.load_all_metadata(applied_dir, repostate=constants.APPLIED)
                self.patch_data.load_all_metadata(committed_dir, repostate=constants.COMMITTED)

                raise MetadataFail(msg)

        # Delete the packages dir
        package_dir[release] = "%s/%s" % (root_package_dir, release)
        if os.path.exists(package_dir[release]):
            try:
                shutil.rmtree(package_dir[release])
            except shutil.Error:
                msg = "Failed to delete package dir for %s" % release
                LOG.exception(msg)

        del package_dir[release]

        # Verify the release exists
        repo_dir[release] = "%s/rel-%s" % (repo_root_dir, release)
        if not os.path.exists(repo_dir[release]):
            # Nothing to do
            msg = "Patch repository for %s does not exist" % release
            msg_info += msg + "\n"
            LOG.info(msg)
            del repo_dir[release]

            # Refresh patch data
            self.patch_data = PatchData()
            self.patch_data.load_all_metadata(avail_dir, repostate=constants.AVAILABLE)
            self.patch_data.load_all_metadata(applied_dir, repostate=constants.APPLIED)
            self.patch_data.load_all_metadata(committed_dir, repostate=constants.COMMITTED)

            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # Delete the repo
        try:
            shutil.rmtree(repo_dir[release])
        except shutil.Error:
            msg = "Failed to delete repo for %s" % release
            LOG.exception(msg)

        del repo_dir[release]

        if self.base_pkgdata is not None and release in self.base_pkgdata.pkgs:
            del self.base_pkgdata.pkgs[release]

        # Refresh patch data
        self.patch_data = PatchData()
        self.patch_data.load_all_metadata(avail_dir, repostate=constants.AVAILABLE)
        self.patch_data.load_all_metadata(applied_dir, repostate=constants.APPLIED)
        self.patch_data.load_all_metadata(committed_dir, repostate=constants.COMMITTED)

        return dict(info=msg_info, warning=msg_warning, error=msg_error)

    def patch_query_what_requires(self, patch_ids):
        """
        Query the known patches to see which have dependencies on the specified patches
        :return:
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
            if patch_id not in self.patch_data.metadata:
                msg = "Patch %s does not exist" % patch_id
                LOG.error(msg)
                msg_error += msg + "\n"
                id_verification = False

        if not id_verification:
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        required_patches = {}
        for patch_iter in list(self.patch_data.metadata):
            for req_patch in self.patch_data.metadata[patch_iter]["requires"]:
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

    def patch_sync(self):
        # Increment the patch_op_counter here
        self.inc_patch_op_counter()

        self.patch_data_lock.acquire()
        # self.patch_data.load_all()
        self.check_patch_states()
        self.patch_data_lock.release()

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

    def patch_query_cached(self, **kwargs):
        query_state = None
        if "show" in kwargs:
            if kwargs["show"] == "available":
                query_state = constants.AVAILABLE
            elif kwargs["show"] == "applied":
                query_state = constants.APPLIED
            elif kwargs["show"] == "committed":
                query_state = constants.COMMITTED

        query_release = None
        if "release" in kwargs:
            query_release = kwargs["release"]

        results = {}
        self.patch_data_lock.acquire()
        if query_state is None and query_release is None:
            # Return everything
            results = self.patch_data.metadata
        else:
            # Filter results
            for patch_id, data in self.patch_data.metadata.items():
                if query_state is not None and data["repostate"] != query_state:
                    continue
                if query_release is not None and data["sw_version"] != query_release:
                    continue
                results[patch_id] = data
        self.patch_data_lock.release()

        return results

    def patch_query_specific_cached(self, patch_ids):
        audit_log_info("Patch show")

        results = {"metadata": {},
                   "contents": {},
                   "error": ""}

        self.patch_data_lock.acquire()

        for patch_id in patch_ids:
            if patch_id not in list(self.patch_data.metadata):
                results["error"] += "%s is unrecognized\n" % patch_id

        for patch_id, data in self.patch_data.metadata.items():
            if patch_id in patch_ids:
                results["metadata"][patch_id] = data
        for patch_id, data in self.patch_data.contents.items():
            if patch_id in patch_ids:
                results["contents"][patch_id] = data

        self.patch_data_lock.release()

        return results

    def get_dependencies(self, patch_ids, recursive):
        dependencies = set()
        patch_added = False

        self.patch_data_lock.acquire()

        # Add patches to workset
        for patch_id in sorted(patch_ids):
            dependencies.add(patch_id)
            patch_added = True

        while patch_added:
            patch_added = False
            for patch_id in sorted(dependencies):
                for req in self.patch_data.metadata[patch_id]["requires"]:
                    if req not in dependencies:
                        dependencies.add(req)
                        patch_added = recursive

        self.patch_data_lock.release()

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

        self.patch_data_lock.acquire()

        # Verify patch IDs
        for patch_id in sorted(patch_ids):
            if patch_id not in list(self.patch_data.metadata):
                errormsg = "%s is unrecognized\n" % patch_id
                LOG.info("patch_query_dependencies: %s", errormsg)
                results["error"] += errormsg
                failure = True
        self.patch_data_lock.release()

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
            if not os.path.exists(committed_dir):
                os.makedirs(committed_dir)
        except os.error:
            msg = "Failed to create %s" % committed_dir
            LOG.exception(msg)
            raise PatchFail(msg)

        failure = False
        recursive = True
        cleanup_files = set()
        results = {"info": "",
                   "error": ""}

        # Ensure there are only REL patches
        non_rel_list = []
        self.patch_data_lock.acquire()
        for patch_id in self.patch_data.metadata:
            if self.patch_data.metadata[patch_id]['status'] != constants.STATUS_RELEASED:
                non_rel_list.append(patch_id)
        self.patch_data_lock.release()

        if len(non_rel_list) > 0:
            errormsg = "A commit cannot be performed with non-REL status patches in the system:\n"
            for patch_id in non_rel_list:
                errormsg += "    %s\n" % patch_id
            LOG.info("patch_commit rejected: %s", errormsg)
            results["error"] += errormsg
            return results

        # Verify patch IDs
        self.patch_data_lock.acquire()
        for patch_id in sorted(patch_ids):
            if patch_id not in list(self.patch_data.metadata):
                errormsg = "%s is unrecognized\n" % patch_id
                LOG.info("patch_commit: %s", errormsg)
                results["error"] += errormsg
                failure = True
        self.patch_data_lock.release()

        if failure:
            LOG.info("patch_commit: Failed patch ID check")
            return results

        commit_list = self.get_dependencies(patch_ids, recursive)

        # Check patch states
        avail_list = []
        self.patch_data_lock.acquire()
        for patch_id in commit_list:
            if self.patch_data.metadata[patch_id]['patchstate'] != constants.APPLIED \
                    and self.patch_data.metadata[patch_id]['patchstate'] != constants.COMMITTED:
                avail_list.append(patch_id)
        self.patch_data_lock.release()

        if len(avail_list) > 0:
            errormsg = "The following patches are not applied and cannot be committed:\n"
            for patch_id in avail_list:
                errormsg += "    %s\n" % patch_id
            LOG.info("patch_commit rejected: %s", errormsg)
            results["error"] += errormsg
            return results

        with self.patch_data_lock:
            for patch_id in commit_list:
                # Fetch file paths that need to be cleaned up to
                # free patch storage disk space
                if self.patch_data.metadata[patch_id].get("restart_script"):
                    restart_script_path = "%s/%s" % \
                        (root_scripts_dir,
                         self.patch_data.metadata[patch_id]["restart_script"])
                    if os.path.exists(restart_script_path):
                        cleanup_files.add(restart_script_path)
                patch_sw_version = self.patch_data.metadata[patch_id]["sw_version"]
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
            applied_fname = os.path.join(applied_dir, metadata_fname)
            committed_fname = os.path.join(committed_dir, metadata_fname)
            if os.path.exists(applied_fname):
                try:
                    shutil.move(applied_fname, committed_fname)
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

        self.patch_data.load_all()

        results["info"] = "The patches have been committed."
        return results

    def query_host_cache(self):
        output = []

        self.hosts_lock.acquire()
        for nbr in list(self.hosts):
            host = self.hosts[nbr].get_dict()
            host["interim_state"] = False
            for patch_id in list(pc.interim_state):
                if nbr in pc.interim_state[patch_id]:
                    host["interim_state"] = True

            output.append(host)

        self.hosts_lock.release()

        return output

    def any_patch_host_installing(self):
        rc = False

        self.hosts_lock.acquire()
        for host in self.hosts.values():
            if host.state == constants.PATCH_AGENT_STATE_INSTALLING:
                rc = True
                break

        self.hosts_lock.release()

        return rc

    def copy_restart_scripts(self):
        with self.patch_data_lock:
            for patch_id in self.patch_data.metadata:
                if (self.patch_data.metadata[patch_id]["patchstate"] in
                    [constants.PARTIAL_APPLY, constants.PARTIAL_REMOVE]) \
                   and self.patch_data.metadata[patch_id].get("restart_script"):
                    try:
                        restart_script_name = self.patch_data.metadata[patch_id]["restart_script"]
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
                        raise PatchError(msg)
                elif self.patch_data.metadata[patch_id].get("restart_script"):
                    try:
                        restart_script_name = self.patch_data.metadata[patch_id]["restart_script"]
                        restart_script_path = "%s/%s" \
                            % (constants.PATCH_SCRIPTS_STAGING_DIR, restart_script_name)
                        if os.path.exists(restart_script_path):
                            os.remove(restart_script_path)
                            msg = "Removing restart script for %s" % patch_id
                            LOG.info(msg)
                    except shutil.Error:
                        msg = "Failed to delete the restart script for %s" % patch_id
                        LOG.exception(msg)

    def patch_host_install(self, host_ip, force, async_req=False):
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
                    raise PatchError("Host IP (%s) not in table" % ip)
            except Exception:
                self.hosts_lock.release()
                msg = "Unknown host specified: %s" % host_ip
                msg_error += msg + "\n"
                LOG.error("Error in host-install: %s", msg)
                return dict(info=msg_info, warning=msg_warning, error=msg_error)

        msg = "Running host-install for %s (%s), force=%s, async_req=%s" % (host_ip, ip, force, async_req)
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
            msg = "Patch installation request sent to %s." % self.hosts[ip].hostname
            msg_info += msg + "\n"
            LOG.info("host-install async_req: %s", msg)
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
                    msg = "Patch installation was successful on %s." % self.hosts[ip].hostname
                    msg_info += msg + "\n"
                    LOG.info("host-install: %s", msg)
                elif self.hosts[ip].install_reject_reason:
                    msg = "Patch installation rejected by %s. %s" % (
                        self.hosts[ip].hostname,
                        self.hosts[ip].install_reject_reason)
                    msg_error += msg + "\n"
                    LOG.error("Error in host-install: %s", msg)
                else:
                    msg = "Patch installation failed on %s." % self.hosts[ip].hostname
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
                    raise PatchError("Host IP (%s) not in table" % ip)
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

    def is_applied(self, patch_ids):
        all_applied = True

        self.patch_data_lock.acquire()

        for patch_id in patch_ids:
            if patch_id not in self.patch_data.metadata:
                all_applied = False
                break

            if self.patch_data.metadata[patch_id]["patchstate"] != constants.APPLIED:
                all_applied = False
                break

        self.patch_data_lock.release()

        return all_applied

    def is_available(self, patch_ids):
        all_available = True

        self.patch_data_lock.acquire()

        for patch_id in patch_ids:
            if patch_id not in self.patch_data.metadata:
                all_available = False
                break

            if self.patch_data.metadata[patch_id]["patchstate"] != \
                    constants.AVAILABLE:
                all_available = False
                break

        self.patch_data_lock.release()

        return all_available

    def report_app_dependencies(self, patch_ids, **kwargs):
        """
        Handle report of application dependencies
        """
        if "app" not in kwargs:
            raise PatchInvalidRequest

        appname = kwargs.get("app")

        LOG.info("Handling app dependencies report: app=%s, patch_ids=%s",
                 appname, ','.join(patch_ids))

        self.patch_data_lock.acquire()

        if len(patch_ids) == 0:
            if appname in self.app_dependencies:
                del self.app_dependencies[appname]
        else:
            self.app_dependencies[appname] = patch_ids

        try:
            tmpfile, tmpfname = tempfile.mkstemp(
                prefix=app_dependency_basename,
                dir=constants.PATCH_STORAGE_DIR)

            os.write(tmpfile, json.dumps(self.app_dependencies).encode())
            os.close(tmpfile)

            os.rename(tmpfname, app_dependency_filename)
        except Exception:
            LOG.exception("Failed in report_app_dependencies")
            raise PatchFail("Internal failure")
        finally:
            self.patch_data_lock.release()

        return True

    def query_app_dependencies(self):
        """
        Query application dependencies
        """
        self.patch_data_lock.acquire()

        data = self.app_dependencies

        self.patch_data_lock.release()

        return dict(data)


# The wsgiref.simple_server module has an error handler that catches
# and prints any exceptions that occur during the API handling to stderr.
# This means the patching sys.excepthook handler that logs uncaught
# exceptions is never called, and those exceptions are lost.
#
# To get around this, we're subclassing the simple_server.ServerHandler
# in order to replace the handle_error method with a custom one that
# logs the exception instead, and will set a global flag to shutdown
# the server and reset.
#
class MyServerHandler(simple_server.ServerHandler):
    def handle_error(self):
        LOG.exception('An uncaught exception has occurred:')
        if not self.headers_sent:
            self.result = self.error_output(self.environ, self.start_response)
            self.finish_response()
        global keep_running
        keep_running = False


def get_handler_cls():
    cls = simple_server.WSGIRequestHandler

    # old-style class doesn't support super
    class MyHandler(cls, object):
        def address_string(self):
            # In the future, we could provide a config option to allow reverse DNS lookup
            return self.client_address[0]

        # Overload the handle function to use our own MyServerHandler
        def handle(self):
            """Handle a single HTTP request"""

            self.raw_requestline = self.rfile.readline()
            if not self.parse_request():  # An error code has been sent, just exit
                return

            handler = MyServerHandler(
                self.rfile, self.wfile, self.get_stderr(), self.get_environ()
            )
            handler.request_handler = self  # pylint: disable=attribute-defined-outside-init
            handler.run(self.server.get_app())

    return MyHandler


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
                server_class=server_class,
                handler_class=get_handler_cls())

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
    def __init__(self):
        threading.Thread.__init__(self)
        # LOG.info ("Initializing Authenticated API thread")
        self.wsgi = None

    def run(self):
        host = CONF.auth_api_bind_ip
        port = CONF.auth_api_port
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
                host, port,
                auth_app.VersionSelectorApplication(),
                server_class=server_class,
                handler_class=get_handler_cls())

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
        global pc
        global thread_death

        # LOG.info ("In Main thread")

        try:
            sock_in = pc.setup_socket()

            while sock_in is None:
                # Check every thirty seconds?
                # Once we've got a conf file, tied into packstack,
                # we'll get restarted when the file is updated,
                # and this should be unnecessary.
                time.sleep(30)
                sock_in = pc.setup_socket()

            # Ok, now we've got our socket. Let's start with a hello!
            pc.socket_lock.acquire()

            hello = PatchMessageHello()
            hello.send(pc.sock_out)

            hello_agent = PatchMessageHelloAgent()
            hello_agent.send(pc.sock_out)

            pc.socket_lock.release()

            # Send hello every thirty seconds
            hello_timeout = time.time() + 30.0
            remaining = 30

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

                inputs = [pc.sock_in] + agent_query_conns
                outputs = []

                # LOG.info("Running select, remaining=%d", remaining)
                rlist, wlist, xlist = select.select(inputs, outputs, inputs, remaining)

                if (len(rlist) == 0 and
                        len(wlist) == 0 and
                        len(xlist) == 0):
                    # Timeout hit
                    pc.audit_socket()

                # LOG.info("Checking sockets")
                for s in rlist:
                    data = ''
                    addr = None
                    msg = None

                    if s == pc.sock_in:
                        # Receive from UDP
                        pc.socket_lock.acquire()
                        data, addr = s.recvfrom(1024)
                        pc.socket_lock.release()
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

                    if msg is None:
                        msg = messages.PatchMessage()

                    msg.decode(msgdata)
                    if s == pc.sock_in:
                        msg.handle(pc.sock_out, addr)
                    else:
                        msg.handle(s, addr)

                    # We can drop the connection after a query response
                    if msg.msgtype == messages.PATCHMSG_QUERY_DETAILED_RESP and s != pc.sock_in:
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
                if remaining <= 0 or remaining > 30:
                    hello_timeout = time.time() + 30.0
                    remaining = 30

                    pc.socket_lock.acquire()

                    hello = PatchMessageHello()
                    hello.send(pc.sock_out)

                    hello_agent = PatchMessageHelloAgent()
                    hello_agent.send(pc.sock_out)

                    pc.socket_lock.release()

                    # Age out neighbours
                    pc.controller_neighbours_lock.acquire()
                    nbrs = list(pc.controller_neighbours)
                    for n in nbrs:
                        # Age out controllers after 2 minutes
                        if pc.controller_neighbours[n].get_age() >= 120:
                            LOG.info("Aging out controller %s from table", n)
                            del pc.controller_neighbours[n]
                    pc.controller_neighbours_lock.release()

                    pc.hosts_lock.acquire()
                    nbrs = list(pc.hosts)
                    for n in nbrs:
                        # Age out hosts after 1 hour
                        if pc.hosts[n].get_age() >= 3600:
                            LOG.info("Aging out host %s from table", n)
                            del pc.hosts[n]
                            for patch_id in list(pc.interim_state):
                                if n in pc.interim_state[patch_id]:
                                    pc.interim_state[patch_id].remove(n)

                    pc.hosts_lock.release()
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

    global pc
    pc = PatchController()

    LOG.info("launching")
    api_thread = PatchControllerApiThread()
    auth_api_thread = PatchControllerAuthApiThread()
    main_thread = PatchControllerMainThread()

    api_thread.start()
    auth_api_thread.start()
    main_thread.start()

    thread_death.wait()
    global keep_running
    keep_running = False

    api_thread.join()
    auth_api_thread.join()
    main_thread.join()
