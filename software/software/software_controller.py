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

import software.ostree_utils as ostree_utils
from software.api import app
from software.authapi import app as auth_app
from software.base import PatchService
from software.exceptions import MetadataFail
from software.exceptions import OSTreeCommandFail
from software.exceptions import OSTreeTarFail
from software.exceptions import SoftwareError
from software.exceptions import SoftwareFail
from software.exceptions import ReleaseInvalidRequest
from software.exceptions import ReleaseValidationFailure
from software.exceptions import ReleaseMismatchFailure
from software.software_functions import configure_logging
from software.software_functions import BasePackageData
from software.software_functions import available_dir
from software.software_functions import unavailable_dir
from software.software_functions import deploying_start_dir
from software.software_functions import deploying_host_dir
from software.software_functions import deploying_activate_dir
from software.software_functions import deploying_complete_dir
from software.software_functions import deployed_dir
from software.software_functions import aborting_dir
from software.software_functions import removing_dir
from software.software_functions import committed_dir
from software.software_functions import PatchFile
from software.software_functions import package_dir
from software.software_functions import repo_dir
from software.software_functions import root_scripts_dir
from software.software_functions import semantics_dir
from software.software_functions import SW_VERSION
from software.software_functions import LOG
from software.software_functions import audit_log_info
from software.software_functions import patch_dir
from software.software_functions import repo_root_dir
from software.software_functions import ReleaseData

import software.config as cfg
import software.utils as utils

import software.messages as messages
import software.constants as constants

from tsconfig.tsconfig import INITIAL_CONFIG_COMPLETE_FLAG

CONF = oslo_cfg.CONF

pidfile_path = "/var/run/patch_controller.pid"

sc = None
state_file = "%s/.controller.state" % constants.SOFTWARE_STORAGE_DIR
app_dependency_basename = "app_dependencies.json"
app_dependency_filename = "%s/%s" % (constants.SOFTWARE_STORAGE_DIR, app_dependency_basename)

insvc_patch_restart_controller = "/run/software/.restart.software-controller"

stale_hosts = []
pending_queries = []

thread_death = None
keep_running = True

DEPLOY_STATE_METADATA_DIR_DICT = \
    {
        constants.AVAILABLE: available_dir,
        constants.UNAVAILABLE: unavailable_dir,
        constants.DEPLOYING_START: deploying_start_dir,
        constants.DEPLOYING_HOST: deploying_host_dir,
        constants.DEPLOYING_ACTIVATE: deploying_activate_dir,
        constants.DEPLOYING_COMPLETE: deploying_complete_dir,
        constants.DEPLOYED: deployed_dir,
        constants.REMOVING: removing_dir,
        constants.ABORTING: aborting_dir,
        constants.COMMITTED: committed_dir,
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
                    raise SoftwareFail(msg)

    def software_release_upload(self, release_files):
        """
        Upload software release files
        :return:
        """
        msg_info = ""
        msg_warning = ""
        msg_error = ""

        # Refresh data, if needed
        self.base_pkgdata.loaddirs()

        # Protect against duplications
        release_list = sorted(set(release_files))

        # First, make sure the specified files exist
        for release_file in release_list:
            if not os.path.isfile(release_file):
                raise SoftwareFail("File does not exist: %s" % release_file)

        try:
            if not os.path.exists(available_dir):
                os.makedirs(available_dir)
            if not os.path.exists(unavailable_dir):
                os.makedirs(unavailable_dir)
            if not os.path.exists(deploying_start_dir):
                os.makedirs(deploying_start_dir)
            if not os.path.exists(deploying_host_dir):
                os.makedirs(deploying_host_dir)
            if not os.path.exists(deploying_activate_dir):
                os.makedirs(deploying_activate_dir)
            if not os.path.exists(deploying_complete_dir):
                os.makedirs(deploying_complete_dir)
            if not os.path.exists(deployed_dir):
                os.makedirs(deployed_dir)
            if not os.path.exists(removing_dir):
                os.makedirs(removing_dir)
            if not os.path.exists(aborting_dir):
                os.makedirs(aborting_dir)
            if not os.path.exists(committed_dir):
                os.makedirs(committed_dir)
        except os.error:
            msg = "Failed to create directories"
            LOG.exception(msg)
            raise SoftwareFail(msg)

        msg = "Uploading files: %s" % ",".join(release_list)
        LOG.info(msg)
        audit_log_info(msg)

        for release_file in release_list:
            msg = "Uploading release: %s" % release_file
            LOG.info(msg)
            audit_log_info(msg)

            # Get the release_id from the filename
            # and check to see if it's already uploaded
            # todo(abailey) We should not require the ID as part of the file
            (release_id, ext) = os.path.splitext(os.path.basename(release_file))
            if release_id in self.release_data.metadata:
                if self.release_data.metadata[release_id]["state"] != constants.AVAILABLE:
                    msg = "%s is being or has already been deployed." % release_id
                    LOG.info(msg)
                    msg_info += msg + "\n"
                    continue
                elif self.release_data.metadata[release_id]["state"] == constants.COMMITTED:
                    msg = "%s is committed. Metadata not updated" % release_id
                    LOG.info(msg)
                    msg_info += msg + "\n"
                    continue
                else:
                    mdir = available_dir

                try:
                    # todo(abailey) PatchFile / extract_patch should be renamed
                    thisrelease = PatchFile.extract_patch(release_file,
                                                          metadata_dir=mdir,
                                                          metadata_only=True,
                                                          existing_content=self.release_data.contents[release_id],
                                                          base_pkgdata=self.base_pkgdata)
                    self.release_data.update_release(thisrelease)
                    msg = "%s is already uploaded. Updated metadata only" % release_id
                    LOG.info(msg)
                    msg_info += msg + "\n"
                except ReleaseMismatchFailure:
                    msg = "Contents of %s do not match re-uploaded release" % release_id
                    LOG.exception(msg)
                    msg_error += msg + "\n"
                    continue
                except ReleaseValidationFailure as e:
                    msg = "Release validation failed for %s" % release_id
                    if str(e) is not None and str(e) != '':
                        msg += ":\n%s" % str(e)
                    LOG.exception(msg)
                    msg_error += msg + "\n"
                    continue
                except SoftwareFail:
                    msg = "Failed to upload release %s" % release_id
                    LOG.exception(msg)
                    msg_error += msg + "\n"

                continue

            if ext not in [".patch", ".tar", ".iso"]:
                msg = "File: %s must end in .patch .tar or .iso" \
                      % os.path.basename(release_file)
                LOG.exception(msg)
                msg_error += msg + "\n"
                continue

            try:
                thisrelease = PatchFile.extract_patch(release_file,
                                                      metadata_dir=available_dir,
                                                      base_pkgdata=self.base_pkgdata)

                msg_info += "%s is now uploaded\n" % release_id
                self.release_data.add_release(thisrelease)

                if len(self.hosts) > 0:
                    self.release_data.metadata[release_id]["state"] = constants.AVAILABLE
                else:
                    self.release_data.metadata[release_id]["state"] = constants.UNKNOWN
            except ReleaseValidationFailure as e:
                msg = "Release validation failed for %s" % release_id
                if str(e) is not None and str(e) != '':
                    msg += ":\n%s" % str(e)
                LOG.exception(msg)
                msg_error += msg + "\n"
                continue
            except SoftwareFail:
                msg = "Failed to upload release %s" % release_id
                LOG.exception(msg)
                msg_error += msg + "\n"
                continue

        return dict(info=msg_info, warning=msg_warning, error=msg_error)

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
        :return:
        """
        msg_info = ""
        msg_warning = ""
        msg_error = ""

        # Protect against duplications
        release_list = sorted(list(set(release_ids)))

        msg = "Deleting releases: %s" % ",".join(release_list)
        LOG.info(msg)
        audit_log_info(msg)

        # Verify releases exist and are in proper state first
        id_verification = True
        for release_id in release_list:
            if release_id not in self.release_data.metadata:
                msg = "Release %s does not exist" % release_id
                LOG.error(msg)
                msg_error += msg + "\n"
                id_verification = False
                continue

            deploystate = self.release_data.metadata[release_id]["state"]
            ignore_states = [constants.AVAILABLE, constants.DEPLOYING_START,
                             constants.DEPLOYING_ACTIVATE, constants.DEPLOYING_COMPLETE,
                             constants.DEPLOYING_HOST, constants.DEPLOYED]

            if deploystate not in ignore_states:
                msg = "Release %s is active and cannot be deleted." % release_id
                LOG.error(msg)
                msg_error += msg + "\n"
                id_verification = False
                continue

        if not id_verification:
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # Handle operation
        for release_id in release_list:
            release_sw_version = self.release_data.metadata[release_id]["sw_version"]

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

            try:
                # Delete the metadata
                deploystate = self.release_data.metadata[release_id]["state"]
                metadata_dir = DEPLOY_STATE_METADATA_DIR_DICT[deploystate]
                os.remove("%s/%s-metadata.xml" % (metadata_dir, release_id))
            except OSError:
                msg = "Failed to remove metadata for %s" % release_id
                LOG.exception(msg)
                raise MetadataFail(msg)

            self.delete_restart_script(release_id)
            self.release_data.delete_release(release_id)
            msg = "%s has been deleted" % release_id
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

        self.release_data.load_all_metadata(available_dir, state=constants.AVAILABLE)
        self.release_data.load_all_metadata(unavailable_dir, state=constants.UNAVAILABLE)
        self.release_data.load_all_metadata(deploying_start_dir, state=constants.DEPLOYING_START)
        self.release_data.load_all_metadata(deploying_host_dir, state=constants.DEPLOYING_HOST)
        self.release_data.load_all_metadata(deploying_activate_dir, state=constants.DEPLOYING_ACTIVATE)
        self.release_data.load_all_metadata(deploying_complete_dir, state=constants.DEPLOYING_COMPLETE)
        self.release_data.load_all_metadata(deployed_dir, state=constants.DEPLOYED)
        self.release_data.load_all_metadata(removing_dir, state=constants.REMOVING)
        self.release_data.load_all_metadata(aborting_dir, state=constants.ABORTING)
        self.release_data.load_all_metadata(committed_dir, state=constants.COMMITTED)

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
            if not os.path.exists(committed_dir):
                os.makedirs(committed_dir)
        except os.error:
            msg = "Failed to create %s" % committed_dir
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
                patch_sw_version = self.release_data.metadata[patch_id]["sw_version"]
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
            deployed_fname = os.path.join(deployed_dir, metadata_fname)
            committed_fname = os.path.join(committed_dir, metadata_fname)
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

    def software_deploy_start_api(self, deployment: str, **kwargs) -> dict:
        """
        Start deployment by applying the changes to the feed ostree
        return: dict of info, warning and error messages
        """
        msg_info = ""
        msg_warning = ""
        msg_error = ""

        # We need to verify that the software release exists
        if deployment not in self.release_data.metadata:
            msg = "Software release version corresponding to the specified deployment " \
                  "%s does not exist" % deployment
            LOG.error(msg)
            msg_error += msg + "\n"
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # Identify if this is apply or remove operation
        # todo(jcasteli) Remove once the logic to include major release version
        # in release list is implemented
        running_sw_version = "23.09.0"
        # Commit1 in release metadata.xml file represents the latest commit
        for release_id in sorted(list(self.release_data.metadata)):
            if self.latest_feed_commit == self.release_data.contents[release_id]["commit1"]["commit"]:
                running_sw_version = self.release_data.metadata[release_id]["sw_version"]
                LOG.info("Running software version: %s", running_sw_version)

        higher = utils.compare_release_version(self.release_data.metadata[deployment]["sw_version"],
                                               running_sw_version)

        if higher is None:
            msg_error += "The software version format for this release is not correct.\n"
            return dict(info=msg_info, warning=msg_warning, error=msg_error)
        elif higher:
            operation = "apply"
        else:
            operation = "remove"

        # If releases are such that R2 requires R1
        # R3 requires R2
        # R4 requires R3
        # And current running release is R2
        # And command issued is "software deploy start R4"
        # Order for apply operation: [R3, R4]
        # Order for remove operation: [R3]
        if operation == "apply":
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
                except OSTreeCommandFail:
                    LOG.exception("Failure during commit consistency check for %s.", release)

                if self.release_data.contents[release]["base"]["commit"] != latest_commit:
                    msg = "The base commit %s for %s does not match the latest commit %s " \
                          "on this system." \
                          % (self.release_data.contents[release]["base"]["commit"],
                             release,
                             latest_commit)
                    LOG.info(msg)
                    msg_info += msg + "\n"
                    continue

                ostree_tar_filename = self.get_ostree_tar_filename(release_sw_version, release)

                # Create a temporary working directory
                tmpdir = tempfile.mkdtemp(prefix="deployment_")

                # Save the current directory, so we can chdir back after
                orig_wd = os.getcwd()

                # Change to the tmpdir
                os.chdir(tmpdir)

                try:
                    # Extract the software.tar
                    tar = tarfile.open(ostree_tar_filename)
                    tar.extractall()
                    feed_ostree = "%s/rel-%s/ostree_repo" % (constants.FEED_OSTREE_BASE_DIR, release_sw_version)
                    # Copy extracted folders of software.tar to the feed ostree repo
                    shutil.copytree(tmpdir, feed_ostree, dirs_exist_ok=True)
                except tarfile.TarError:
                    msg = "Failed to extract the ostree tarball for %s" % release
                    LOG.exception(msg)
                    raise OSTreeTarFail(msg)
                except shutil.Error:
                    msg = "Failed to copy the ostree tarball for %s" % release
                    LOG.exception(msg)
                    raise OSTreeTarFail(msg)
                finally:
                    # Change back to original working dir
                    os.chdir(orig_wd)
                    shutil.rmtree(tmpdir, ignore_errors=True)

                try:
                    # Move the release metadata to deploying dir
                    deploystate = self.release_data.metadata[release]["state"]
                    metadata_dir = DEPLOY_STATE_METADATA_DIR_DICT[deploystate]
                    shutil.move("%s/%s-metadata.xml" % (metadata_dir, release),
                                "%s/%s-metadata.xml" % (deploying_start_dir, release))

                    msg_info += "%s is now in the repo\n" % release
                except shutil.Error:
                    msg = "Failed to move the metadata for %s" % release
                    LOG.exception(msg)
                    raise MetadataFail(msg)

                if len(self.hosts) > 0:
                    self.release_data.metadata[release]["state"] = constants.DEPLOYING_START
                else:
                    self.release_data.metadata[release]["state"] = constants.UNKNOWN

                # Commit1 in release metadata.xml file represents the latest commit
                # after this release has been applied to the feed repo
                self.latest_feed_commit = self.release_data.contents[release]["commit1"]["commit"]

                with self.hosts_lock:
                    self.interim_state[release] = list(self.hosts)

        elif operation == "remove":
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
                                "%s/%s-metadata.xml" % (removing_dir, release))
                    deploystate = self.release_data.metadata[deployment]["state"]
                    metadata_dir = DEPLOY_STATE_METADATA_DIR_DICT[deploystate]
                    shutil.move("%s/%s-metadata.xml" % (metadata_dir, deployment),
                                "%s/%s-metadata.xml" % (deploying_start_dir, deployment))
                    msg_info += "%s has been removed from the repo\n" % release
                except shutil.Error:
                    msg = "Failed to move the metadata for %s" % release
                    LOG.exception(msg)
                    raise MetadataFail(msg)

                # update state
                if len(self.hosts) > 0:
                    self.release_data.metadata[release]["state"] = constants.REMOVING
                    self.release_data.metadata[deployment]["state"] = constants.DEPLOYING_START
                else:
                    self.release_data.metadata[release]["state"] = constants.UNKNOWN
                    self.release_data.metadata[deployment]["state"] = constants.UNKNOWN

                # only update lastest_feed_commit if it is an ostree patch
                if self.release_data.contents[release].get("base") is not None:
                    # Base Commit in this release's metadata.xml file represents the latest commit
                    # after this release has been removed from the feed repo
                    self.latest_feed_commit = self.release_data.contents[release]["base"]["commit"]

                with self.hosts_lock:
                    self.interim_state[release] = list(self.hosts)

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
                        shutil.move("%s/%s-metadata.xml" % (deploying_activate_dir, release_id),
                                    "%s/%s-metadata.xml" % (deploying_complete_dir, release_id))
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
                        shutil.move("%s/%s-metadata.xml" % (removing_dir, release_id),
                                    "%s/%s-metadata.xml" % (available_dir, release_id))
                        msg_info += "%s is available\n" % release_id
                    except shutil.Error:
                        msg = "Failed to move the metadata for %s" % release_id
                        LOG.exception(msg)
                        raise MetadataFail(msg)
                elif self.release_data.metadata[release_id]["state"] == constants.DEPLOYING_COMPLETE:
                    self.release_data.metadata[release_id]["state"] = constants.DEPLOYED

                    try:
                        shutil.move("%s/%s-metadata.xml" % (deploying_complete_dir, release_id),
                                    "%s/%s-metadata.xml" % (deployed_dir, release_id))
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
                shutil.move("%s/%s-metadata.xml" % (deploying_host_dir, release),
                            "%s/%s-metadata.xml" % (deploying_activate_dir, release))
            except shutil.Error:
                msg = "Failed to move the metadata for %s" % release
                LOG.exception(msg)
                raise MetadataFail(msg)

            msg_info += "Deployment for %s has been activated\n" % release
            self.release_data.metadata[release]["state"] = constants.DEPLOYING_ACTIVATE

        return dict(info=msg_info, warning=msg_warning, error=msg_error)

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
                        shutil.move("%s/%s-metadata.xml" % (deploying_start_dir, release),
                                    "%s/%s-metadata.xml" % (deploying_host_dir, release))
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
                    shutil.move("%s/%s-metadata.xml" % (deploying_start_dir, release),
                                "%s/%s-metadata.xml" % (deploying_host_dir, release))
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

    def is_completed(self, release_ids):
        all_completed = True

        with self.release_data_lock:

            for release_id in release_ids:
                if release_id not in self.release_data.metadata:
                    all_completed = False
                    break

                if self.release_data.metadata[release_id]["state"] != constants.DEPLOYED:
                    all_completed = False
                    break

        return all_completed

    def is_uploaded(self, release_ids):
        all_uploaded = True

        with self.release_data_lock:

            for release_id in release_ids:
                if release_id not in self.release_data.metadata:
                    all_uploaded = False
                    break

                if self.release_data.metadata[release_id]["state"] != \
                        constants.AVAILABLE:
                    all_uploaded = False
                    break

        return all_uploaded

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
        global sc
        global thread_death

        # LOG.info ("In Main thread")

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

                inputs = [sc.sock_in] + agent_query_conns
                outputs = []

                # LOG.info("Running select, remaining=%d", remaining)
                rlist, wlist, xlist = select.select(inputs, outputs, inputs, remaining)

                if (len(rlist) == 0 and
                        len(wlist) == 0 and
                        len(xlist) == 0):
                    # Timeout hit
                    sc.audit_socket()

                # LOG.info("Checking sockets")
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
                if remaining <= 0 or remaining > 30:
                    hello_timeout = time.time() + 30.0
                    remaining = 30

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
