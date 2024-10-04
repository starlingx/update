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
from packaging import version
import select
import sh
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from wsgiref import simple_server

from fm_api import fm_api
from fm_api import constants as fm_constants

from oslo_config import cfg as oslo_cfg

import software.apt_utils as apt_utils
import software.ostree_utils as ostree_utils
from software.api import app
from software.authapi import app as auth_app
from software.constants import INSTALL_LOCAL_FLAG
from software.states import DEPLOY_STATES
from software.states import DEPLOY_HOST_STATES
from software.base import PatchService
from software.dc_utils import get_subcloud_groupby_version
from software.deploy_state import require_deploy_state
from software.exceptions import APTOSTreeCommandFail
from software.exceptions import HostNotFound
from software.exceptions import InternalError
from software.exceptions import MetadataFail
from software.exceptions import UpgradeNotSupported
from software.exceptions import OSTreeCommandFail
from software.exceptions import OSTreeTarFail
from software.exceptions import SoftwareError
from software.exceptions import SoftwareFail
from software.exceptions import ReleaseInvalidRequest
from software.exceptions import ReleaseValidationFailure
from software.exceptions import ReleaseIsoDeleteFailure
from software.exceptions import SoftwareServiceError
from software.exceptions import InvalidOperation
from software.exceptions import HostIpNotFound
from software.release_data import reload_release_data
from software.release_data import get_SWReleaseCollection
from software.software_functions import collect_current_load_for_hosts
from software.software_functions import copy_pxeboot_update_file
from software.software_functions import create_deploy_hosts
from software.software_functions import deploy_host_validations
from software.software_functions import validate_host_deploy_order
from software.software_functions import parse_release_metadata
from software.software_functions import configure_logging
from software.software_functions import mount_iso_load
from software.software_functions import unmount_iso_load
from software.software_functions import read_upgrade_support_versions
from software.software_functions import get_to_release_from_metadata_file
from software.software_functions import BasePackageData
from software.software_functions import PatchFile
from software.software_functions import package_dir
from software.software_functions import repo_dir
from software.software_functions import root_scripts_dir
from software.software_functions import set_host_target_load
from software.software_functions import SW_VERSION
from software.software_functions import LOG
from software.software_functions import audit_log_info
from software.software_functions import repo_root_dir
from software.software_functions import is_deploy_state_in_sync
from software.software_functions import is_deployment_in_progress
from software.software_functions import get_release_from_patch
from software.software_functions import clean_up_deployment_data
from software.software_functions import run_deploy_clean_up_script
from software.release_state import ReleaseState
from software.deploy_host_state import DeployHostState
from software.deploy_state import DeployState
from software.release_verify import verify_files
import software.config as cfg
import software.utils as utils
from software.sysinv_utils import get_k8s_ver
from software.sysinv_utils import is_system_controller
from software.sysinv_utils import update_host_sw_version
from software.sysinv_utils import are_all_hosts_unlocked_and_online
from software.sysinv_utils import get_system_info

from software.db.api import get_instance

import software.messages as messages
import software.constants as constants
from software import states

from tsconfig.tsconfig import INITIAL_CONFIG_COMPLETE_FLAG
from tsconfig.tsconfig import VOLATILE_CONTROLLER_CONFIG_COMPLETE
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
system_mode = None

# Limit socket blocking to 5 seconds to allow for thread to shutdown
api_socket_timeout = 5.0


def is_simplex():
    global system_mode
    if system_mode is None:
        _, system_mode = get_system_info()

    return system_mode == constants.SYSTEM_MODE_SIMPLEX


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
        if sc.install_local:
            return
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

        # NOTE(bqian) sync_from_nbr returns "False" if sync operations failed.
        # need to think of reattempt to deal w/ the potential failure.
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
        sock.sendto(str.encode(message), (sc.agent_address, cfg.agent_port))
        if not sc.install_local:
            local_hostname = utils.ip_to_versioned_localhost(cfg.agent_mcast_group)
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
        sock.sendto(str.encode(message), (sc.agent_address, cfg.agent_port))
        if not sc.install_local:
            local_hostname = utils.ip_to_versioned_localhost(cfg.agent_mcast_group)
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
        self.major_release = None
        self.commit_id = None

    def encode(self):
        global sc
        messages.PatchMessage.encode(self)
        self.message['force'] = self.force
        self.message['major_release'] = self.major_release
        self.message['commit_id'] = self.commit_id

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
        self.reboot_required = False

    def decode(self, data):
        messages.PatchMessage.decode(self, data)
        if 'status' in data:
            self.status = data['status']
        if 'reject_reason' in data:
            self.reject_reason = data['reject_reason']
        if 'reboot_required' in data:
            self.reboot_required = data['reboot_required']

    def encode(self):
        # Nothing to add, so just call the super class
        messages.PatchMessage.encode(self)

    def handle(self, sock, addr):
        LOG.info("Handling install resp from %s", addr[0])
        global sc

        dbapi = get_instance()
        deploy = dbapi.get_deploy_all()
        if len(deploy) == 0:
            LOG.info("No deploy in progress. ignore install resp from %s", addr[0])
            return
        deploy = deploy[0]

        sc.hosts_lock.acquire()
        try:
            # NOTE(bqian) seems like trying to tolerate a failure situation
            # that a host is directed to install a patch but during the installation
            # software-controller-daemon gets restarted
            # should remove the sc.hosts which is in memory volatile storage and replaced with
            # permanent deploy-host entity
            ip = addr[0]
            if ip not in sc.hosts:
                sc.hosts[ip] = AgentNeighbour(ip)

            sc.hosts[ip].install_status = self.status
            sc.hosts[ip].install_pending = False
            sc.hosts[ip].install_reject_reason = self.reject_reason
            hostname = sc.hosts[ip].hostname
        finally:
            sc.hosts_lock.release()

        deploy_host_state = DeployHostState(hostname)
        if self.status:
            deploying = ReleaseState(release_state=states.DEPLOYING)
            if deploying.is_major_release_deployment():
                # For major release deployment, update sysinv ihost.sw_version
                # so that right manifest can be generated.
                sw_version = utils.get_major_release_version(deploy.get("to_release"))
                msg = f"Update {hostname} to {sw_version}"
                LOG.info(msg)
                try:
                    update_host_sw_version(hostname, sw_version)
                except Exception:
                    # Failed a step, fail the host deploy for reattempt
                    deploy_host_state.deploy_failed()
                    return

            deploy_host_state.deployed()
            if self.reboot_required:
                sc.manage_software_alarm(fm_constants.FM_ALARM_ID_USM_DEPLOY_HOST_SUCCESS_RR,
                                         fm_constants.FM_ALARM_STATE_SET,
                                         "%s=%s" % (fm_constants.FM_ENTITY_TYPE_HOST, hostname))
        else:
            deploy_host_state.deploy_failed()
            sc.manage_software_alarm(fm_constants.FM_ALARM_ID_USM_DEPLOY_HOST_FAILURE,
                                     fm_constants.FM_ALARM_STATE_SET,
                                     "%s=%s" % (fm_constants.FM_ENTITY_TYPE_HOST, hostname))

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
        if sc.install_local:
            return
        self.encode()
        message = json.dumps(self.message)
        sock.sendto(str.encode(message), (sc.controller_address, cfg.controller_port))


class SoftwareMessageDeployStateUpdate(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_DEPLOY_STATE_UPDATE)
        self.data = None

    def decode(self, data):
        messages.PatchMessage.decode(self, data)
        self.data = data

    def encode(self):
        global sc
        messages.PatchMessage.encode(self)
        filesystem_data = utils.get_software_filesystem_data()
        deploys_state = {"deploy_host": filesystem_data.get("deploy_host", {}),
                         "deploy": filesystem_data.get("deploy", {})}
        self.message["deploy_state"] = deploys_state

    def handle(self, sock, addr):
        global sc
        if sc.mgmt_ip == addr[0]:
            # update from localhost, ignore
            return

        filesystem_data = utils.get_software_filesystem_data()
        synced_filesystem_data = utils.get_synced_software_filesystem_data()

        actual_state = {"deploy_host": filesystem_data.get("deploy_host", {}),
                        "deploy": filesystem_data.get("deploy", {})}

        synced_state = {"deploy_host": synced_filesystem_data.get("deploy_host", {}),
                        "deploy": synced_filesystem_data.get("deploy", {})}

        peer_state = {"deploy_host": self.data.get("deploy_state").get("deploy_host", {}),
                      "deploy": self.data.get("deploy_state").get("deploy", {})}

        result = "diverged"
        if actual_state == peer_state:
            result = messages.MSG_ACK_SUCCESS
        elif actual_state == synced_state:
            result = messages.MSG_ACK_SUCCESS
            utils.save_to_json_file(constants.SOFTWARE_JSON_FILE, peer_state)

        if result == messages.MSG_ACK_SUCCESS:
            utils.save_to_json_file(constants.SYNCED_SOFTWARE_JSON_FILE, peer_state)

        resp = SoftwareMessageDeployStateUpdateAck()
        resp.send(sock, result)

    def send(self, sock):
        global sc
        self.encode()
        message = json.dumps(self.message)
        sock.sendto(str.encode(message), (sc.controller_address, cfg.controller_port))


class SoftwareMessageDeployStateUpdateAck(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_DEPLOY_STATE_UPDATE_ACK)
        self.peer_state_data = {}

    def decode(self, data):
        messages.PatchMessage.decode(self, data)
        self.peer_state_data = data

    def encode(self, result):  # pylint: disable=arguments-differ
        messages.PatchMessage.encode(self)
        synced_data = utils.get_synced_software_filesystem_data()
        self.message["result"] = result
        self.message["deploy_state"] = synced_data

    def handle(self, sock, addr):
        global sc
        if sc.mgmt_ip == addr[0]:
            # update from localhost, ignore
            return

        if self.peer_state_data["result"] == messages.MSG_ACK_SUCCESS:
            LOG.debug("Peer controller is synced with value: %s",
                      self.peer_state_data["deploy_state"])
            utils.save_to_json_file(constants.SYNCED_SOFTWARE_JSON_FILE,
                                    self.peer_state_data["deploy_state"])
        else:
            LOG.error("Peer controller deploy state has diverged.")

    def send(self, sock, result):
        self.encode(result)
        message = json.dumps(self.message)
        sock.sendto(str.encode(message), (sc.controller_address, cfg.controller_port))


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

        valid_agents = ['deploy-start', 'deploy-activate', 'deploy-activate-rollback', 'admin']
        if 'agent' in data:
            self.agent = data['agent']
        else:
            self.agent = 'unknown'

        if self.agent not in valid_agents:
            # ignore msg from unknown senders
            LOG.info("%s received from unknown agent %s" %
                     (messages.PATCHMSG_DEPLOY_STATE_CHANGED, self.agent))
            self.valid = False

        valid_state = {
            DEPLOY_STATES.START_DONE.value: DEPLOY_STATES.START_DONE,
            DEPLOY_STATES.START_FAILED.value: DEPLOY_STATES.START_FAILED,
            DEPLOY_STATES.ACTIVATE_FAILED.value: DEPLOY_STATES.ACTIVATE_FAILED,
            DEPLOY_STATES.ACTIVATE_DONE.value: DEPLOY_STATES.ACTIVATE_DONE,
            DEPLOY_STATES.ACTIVATE_ROLLBACK_DONE.value: DEPLOY_STATES.ACTIVATE_ROLLBACK_DONE,
            DEPLOY_STATES.ACTIVATE_ROLLBACK_FAILED.value: DEPLOY_STATES.ACTIVATE_ROLLBACK_FAILED,
            DEPLOY_STATES.HOST_FAILED.value: DEPLOY_STATES.HOST_FAILED
        }
        if 'deploy-state' in data and data['deploy-state']:
            deploy_state = data['deploy-state']
            if deploy_state in valid_state:
                self.deploy_state = valid_state[deploy_state]
                LOG.info("%s received from %s with deploy-state %s" %
                         (messages.PATCHMSG_DEPLOY_STATE_CHANGED, self.agent, deploy_state))
            else:
                self.valid = False
                LOG.error("%s received from %s with invalid deploy-state %s" %
                          (messages.PATCHMSG_DEPLOY_STATE_CHANGED, self.agent, deploy_state))

        if 'hostname' in data and data['hostname']:
            self.hostname = data['hostname']

        if 'host-state' in data and data['host-state']:
            host_state = states.DEPLOY_HOST_STATES(data['host-state'])
            if host_state not in states.VALID_HOST_DEPLOY_STATE:
                LOG.error("%s received from %s with invalid host-state %s" %
                          (messages.PATCHMSG_DEPLOY_STATE_CHANGED, self.agent, host_state))
                self.valid = False
            else:
                self.host_state = host_state

        if self.valid:
            self.valid = (bool(self.host_state and self.hostname) != bool(self.deploy_state))

        if not self.valid:
            LOG.error("%s received from %s as invalid %s" %
                      (messages.PATCHMSG_DEPLOY_STATE_CHANGED, self.agent, data))

    def handle(self, sock, addr):
        global sc
        if not self.valid:
            # nothing to do
            return

        if self.deploy_state:
            LOG.info("Received deploy state changed to %s, agent %s" %
                     (self.deploy_state, self.agent))
            try:
                sc.deploy_state_changed(self.deploy_state)
            except Exception as e:
                LOG.error("Deploy state change failed: %s" % str(e))
        else:
            LOG.info("Received %s deploy host state changed to %s, agent %s" %
                     (self.hostname, self.host_state, self.agent))
            sc.host_deploy_state_changed(self.hostname, self.host_state)

        sock.sendto(str.encode("OK"), addr)

    def send(self, sock):
        global sc
        LOG.info("sending sync req")
        self.encode()
        message = json.dumps(self.message)
        sock.sendto(str.encode(message), (sc.controller_address, cfg.controller_port))


class SoftwareMessageDeployDeleteCleanupReq(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_DEPLOY_DELETE_CLEANUP_REQ)
        self.ip = None
        self.major_release = None

    def encode(self):
        messages.PatchMessage.encode(self)
        self.message["major_release"] = self.major_release

    def handle(self, sock, addr):
        LOG.error("Should not get here")

    def send(self, sock):
        global sc
        LOG.info("Sending deploy delete cleanup request to all nodes.")
        self.encode()
        message = json.dumps(self.message)
        sock.sendto(str.encode(message), (sc.agent_address, cfg.agent_port))


class SoftwareMessageDeployDeleteCleanupResp(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_DEPLOY_DELETE_CLEANUP_RESP)
        self.success = None

    def decode(self, data):
        messages.PatchMessage.decode(self, data)
        if 'success' in data:
            self.success = data['success']

    def encode(self):
        # Nothing to add, so just call the super class
        messages.PatchMessage.encode(self)

    def handle(self, sock, addr):
        ip = addr[0]
        LOG.info("Handling deploy delete cleanup resp from %s", ip)
        global sc
        if self.success:
            LOG.info("Host %s sucessfully executed deploy delete "
                     "cleanup tasks." % sc.hosts[ip].hostname)
            return
        LOG.error("Host %s failed executing deploy delete "
                  "cleanup tasks." % sc.hosts[ip].hostname)

    def send(self, sock):  # pylint: disable=unused-argument
        LOG.error("Should not get here")


class PatchController(PatchService):
    def __init__(self):
        PatchService.__init__(self)

        # Locks
        self.socket_lock = threading.RLock()
        self.controller_neighbours_lock = threading.RLock()
        self.hosts_lock = threading.RLock()

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
        reload_release_data()
        try:
            self.latest_feed_commit = ostree_utils.get_feed_latest_commit(SW_VERSION)
        except OSTreeCommandFail:
            LOG.exception("Failure to fetch the feed ostree latest log while "
                          "initializing Patch Controller")
            self.latest_feed_commit = None

        self.check_patch_states()
        self.base_pkgdata = BasePackageData()

        # This is for alarm cache. It will be used to store the last raising alarm id
        self.usm_alarm = {constants.LAST_IN_SYNC: False}
        self.hostname = socket.gethostname()
        self.fm_api = fm_api.FaultAPIs()

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

        self.register_deploy_state_change_listeners()

    def _state_changed_sync(self, *args):  # pylint: disable=unused-argument
        if is_simplex():
            # ensure the in-sync state for SX
            # treat it as SX for deploy before bootstrap
            shutil.copyfile(constants.SOFTWARE_JSON_FILE, constants.SYNCED_SOFTWARE_JSON_FILE)
        else:
            self._update_state_to_peer()

    def register_deploy_state_change_listeners(self):
        # data sync listener
        DeployState.register_event_listener(self._state_changed_sync)
        DeployHostState.register_event_listener(self._state_changed_sync)

        DeployHostState.register_event_listener(DeployState.host_deploy_updated)
        DeployState.register_event_listener(ReleaseState.deploy_updated)
        DeployState.register_event_listener(self.create_clean_up_deployment_alarm)

    @property
    def release_collection(self):
        swrc = get_SWReleaseCollection()
        return swrc

    def update_config(self):
        cfg.read_config()

        if self.port != cfg.controller_port:
            self.port = cfg.controller_port

        # Loopback interface does not support multicast messaging, therefore
        # revert to using unicast messaging when configured against the
        # loopback device
        if self.pre_bootstrap:
            mgmt_ip = utils.gethostbyname(constants.PREBOOTSTRAP_HOSTNAME)
            self.mcast_addr = None
            self.controller_address = mgmt_ip
            self.agent_address = mgmt_ip
        elif cfg.get_mgmt_iface() == constants.LOOPBACK_INTERFACE_NAME:
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

        # NOTE(bqian) sync_from_nbr returns "False" if sync operations failed.
        # need to think of reattempt to deal w/ the potential failure.
        self.sync_from_nbr(host)

    def sync_from_nbr(self, host):
        # Sync the software repo
        host_url = utils.ip_to_url(host)
        try:
            output = subprocess.check_output(["rsync",
                                              "-acv",
                                              "--delete",
                                              "--exclude", "tmp",
                                              "--exclude", "software.json",
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
                        feed_repo = "%s/%s/ostree_repo/" % (constants.FEED_OSTREE_BASE_DIR, rel_dir)
                        if not os.path.isdir(feed_repo):
                            LOG.info("Skipping feed dir %s", feed_repo)
                            continue
                        LOG.info("Syncing %s", feed_repo)
                        output = subprocess.check_output(["ostree",
                                                          "--repo=%s" % feed_repo,
                                                          "pull",
                                                          "--depth=-1",
                                                          "--mirror",
                                                          "starlingx"],
                                                         stderr=subprocess.STDOUT)
                        output = subprocess.check_output(["ostree",
                                                          "summary",
                                                          "--update",
                                                          "--repo=%s" % feed_repo],
                                                         stderr=subprocess.STDOUT)
            LOG.info("Synced to mate feed via ostree pull: %s", output)
        except subprocess.CalledProcessError:
            LOG.error("Failed to sync feed repo between controllers: %s", output)
            return False

        self.read_state_file()

        self.interim_state = {}
        reload_release_data()
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

        # NOTE(bqian) How is this loop relevant?
        # all_insevc_patching equals not required_reboot in deploy entity
        # see software_entity.
        for ip in (ip for ip in list(self.hosts) if self.hosts[ip].out_of_date):
            for release in self.release_collection.iterate_releases():
                # NOTE(bqian) below consolidates DEPLOYING_START to DEPLOYING
                # all_insevc_patching equals not required_reboot in deploy entity
                # see software_entity.
                # also apparently it is a bug to check release state as it will
                # end up return default (true) when it is not DEPLOYING_START for
                # example, checking during removal.
                if release.reboot_required and release.state == states.DEPLOYING:
                    self.allow_insvc_patching = False
        # NOTE(bqian) this function looks very buggy, should probably be rewritten

    def get_release_dependency_list(self, release_id):
        """
        Returns a list of software releases that are required by this release.
        Example: If R5 requires R4 and R1, R4 requires R3 and R1, R3 requires R1
                 then for input param release_id='R5', it will return ['R4', 'R1', 'R3']
        :param release: The software release ID
        """

        def get_dependencies(release_id, visited):
            release = self.release_collection.get_release_by_id(release_id)
            if release is None:
                error = f"Not all required releases are uploaded, missing {release_id}"
                raise SoftwareServiceError(error=error)

            dependencies = []
            for req_release in release.requires_release_ids:
                if req_release not in visited:
                    visited.add(req_release)
                    dependencies.append(req_release)
                    dependencies.extend(get_dependencies(req_release, visited))
            return dependencies

        return get_dependencies(release_id, set())

    def get_release_required_by_list(self, release_id):
        """
        Returns a list of software releases that require this release.
        Example: If R3 requires R2 and R2 requires R1,
                 then for input param release_id='R1', it will return ['R3', 'R2']
        :param release_id: The software release id
        """

        def get_required_by(release_id, visited):
            required_by_list = []
            for req_release in self.release_collection.iterate_releases():
                if release_id in req_release.requires_release_ids and req_release.id not in visited:
                    visited.add(req_release.id)
                    required_by_list.append(req_release.id)
                    required_by_list.extend(get_required_by(req_release.id, visited))
            return required_by_list

        return get_required_by(release_id, set())

    def get_ostree_tar_filename(self, patch_sw_version, patch_id):
        '''
        Returns the path of the ostree tarball
        :param patch_sw_version: sw version this patch must be applied to
        :param patch_id: The patch ID
        '''
        ostree_tar_dir = package_dir[patch_sw_version]
        ostree_tar_filename = "%s/%s-software.tar" % (ostree_tar_dir, patch_id)
        return ostree_tar_filename

    def delete_install_script(self, patch_id):
        '''
        Deletes the install scripts associated with the patch
        :param patch_id: The patch ID
        '''
        release = self.release_collection.get_release_by_id(patch_id)
        pre_install = release.pre_install
        post_install = release.post_install

        pre_install_path = None
        post_install_path = None
        if pre_install:
            pre_install_path = "%s/%s_%s" % (root_scripts_dir, patch_id, pre_install)
        if post_install:
            post_install_path = "%s/%s_%s" % (root_scripts_dir, patch_id, post_install)
        try:
            # Delete the install scripts
            if pre_install_path:
                os.remove(pre_install_path)
            if post_install_path:
                os.remove(post_install_path)
        except OSError:
            msg = "Failed to remove the install script for %s" % patch_id
            LOG.exception(msg)
            raise SoftwareError(msg)

    def run_semantic_check(self, action, patch_list):
        if not os.path.exists(INITIAL_CONFIG_COMPLETE_FLAG):
            # Skip semantic checks if initial configuration isn't complete
            return

        # Pass the current patch state to the semantic check as a series of args
        patch_state_args = []
        for release in self.release_collection.iterate_releases():
            patch_state = '%s=%s' % (release.id, release.state)
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

    def software_install_local_api(self, delete):
        """
        Enable patch installation to local controller
        :return: dict of info, warning and error messages
        """
        msg_info = ""
        msg_warning = ""
        msg_error = ""

        dbapi = get_instance()
        deploy = dbapi.get_deploy_all()
        if len(deploy) > 0:
            msg_info += "Software Deploy operation is in progress.\n"
            msg_info += "Please finish current deploy before modifying install local mode.\n"
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        if os.path.isfile(INSTALL_LOCAL_FLAG) and delete:
            # Remove install local flag if enabled
            if os.path.isfile(INSTALL_LOCAL_FLAG):
                try:
                    os.remove(INSTALL_LOCAL_FLAG)
                except Exception:
                    LOG.exception("Failed to clear %s flag", INSTALL_LOCAL_FLAG)
            msg = "Software deployment in local installation mode is stopped"
            msg_info += f"{msg}.\n"
            LOG.info(msg)
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        elif not delete and not os.path.isfile(INSTALL_LOCAL_FLAG):
            open(INSTALL_LOCAL_FLAG, 'a').close()
            msg = "Software deployment in local installation mode is started"
            msg_info += f"{msg}.\n"
            LOG.info(msg)
            return dict(info=msg_info, warning=msg_warning, error=msg_error)
        else:
            mode = 'disabled' if delete else 'enabled'
            msg_info += f"Software deployment in local installation mode is already {mode}.\n"
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

        # Only system controller can have 2 major releases (N+1 and N-1)
        max_releases = max_major_releases + 1 if is_system_controller() else max_major_releases
        if len(major_releases) >= max_releases:
            msg = f"Major releases {major_releases} have already been uploaded{' in system controller' if is_system_controller() else ''}. " + \
                f"Max major releases is {max_releases}"
            LOG.info(msg)
            raise SoftwareServiceError(error=msg)

    def _run_load_import(self, from_release, to_release, iso_mount_dir, upgrade_files):
        """
        Run load and import
        :param from_release: From release
        :param to_release: To release
        :param iso_mount_dir: ISO mount directory
        :return: info, warning, error messages, dict of release metadata info
        """
        local_info = ""
        local_warning = ""
        local_error = ""
        release_meta_info = {}

        def run_script_command(cmd):
            LOG.info("Running load import command: %s", " ".join(cmd))
            result = subprocess.run(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, check=True, text=True)
            return (result.stdout, None) if result.returncode == 0 else (None, result.stdout)

        # Check if usm_load_import script exists in the iso
        has_usm_load_import_script = os.path.isfile(os.path.join(
            iso_mount_dir, 'upgrades', 'software-deploy', constants.USM_LOAD_IMPORT_SCRIPT))

        if has_usm_load_import_script:
            # usm_load_import script is found. This iso supports upgrade from USM
            try:
                # Copy iso /upgrades/software-deploy/ to /opt/software/rel-<rel>/bin/
                to_release_bin_dir = os.path.join(
                    constants.SOFTWARE_STORAGE_DIR, ("rel-%s" % to_release), "bin")
                if os.path.exists(to_release_bin_dir):
                    shutil.rmtree(to_release_bin_dir)
                shutil.copytree(os.path.join(iso_mount_dir, "upgrades",
                                constants.SOFTWARE_DEPLOY_FOLDER), to_release_bin_dir)

                # Run usm_load_import script
                import_script = os.path.join(to_release_bin_dir, constants.USM_LOAD_IMPORT_SCRIPT)
                load_import_cmd = [
                    str(import_script),
                    f"--from-release={from_release}",
                    f"--to-release={to_release}",
                    f"--iso-dir={iso_mount_dir}"
                ]

                load_import_info, load_import_error = run_script_command(load_import_cmd)
                local_info += load_import_info or ""
                local_error += load_import_error or ""

                # Copy metadata.xml to /opt/software/rel-<rel>/
                to_file = os.path.join(constants.SOFTWARE_STORAGE_DIR,
                                       ("rel-%s" % to_release), "metadata.xml")
                metadata_file = os.path.join(iso_mount_dir, "upgrades", "metadata.xml")
                shutil.copyfile(metadata_file, to_file)

                # Update the release metadata
                # metadata files have been copied over to the metadata/available directory
                reload_release_data()
                LOG.info("Updated release metadata for %s", to_release)

                release_meta_info = self.get_release_meta_info(
                    to_release, iso_mount_dir, upgrade_files)

                return local_info, local_warning, local_error, release_meta_info

            except Exception as e:
                LOG.exception("Error occurred while running load import: %s", str(e))
                raise

        # At this step, usm_load_import script is not found in the iso
        # Therefore, we run the local usm_load_import script which supports importing the N-1 iso
        # that doesn't support USM feature.
        # This is the special case where *only* DC system controller can import this iso
        # TODO(ShawnLi): remove the code below when this special case is not supported
        try:
            local_import_script = os.path.join(
                "/usr/sbin/software-deploy/", constants.USM_LOAD_IMPORT_SCRIPT)

            load_import_cmd = [local_import_script,
                               "--from-release=%s" % from_release,
                               "--to-release=%s" % to_release,
                               "--iso-dir=%s" % iso_mount_dir,
                               "--is-usm-iso=False"]

            load_import_info, load_import_error = run_script_command(load_import_cmd)
            local_info += load_import_info or ""
            local_error += load_import_error or ""

            # Update the release metadata
            # metadata files have been copied over to the metadata/available directory
            reload_release_data()
            LOG.info("Updated release metadata for %s", to_release)

            release_meta_info = {
                os.path.basename(upgrade_files[constants.ISO_EXTENSION]): {
                    "id": constants.RELEASE_GA_NAME % to_release,
                    "sw_release": to_release,
                },
                os.path.basename(upgrade_files[constants.SIG_EXTENSION]): {
                    "id": None,
                    "sw_release": None,
                }
            }
            return local_info, local_warning, local_error, release_meta_info

        except Exception as e:
            LOG.exception("Error occurred while running local load import script: %s", str(e))
            raise

    def get_release_meta_info(self, to_release, iso_mount_dir, upgrade_files) -> dict:
        """
        Get release metadata information from metadata.xml
        :param iso_mount_dir: ISO mount directory
        :param upgrade_files: dict of upgrade files
        :return: dict of release metadata info
        """

        # Get release metadata
        # NOTE(bqian) to_release is sw_version (MM.mm), the path isn't correct
        # also prepatched iso needs to be handled.
        # should go through the release_data to find the latest release of major release
        # to_release
        abs_stx_release_metadata_file = os.path.join(
            iso_mount_dir, 'upgrades', f"{constants.RELEASE_GA_NAME % to_release}-metadata.xml")
        all_release_meta_info = parse_release_metadata(abs_stx_release_metadata_file)
        return {
            os.path.basename(upgrade_files[constants.ISO_EXTENSION]): {
                "id": all_release_meta_info.get("id"),
                "sw_release": all_release_meta_info.get("sw_version"),
            },
            os.path.basename(upgrade_files[constants.SIG_EXTENSION]): {
                "id": None,
                "sw_release": None,
            }
        }

    def _clean_up_load_import(self, iso_mount_dir, to_release, iso_file, is_import_completed):
        """
        Clean up load and import
        :param iso_mount_dir: ISO mount directory
        :param to_release: To release
        :param iso_file: ISO file
        """
        # Unmount the iso file
        if iso_mount_dir:
            unmount_iso_load(iso_mount_dir)
            LOG.info("Unmounted iso file %s", iso_file)

        # remove upload leftover in case of failure
        if to_release and not is_import_completed:
            to_release_dir = os.path.join(constants.SOFTWARE_STORAGE_DIR, "rel-%s" % to_release)
            shutil.rmtree(to_release_dir, ignore_errors=True)

    def _clean_up_inactive_load_import(self, release_version):
        """
        Clean up inactive load and import
        :param release_version: Release version
        """
        dirs_to_remove = [
            f"{constants.DC_VAULT_PLAYBOOK_DIR}/{release_version}",
            f"{constants.DC_VAULT_LOADS_DIR}/{release_version}"
        ]

        for dir_path in dirs_to_remove:
            if os.path.exists(dir_path):
                shutil.rmtree(dir_path, ignore_errors=True)
                LOG.info("Removed %s", dir_path)

        # TODO(ShawnLi): the code below is to only clean up those files that were created in usm_laod_import script
        # delete 22.12 iso metadata in /opt/software/metadata/unavailable
        # delete 22.12 patches in /opt/software/metadata/committed
        file_patterns = [
            (states.UNAVAILABLE_DIR, fr'^([a-zA-Z]+)-({release_version})-metadata\.xml$'),
            (states.COMMITTED_DIR, fr'^([a-zA-Z]+)_({release_version})_PATCH_([0-9]+)-metadata\.xml$')
        ]

        # Remove files matching patterns
        for directory, pattern in file_patterns:
            matched_file_names = utils.find_file_by_regex(directory, pattern)
            for filename in matched_file_names:
                abs_filename = os.path.join(directory, filename)
                try:
                    os.remove(abs_filename)
                    LOG.info("Removed: %s", abs_filename)
                except OSError:
                    LOG.warning("Failed to remove: %s", abs_filename)

    def _process_upload_upgrade_files(
            self, from_release, to_release, iso_mount_dir, supported_from_releases, upgrade_files):
        """
        Process the uploaded upgrade files
        :param from_release: From release
        :param to_release: To release
        :param iso_mount_dir: ISO mount directory
        :param supported_from_releases: List of supported releases
        :param upgrade_files: dict of upgrade files
        :return: info, warning, error messages, dict of release metadata info
        """

        # validate this major release upload
        self.major_release_upload_check()

        try:
            # Validate that the current release is supported to upgrade to the new release
            supported_versions = [v.get("version") for v in supported_from_releases]
            if SW_VERSION not in supported_versions:
                raise UpgradeNotSupported("Current release %s not supported to upgrade to %s"
                                          % (SW_VERSION, to_release))
            # Run usm_load_import script
            LOG.info("Starting load import from %s", upgrade_files[constants.ISO_EXTENSION])
            return self._run_load_import(from_release, to_release, iso_mount_dir, upgrade_files)
        except Exception as e:
            LOG.exception("Error occurred while processing upload upgrade files: %s", str(e))
            raise

    def _process_inactive_upgrade_files(
            self, from_release, to_release, iso_mount_dir, upgrade_files):
        """
        Process the uploaded inactive upgrade files, aka N-1 release
        :param from_release: From release
        :param to_release: To release
        :param iso_mount_dir: ISO mount directory
        :param upgrade_files: dict of upgrade files
        :return: info, warning, error messages, dict of release metadata info
        """

        # validate this major release upload
        self.major_release_upload_check()

        to_release_maj_ver = utils.get_major_release_version(to_release)

        try:

            # Validate the N-1 release from the iso file is supported to upgrade to the current N release
            current_upgrade_supported_versions = read_upgrade_support_versions(
                "/usr/rootdirs/opt/")
            supported_versions = [v.get("version") for v in current_upgrade_supported_versions]

            # to_release is N-1 release in here
            if to_release_maj_ver not in supported_versions:
                raise UpgradeNotSupported(
                    "ISO file release version %s not supported to upgrade to %s" %
                    (to_release_maj_ver, SW_VERSION))

            # iso validation completed
            LOG.info("Starting load import from %s", upgrade_files[constants.ISO_EXTENSION])

            # from_release is set to None when uploading N-1 load
            return self._run_load_import(from_release, to_release, iso_mount_dir, upgrade_files)

        except Exception as e:
            LOG.exception("Error occurred while processing inactive upgrade files: %s", str(e))
            raise

    def _checkout_commit_to_dc_vault_playbook_dir(self, release_version):
        """
        Checkout commit to dc-vault playbook dir
        :param release_version: release version
        :return: None
        """
        dc_vault_playbook_dir = f"{constants.DC_VAULT_PLAYBOOK_DIR}/{release_version}"

        os.makedirs(dc_vault_playbook_dir, exist_ok=True)
        ostree_repo = os.path.join(constants.FEED_DIR,
                                   "rel-%s/ostree_repo" % release_version)

        try:
            latest_commit = ostree_utils.get_feed_latest_commit(release_version)
            LOG.info("Getting latest commit for %s: %s", release_version, latest_commit)
        except OSTreeCommandFail as e:
            LOG.exception("Error occurred while getting latest commit for %s: %s",
                          release_version, str(e))
            raise

        try:
            LOG.info("Checking out commit %s to %s", latest_commit, dc_vault_playbook_dir)
            ostree_utils.checkout_commit_to_dir(
                ostree_repo, latest_commit, dc_vault_playbook_dir, sub_path=constants.PLAYBOOKS_PATH)
        except Exception:
            if os.path.exists(dc_vault_playbook_dir):
                shutil.rmtree(dc_vault_playbook_dir)
            raise

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
            for state_dir in states.DEPLOY_STATE_METADATA_DIR:
                os.makedirs(state_dir, exist_ok=True)
        except os.error:
            msg = "Failed to create directories"
            LOG.exception(msg)
            raise SoftwareFail(msg)

        for patch_file in patch_files:

            base_patch_filename = os.path.basename(patch_file)

            # Get the release_id from the patch's metadata
            # and check to see if it's already uploaded
            release_id = get_release_from_patch(patch_file, 'id')

            release = self.release_collection.get_release_by_id(release_id)
            patch_id = None
            thispatch = None

            try:
                if release:
                    if release.state == states.COMMITTED:
                        msg = "%s is committed. Metadata not updated" % release_id
                        LOG.info(msg)
                        local_info += msg + "\n"
                    elif release.state != states.AVAILABLE:
                        msg = "%s is not currently in available state to be deployed." % release_id
                        LOG.info(msg)
                        local_info += msg + "\n"
                    else:
                        # todo(abailey) PatchFile / extract_patch should be renamed
                        patch_id, thispatch, error_msg = PatchFile.extract_patch(
                            patch_file,
                            metadata_dir=states.AVAILABLE_DIR,
                            metadata_only=True,
                            existing_content=release.contents,
                            base_pkgdata=self.base_pkgdata)

                        if error_msg:
                            raise ReleaseValidationFailure(error=error_msg)

                        PatchFile.unpack_patch(patch_file)
                        reload_release_data()
                        msg = "%s is already uploaded. Updated metadata only" % release_id
                        LOG.info(msg)
                        local_info += msg + "\n"
                else:
                    patch_id, thispatch, error_msg = PatchFile.extract_patch(
                        patch_file,
                        metadata_dir=states.AVAILABLE_DIR,
                        base_pkgdata=self.base_pkgdata)

                    if error_msg:
                        raise ReleaseValidationFailure(error=error_msg)

                    PatchFile.unpack_patch(patch_file)
                    local_info += "%s is now uploaded\n" % release_id
                    reload_release_data()

                    # NOTE(bqian) Below check an exception raise should be revisit,
                    # if applicable, should be applied to the beginning of all requests.
                    if len(self.hosts) == 0:
                        msg = "service is running in incorrect state. No registered host"
                        raise InternalError(msg)
            except Exception as e:
                msg = "Failed to upload release %s" % release_id
                LOG.exception("%s: %s" % (msg, e))
                local_error += msg + "\n"

                if patch_id and thispatch:
                    PatchFile.delete_extracted_patch(patch_id, thispatch)

                    try:
                        release_sw_version = thispatch.metadata[patch_id]["sw_version"]
                        pkg_feed_dir = "%s/rel-%s" % (constants.PACKAGE_FEED_DIR, release_sw_version)
                        apt_utils.component_remove(pkg_feed_dir, release_sw_version)
                    except Exception:
                        LOG.info("Could not delete apt-ostree component, does not exist")
                continue

            release = self.release_collection.get_release_by_id(release_id)
            if release:
                upload_patch_info.append({
                    base_patch_filename: {
                        "id": release_id,
                        "sw_release": release.sw_release,  # MM.mm.pp release version
                    }
                })

        # create versioned precheck for uploaded patches
        for patch in upload_patch_info:
            filename, values = list(patch.items())[0]
            LOG.info("Creating precheck for release %s..." % values.get("id"))
            for pf in patch_files:
                if filename in pf:
                    patch_file = pf

            sw_release = values.get("sw_release")

            required_patches = []
            for dep_id in self.release_collection.get_release_by_id(values.get("id")).requires_release_ids:
                required_patches.append(version.parse(dep_id))

            # sort the required patches list and get the latest, if available
            req_patch_version = None
            if len(required_patches) > 0:
                req_patch = str(sorted(required_patches)[-1])
                _, req_patch_version, _, _ = utils.get_component_and_versions(req_patch)
                if self.release_collection.get_release_by_id(req_patch) is None:
                    LOG.warning("Required patch '%s' is not uploaded." % req_patch)

            PatchFile.create_versioned_precheck(patch_file, sw_release, req_patch_version=req_patch_version)

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
        is_importing_inactive_load = False

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
                msg = "The file extension is not supported. Supported extensions include .patch, .iso and .sig"
                LOG.exception(msg)
                raise ReleaseValidationFailure(error=msg)

        if len(upgrade_files) == 1:  # Only one upgrade file uploaded
            msg = "Missing upgrade file or signature file"
            LOG.error(msg)
            msg_error += msg + "\n"
        elif upgrade_files.get(constants.ISO_EXTENSION, None) and self.hostname != constants.CONTROLLER_0_HOSTNAME:
            raise SoftwareServiceError("Upload can only be performed on controller-0.")
        elif len(upgrade_files) == 2:  # Two upgrade files uploaded
            tmp_info = ""
            tmp_error = ""
            tmp_warning = ""
            tmp_release_meta_info = {}
            is_import_completed = True

            iso = upgrade_files[constants.ISO_EXTENSION]
            sig = upgrade_files[constants.SIG_EXTENSION]

            if not verify_files([iso], sig):
                msg = "Software %s:%s signature validation failed" % (iso, sig)
                raise ReleaseValidationFailure(error=msg)

            LOG.info("iso and signature files upload completed.")

            try:
                # Mount the iso file after signature verification
                iso_mount_dir = mount_iso_load(iso, constants.TMP_DIR)
                LOG.info("Mounted iso file %s to %s", iso, iso_mount_dir)

                # Read the metadata from the iso file to get to-release and supported-from-releases
                supported_from_releases = read_upgrade_support_versions(iso_mount_dir)
                to_release = get_to_release_from_metadata_file(iso_mount_dir)
                to_release_maj_ver = utils.get_major_release_version(to_release)
                LOG.info("Reading metadata from iso file %s completed. \nto_release: %s", iso, to_release_maj_ver)

                # Same release is uploaded, return the metadata info from the iso file
                if to_release_maj_ver == SW_VERSION:
                    tmp_info = f"Uploaded release {to_release} is the same as current release on the controller"
                    tmp_release_meta_info = self.get_release_meta_info(to_release, iso_mount_dir, upgrade_files)
                elif to_release > SW_VERSION:
                    # N + 1 release is uploaded, process it regardless
                    tmp_info, tmp_warning, tmp_error, tmp_release_meta_info = self._process_upload_upgrade_files(
                        SW_VERSION, to_release, iso_mount_dir, supported_from_releases, upgrade_files)
                elif to_release < SW_VERSION and is_system_controller():
                    # N - 1 release is uploaded, process it only if the region is system controller
                    is_importing_inactive_load = True
                    tmp_info, tmp_warning, tmp_error, tmp_release_meta_info = self._process_inactive_upgrade_files(
                        None, to_release, iso_mount_dir, upgrade_files)
                    # Checkout commit to dc-vault/playbooks directory
                    self._checkout_commit_to_dc_vault_playbook_dir(to_release_maj_ver)
            except Exception as e:
                LOG.error("Error occurred while processing software release upload: %s", str(e))
                is_import_completed = False
                raise
            finally:
                self._clean_up_load_import(iso_mount_dir, to_release, iso, is_import_completed)
                if is_importing_inactive_load and not is_import_completed:
                    self._clean_up_inactive_load_import(to_release)

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

        reload_release_data()

        return dict(info=msg_info, warning=msg_warning, error=msg_error, upload_info=upload_info)

    def release_apply_order(self, release_id, running_release_sw_version):
        """
        Determines the order of releases for applying.
        :param release_id: The appliyng release id
        :param running_release_sw_version: The running release major version
        :return: List of releases in the order for applying
        """

        release_dependencies = self.get_release_dependency_list(release_id)
        release_dependencies.append(release_id)

        deployed_releases_id = []
        for rel in self.release_collection.iterate_releases():
            if rel.state == states.DEPLOYED:
                deployed_releases_id.append(rel.id)

        # filter release_dependencies to include only releases
        # that matches the major running release version
        # and remove all releases already deployed
        to_apply_releases = [
            rel_id for rel_id in release_dependencies
            if f"-{running_release_sw_version}." in rel_id and rel_id not in deployed_releases_id
        ]

        to_apply_releases.sort()
        return to_apply_releases

    def release_remove_order(self, release_id, running_release_sw_version):
        """
        Determines the order of releases for removing.
        :param release_id: The removing release id
        :param running_release_sw_version: The running release major version
        :return: List of releases in the order for removing
        """

        # if removing release is not from the major running version, cannot remove it
        if f"-{running_release_sw_version}." not in release_id:
            return []

        to_remove_releases = self.get_release_required_by_list(release_id)
        # The specified release will not be removed
        if release_id in to_remove_releases:
            to_remove_releases.remove(release_id)

        to_remove_releases.sort(reverse=True)
        return to_remove_releases

    def reset_feed_commit(self, release):
        commit_id = release.commit_id
        if commit_id is None:
            LOG.warning("Unable to find the commit id in metadata")
            return

        LOG.info("Reset feed to commit %s" % commit_id)

        try:
            feed_ostree_dir = "%s/rel-%s/ostree_repo" % \
                (constants.FEED_OSTREE_BASE_DIR, release.sw_version)

            apt_utils.run_rollback(feed_ostree_dir, commit_id)
            self.latest_feed_commit = commit_id
        except APTOSTreeCommandFail:
            msg = "Failure when reseting commit %s" % commit_id
            LOG.exception(msg)
            raise APTOSTreeCommandFail(msg)

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
        if not_founds:
            list_str = ','.join(not_founds)
            err_msg = f"Release{'' if len(not_founds) == 1 else 's'} {list_str} can not be found\n"

        if cannot_del:
            list_str = ','.join(cannot_del)
            err_msg += (f"Release{'' if len(cannot_del) == 1 else 's'} {list_str} "
                        f"{'is' if len(cannot_del) == 1 else 'are'} not ready to be deleted\n")

        if used_by_subcloud:
            list_str = ','.join(used_by_subcloud)
            err_msg += f"Release{'' if len(used_by_subcloud) == 1 else 's'} {list_str} still used by subcloud(s)"

        if len(err_msg) > 0:
            raise SoftwareServiceError(error=err_msg)

        msg = "Deleting releases: %s" % ",".join(release_list)
        LOG.info(msg)
        audit_log_info(msg)

        # Handle operation
        for release_id in release_list:
            release = self.release_collection.get_release_by_id(release_id)
            release_sw_version = release.sw_version

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
            is_major_release = ReleaseState(release_ids=[release.id]).is_major_release_deployment()
            if not is_major_release:
                package_repo_dir = "%s/rel-%s" % (constants.PACKAGE_FEED_DIR, release_sw_version)
                packages = [pkg.split("_")[0] for pkg in release.packages]
                if packages:
                    apt_utils.package_remove(package_repo_dir, release.sw_release, packages)

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
            PatchFile.delete_versioned_directory(release.sw_release)

            # Delete N-1 load on system controller
            if is_system_controller():
                self._clean_up_inactive_load_import(release_sw_version)

            try:
                # Delete the metadata
                metadata_dir = states.RELEASE_STATE_TO_DIR_MAP[release.state]
                os.remove("%s/%s" % (metadata_dir, metadata_file))
            except OSError:
                msg = "Failed to remove metadata for %s" % release_id
                LOG.exception(msg)
                raise MetadataFail(msg)

            self.delete_install_script(release_id)
            reload_release_data()
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
        is_in_sync = is_deploy_state_in_sync()
        return {"in_sync": is_in_sync}

    def patch_init_release_api(self, release_id):
        """
        Create an empty repo for a new release_id
        :return: dict of info, warning and error messages
        """
        msg_info = ""
        msg_warning = ""
        msg_error = ""

        msg = "Initializing repo for: %s" % release_id
        LOG.info(msg)
        audit_log_info(msg)

        if release_id == SW_VERSION:
            msg = "Rejected: Requested release %s is running release" % release_id
            msg_error += msg + "\n"
            LOG.info(msg)
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # Refresh data
        self.base_pkgdata.loaddirs()

        reload_release_data()

        repo_dir[release_id] = "%s/rel-%s" % (repo_root_dir, release_id)

        # Verify the release doesn't already exist
        if os.path.exists(repo_dir[release_id]):
            msg = "Patch repository for %s already exists" % release_id
            msg_info += msg + "\n"
            LOG.info(msg)
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # Create the repo
        try:
            # todo(jcasteli)  determine if ostree change needs a createrepo equivalent
            output = "UNDER CONSTRUCTION for OSTREE"
            LOG.info("Repo[%s] updated:\n%s", release_id, output)
        except Exception:
            msg = "Failed to update the repo for %s" % release_id
            LOG.exception(msg)

            # Wipe out what was created
            shutil.rmtree(repo_dir[release_id])
            del repo_dir[release_id]

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
            release = self.release_collection.get_release_by_id(patch_id)
            if release is None:
                msg = "Patch %s does not exist" % patch_id
                LOG.error(msg)
                msg_error += msg + "\n"
                id_verification = False

        if not id_verification:
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        required_patches = {}
        for release in self.release_collection.iterate_releases():
            for req_patch in release.requires_release_ids:
                if req_patch not in patch_ids:
                    continue

                if req_patch not in required_patches:
                    required_patches[req_patch] = []

                required_patches[req_patch].append(release.id)

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

        self.check_patch_states()

        if self.sock_out is None or self.install_local:
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
            valid_query_states = [
                states.AVAILABLE,
                states.UNAVAILABLE,
                states.DEPLOYED,
                states.REMOVING,
                states.COMMITTED,
                states.DEPLOYING
            ]
            if kwargs["show"] in valid_query_states:
                query_state = kwargs["show"]

        query_release = None
        if "release" in kwargs:
            query_release = kwargs["release"]

        results = []

        def filter_by_version():
            for r in self.release_collection.iterate_releases():
                if r.sw_version in query_release:
                    yield r

        def filter_by_state():
            for rel in self.release_collection.iterate_releases_by_state(query_state):
                yield rel

        if query_state is not None:
            iterator = filter_by_state
        elif query_release is not None:
            iterator = filter_by_version
        else:
            iterator = self.release_collection.iterate_releases

        for i in iterator():
            data = i.to_query_dict()
            results.append(data)

        return results

    def software_release_query_specific_cached(self, release_ids):
        LOG.info("software release show")

        results = []

        for release_id in release_ids:
            release = self.release_collection.get_release_by_id(release_id)
            if release is not None:
                results.append(release.to_query_dict())

        return results

    def get_dependencies(self, patch_ids, recursive):
        dependencies = set()
        patch_added = False

        # Add patches to workset
        for patch_id in sorted(patch_ids):
            dependencies.add(patch_id)
            patch_added = True

        while patch_added:
            patch_added = False
            for patch_id in sorted(dependencies):
                release = self.release_collection.get_release_by_id(patch_id)
                for req in release.requires:
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

        # Verify patch IDs
        for patch_id in sorted(patch_ids):
            release = self.release_collection.get_release_by_id(patch_id)
            if release is None:
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
            if not os.path.exists(states.COMMITTED_DIR):
                os.makedirs(states.COMMITTED_DIR)
        except os.error:
            msg = "Failed to create %s" % states.COMMITTED_DIR
            LOG.exception(msg)
            raise SoftwareFail(msg)

        failure = False
        recursive = True
        cleanup_files = set()
        results = {"info": "",
                   "error": ""}

        # Ensure there are only REL patches
        non_rel_list = []
        for release in self.release_collection.iterate_releases():
            if release.status != constants.STATUS_RELEASED:
                non_rel_list.append(release.id)

        if len(non_rel_list) > 0:
            errormsg = "A commit cannot be performed with non-REL status patches in the system:\n"
            for patch_id in non_rel_list:
                errormsg += "    %s\n" % patch_id
            LOG.info("patch_commit rejected: %s", errormsg)
            results["error"] += errormsg
            return results

        # Verify Release IDs
        for patch_id in sorted(patch_ids):
            release = self.release_collection.get_release_by_id(patch_id)
            if release is None:
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
        for patch_id in commit_list:
            release = self.release_collection.get_release_by_id(patch_id)
            if release.state not in [states.DEPLOYED, states.COMMITTED]:
                avail_list.append(patch_id)

        if len(avail_list) > 0:
            errormsg = "The following patches are not applied and cannot be committed:\n"
            for patch_id in avail_list:
                errormsg += "    %s\n" % patch_id
            LOG.info("patch_commit rejected: %s", errormsg)
            results["error"] += errormsg
            return results

        # TODO(ShawnLi): Comment out for 24.09 release. This is gated to 25.03
        # for patch_id in commit_list:
        #     # Fetch file paths that need to be cleaned up to
        #     # free patch storage disk space
        #     pre_install_filename = self.release_data.metadata[patch_id].get("pre_install")
        #     post_install_filename = self.release_data.metadata[patch_id].get("post_install")

        #     if pre_install_filename:
        #         pre_install_script_path = "%s/%s_%s" % (root_scripts_dir, patch_id, pre_install_filename)
        #         post_install_script_path = "%s/%s_%s" % (root_scripts_dir, patch_id, post_install_filename)
        #         if os.path.exists(pre_install_script_path):
        #             cleanup_files.add(pre_install_script_path)
        #         if os.path.exists(post_install_script_path):
        #             cleanup_files.add(post_install_script_path)

        #     patch_sw_version = utils.get_major_release_version(
        #         self.release_data.metadata[patch_id]["sw_version"])
        #     abs_ostree_tar_dir = package_dir[patch_sw_version]
        #     software_tar_path = "%s/%s-software.tar" % (abs_ostree_tar_dir, patch_id)
        #     if os.path.exists(software_tar_path):
        #         cleanup_files.add(software_tar_path)

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
            deployed_fname = os.path.join(states.DEPLOYED_DIR, metadata_fname)
            committed_fname = os.path.join(states.COMMITTED_DIR, metadata_fname)
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

        reload_release_data()

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

    def copy_install_scripts(self):
        applying_states = [states.DEPLOYING, states.REMOVING]
        for release in self.release_collection.iterate_releases():
            pre_install = release.pre_install
            post_install = release.post_install
            folder = ["preinstall", "postinstall"]
            if release.state in applying_states:
                try:
                    for i, file in enumerate(file for file in (pre_install, post_install) if file):
                        full_name_file = "%s_%s" % (release.id, file)
                        script_path = "%s/%s" % (root_scripts_dir, full_name_file)
                        dest_path = constants.PATCH_SCRIPTS_STAGING_DIR + "/" + folder[i]
                        dest_script_file = "%s/%s" % (dest_path, full_name_file)
                        if not os.path.exists(dest_path):
                            os.makedirs(dest_path, 0o700)
                        shutil.copyfile(script_path, dest_script_file)
                        os.chmod(dest_script_file, 0o700)
                        msg = "Creating install script %s for %s" % (full_name_file, release.id)
                        LOG.info(msg)
                except shutil.Error:
                    msg = "Failed to copy the install script %s for %s" % (full_name_file, release.id)
                    LOG.exception(msg)
                    raise SoftwareError(msg)
            else:
                try:
                    for i, file in enumerate(file for file in (pre_install, post_install) if file):
                        full_name_file = "%s_%s" % (release.id, file)
                        script_path = "%s/%s/%s" % (constants.PATCH_SCRIPTS_STAGING_DIR, folder[i], full_name_file)
                        if os.path.exists(script_path):
                            os.remove(script_path)
                        msg = "Removing install script %s for %s" % (full_name_file, release.id)
                        LOG.info(msg)
                except shutil.Error:
                    msg = "Failed to delete the install script %s for %s" % (full_name_file, release.id)
                    LOG.exception(msg)

    def _update_state_to_peer(self):
        self.socket_lock.acquire()
        try:
            state_update_msg = SoftwareMessageDeployStateUpdate()
            state_update_msg.send(self.sock_out)
        finally:
            self.socket_lock.release()

    def _release_basic_checks(self, deployment):
        """
        Does basic sanity checks on the release data
        :param deployment: release to be checked
        :return: release object (if exists),
                 bool with success output,
                 strings with info, warning and error messages
        """

        # We need to verify that the software release exists
        release = self.release_collection.get_release_by_id(deployment)
        if not release:
            msg = "Software release version corresponding to the specified release " \
                  "%s does not exist." % deployment
            LOG.error(msg)
            msg = msg + " Try deleting and re-uploading the software for recovery."
            raise SoftwareServiceError(error=msg)

        return release

    def _deploy_precheck(self, release_version: str, force: bool = False,
                         region_name: str = None, patch: bool = False) -> dict:
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

        if region_name is None:
            region_name = utils.get_local_region_name()
        precheck_script = utils.get_precheck_script(release_version)

        if not os.path.isfile(precheck_script) and patch:
            # Precheck script may not be available for some patches
            # In that case, report system as healthy with info message to proceed
            msg_info = f"No deploy-precheck script available for patch version {release_version}"
            return dict(info=msg_info, warning=msg_warning, error=msg_error, system_healthy=True)

        if not os.path.isfile(precheck_script):
            msg = "Release files for deployment %s are not present on the system, " \
                  "cannot proceed with the precheck." % release_version
            LOG.error(msg)
            msg_error = "Fail to perform deploy precheck. " \
                        "Uploaded release may have been damaged. " \
                        "Try delete and re-upload the release.\n"
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        if self.pre_bootstrap and not force:
            # Deploy precheck may not be supported in prebootstrap environment if
            # script access any of services like sysinv, keystone, etc.
            msg_warning = "Pre-bootstrap environment may not support deploy precheck.\n" \
                          "Use --force option to execute deploy precheck script.\n"
            return dict(info=msg_info, warning=msg_warning, error=msg_error, system_healthy=True)

        deploy_in_progress = self._get_software_upgrade()

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
        # TODO(jvazhapp) the region_name will not be 'RegionOne' (for standalone
        #  clouds or subcloud)
        if region_name != "RegionOne":
            pass

        # Get releases info required for precheck
        releases = self.software_release_query_cached()
        for release in releases:
            keys_to_delete = ['packages', 'summary', 'description',
                              'install_instructions', 'warnings', 'component']
            for key in keys_to_delete:
                del release[key]

        cmd = [precheck_script,
               "--auth_url=%s" % auth_url,
               "--username=%s" % username,
               "--password=%s" % password,
               "--project_name=%s" % project_name,
               "--user_domain_name=%s" % user_domain_name,
               "--project_domain_name=%s" % project_domain_name,
               "--region_name=%s" % region_name,
               "--releases=%s" % json.dumps(releases),
               "--deploy_in_progress=%s" % json.dumps(deploy_in_progress)]
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

    def software_deploy_precheck_api(self, deployment: str, force: bool = False, region_name=None) -> dict:
        """
        Verify if system satisfy the requisites to upgrade to a specified deployment.
        :param deployment: full release name, e.g. starlingx-MM.mm.pp
        :param force: if True will ignore minor alarms during precheck
        :return: dict of info, warning and error messages
        """

        release = self._release_basic_checks(deployment)
        release_version = release.sw_release

        # Check fields (MM.mm) of release_version to set patch flag
        is_patch = (not utils.is_upgrade_deploy(SW_VERSION, release_version))
        if not is_patch and socket.gethostname() != constants.CONTROLLER_0_HOSTNAME:
            raise SoftwareServiceError(f"Deploy precheck for major releases needs to be executed in"
                                       f" {constants.CONTROLLER_0_HOSTNAME} host.")

        ret = self._deploy_precheck(release_version, force, region_name, is_patch)
        if ret:
            if ret.get("system_healthy") is None:
                ret["error"] = "Fail to perform deploy precheck. Internal error has occurred.\n" + \
                               ret.get("error")
            elif not ret.get("system_healthy"):
                ret["error"] = "The following issues have been detected, which prevent " \
                               "deploying %s\n" % deployment + ret.get("info")
        return ret

    def _deploy_upgrade_start(self, to_release, commit_id):
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

    def deploy_state_changed(self, new_state):
        '''Handle 'deploy state change' event, invoked when operations complete. '''

        deploy_state = DeployState.get_instance()
        state_event = {
            DEPLOY_STATES.START_DONE: deploy_state.start_done,
            DEPLOY_STATES.START_FAILED: deploy_state.start_failed,
            DEPLOY_STATES.ACTIVATE_DONE: deploy_state.activate_done,
            DEPLOY_STATES.ACTIVATE_FAILED: deploy_state.activate_failed,
            DEPLOY_STATES.ACTIVATE_ROLLBACK_DONE: deploy_state.activate_rollback_done,
            DEPLOY_STATES.ACTIVATE_ROLLBACK_FAILED: deploy_state.activate_rollback_failed,
            DEPLOY_STATES.HOST_FAILED: deploy_state.deploy_host_failed
        }
        if new_state in state_event:
            state_event[new_state]()
        else:
            msg = f"Received invalid deploy state update {deploy_state}"
            LOG.error(msg)

    def host_deploy_state_changed(self, hostname, host_deploy_state):
        '''Handle 'host deploy state change' event. '''

        deploy_host_state = DeployHostState(hostname)
        state_event = {
            DEPLOY_HOST_STATES.FAILED: deploy_host_state.failed
        }
        if host_deploy_state in state_event:
            state_event[host_deploy_state]()
        else:
            msg = f"Received invalid deploy host state update {host_deploy_state}"
            LOG.error(msg)

    def add_text_tag_to_xml(self, parent, tag, text):
        '''Add text to tag. Create it if it does not exist'''
        element = parent.find(tag)
        if element is None:
            element = ET.SubElement(parent, tag)
        element.text = text
        return element

    def is_deployment_list_reboot_required(self, deployment_list):
        """Check if any deploy in deployment list is reboot required"""
        for release_id in deployment_list:
            release = self.release_collection.get_release_by_id(release_id)
            if release.reboot_required:
                return True
        return False

    def install_releases_thread(self, deployment_list, feed_repo, running_release):
        """
        In a separated thread.
        Install the debian packages, create the commit and update the metadata.
        """
        def run():
            LOG.info("Installing releases on repo: %s" % feed_repo)

            try:
                for release_id in deployment_list:
                    msg = "Starting deployment for: %s" % release_id
                    LOG.info(msg)
                    audit_log_info(msg)

                    deploy_release = self._release_basic_checks(release_id)
                    all_commits = ostree_utils.get_all_feed_commits(running_release.sw_version)
                    if deploy_release.commit_id in all_commits:
                        # This case is for node with prestaged data where ostree
                        # commits have been pulled from system controller
                        LOG.info("Commit %s already exists in feed repo for release %s"
                                 % (deploy_release.commit_id, release_id))
                        continue

                    packages = [pkg.split("_")[0] for pkg in deploy_release.packages]
                    if packages is None:
                        msg = "Unable to determine packages to install"
                        LOG.error(msg)
                        raise MetadataFail(msg)

                    # commit consistency check
                    latest_commit = all_commits[0]
                    # Install debian package through apt-ostree
                    try:
                        apt_utils.run_install(feed_repo, deploy_release.sw_release, packages)
                    except APTOSTreeCommandFail:
                        msg = "Failed to install Debian packages."
                        LOG.exception(msg)
                        raise APTOSTreeCommandFail(msg)

                    # Get the latest commit after performing "apt-ostree install".
                    self.latest_feed_commit = ostree_utils.get_feed_latest_commit(SW_VERSION)

                    deploystate = deploy_release.state
                    metadata_dir = states.RELEASE_STATE_TO_DIR_MAP[deploystate]
                    metadata_file = "%s/%s-metadata.xml" % (metadata_dir, release_id)

                    reload_release_data()
                    # NOTE(bqian) Below check an exception raise should be revisit, if applicable,
                    # should be applied to the begining of all requests.
                    if len(self.hosts) == 0:
                        msg = "service is running in incorrect state. No registered host"
                        raise InternalError(msg)

                    with self.hosts_lock:
                        self.interim_state[release_id] = list(self.hosts)

                    self.latest_feed_commit = ostree_utils.get_feed_latest_commit(SW_VERSION)

                    # Update metadata
                    tree = ET.parse(metadata_file)
                    root = tree.getroot()

                    contents = ET.SubElement(root, constants.CONTENTS_TAG)
                    ostree = ET.SubElement(contents, constants.OSTREE_TAG)
                    self.add_text_tag_to_xml(ostree, constants.NUMBER_OF_COMMITS_TAG, "1")
                    base = ET.SubElement(ostree, constants.BASE_TAG)
                    self.add_text_tag_to_xml(base, constants.COMMIT_TAG, latest_commit)
                    self.add_text_tag_to_xml(base, constants.CHECKSUM_TAG, "")
                    commit1 = ET.SubElement(ostree, constants.COMMIT1_TAG)
                    self.add_text_tag_to_xml(commit1, constants.COMMIT_TAG, self.latest_feed_commit)
                    self.add_text_tag_to_xml(commit1, constants.CHECKSUM_TAG, "")

                    ET.indent(tree, '  ')
                    with open(metadata_file, "wb") as outfile:
                        tree = ET.tostring(root)
                        outfile.write(tree)

                    LOG.info("Latest feed commit: %s added to metadata file" % self.latest_feed_commit)

                # Update the feed ostree summary
                ostree_utils.update_repo_summary_file(feed_repo)
                self.latest_feed_commit = ostree_utils.get_feed_latest_commit(SW_VERSION)

                # move the deploy state to start-done
                deploy_state = DeployState.get_instance()
                deploy_state.start_done(self.latest_feed_commit)

                LOG.info("Finished releases %s deploy start" % deployment_list)

                self.send_latest_feed_commit_to_agent()
                self.software_sync()
            except Exception as e:
                msg = "Deploy start applying failed: %s" % str(e)
                LOG.exception(msg)
                audit_log_info(msg)

                try:
                    # set state to failed
                    deploy_state = DeployState.get_instance()
                    deploy_state.start_failed()
                except Exception as e:
                    msg = "Unable to set deploy failed: %s" % str(e)
                    LOG.exception(msg)
                    audit_log_info(msg)

        thread = threading.Thread(target=run)
        thread.start()

    @require_deploy_state([None],
                          "There is already a deployment in progress ({state.value}). "
                          "Please complete/delete the current deployment.")
    def software_deploy_start_api(self, deployment: str, force: bool, **kwargs) -> dict:
        """
        to start deploy of a specified release.
        The operation implies deploying all undeployed dependency releases of
        the specified release. i.e, to deploy release 24.09.1, it implies
        deploying 24.09.0 and 24.09.1 when 24.09.0 has not been deployed.
        The operation includes steps:
        1. find all undeployed dependency releases
        2. ensure all releases (dependency and specified release) are ready to deployed
        3. precheck
        4. transform all involved releases to deploying state
        5. start the deploy subprocess
        """
        msg_info = ""
        msg_warning = ""
        msg_error = ""
        deploy_release = self._release_basic_checks(deployment)

        running_release = self.release_collection.running_release
        deploy_sw_version = deploy_release.sw_version  # MM.mm

        if ((deploy_release.is_ga_release or deploy_release.prepatched_iso) and
                socket.gethostname() != constants.CONTROLLER_0_HOSTNAME):
            raise SoftwareServiceError(f"Deploy start for major releases needs to be executed in "
                                       f"{constants.CONTROLLER_0_HOSTNAME} host.")

        feed_repo = "%s/rel-%s/ostree_repo" % (constants.FEED_OSTREE_BASE_DIR, deploy_sw_version)
        commit_id = deploy_release.commit_id
        # Set hostname in case of local install
        hostname = None
        if self.pre_bootstrap:
            hostname = constants.PREBOOTSTRAP_HOSTNAME
        elif self.install_local:
            hostname = socket.gethostname()
            valid_hostnames = [constants.CONTROLLER_0_HOSTNAME, constants.CONTROLLER_1_HOSTNAME]
            if hostname not in valid_hostnames:
                LOG.warning("Using unknown hostname for local install: %s", hostname)

        patch_release = True
        if utils.is_upgrade_deploy(SW_VERSION, deploy_release.sw_release):
            # TODO(bqian) remove default latest commit when a commit-id is built into GA metadata
            if commit_id is None:
                commit_id = ostree_utils.get_feed_latest_commit(deploy_sw_version)

            patch_release = False
            to_release = deploy_release.sw_release
            ret = self._deploy_precheck(to_release, force, patch=patch_release)
            if ret["system_healthy"] is None:
                ret["error"] = "Fail to perform deploy precheck. Internal error has occurred.\n" + \
                               ret["error"]
                return ret
            elif not ret["system_healthy"]:
                ret["error"] = "The following issues have been detected, which prevent " \
                               "deploying %s\n" % deployment + ret["info"] + \
                               "Please fix above issues then retry the deploy.\n"
                return ret

            if self._deploy_upgrade_start(to_release, commit_id):
                collect_current_load_for_hosts(deploy_sw_version)
                create_deploy_hosts()

                release_state = ReleaseState(release_ids=[deploy_release.id])
                release_state.start_deploy()
                deploy_state = DeployState.get_instance()
                deploy_state.start(running_release, to_release, feed_repo, commit_id, deploy_release.reboot_required)

                msg_info = "Deployment for %s started" % deployment
            else:
                msg_error = "Deployment for %s failed to start" % deployment

            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # Patch operation: 'deploy release' major version equals 'running release' major version (MM.mm)

        # TODO(bqian) update references of sw_release (string) to SWRelease object

        if deploy_release > running_release:
            operation = "apply"
        elif running_release > deploy_release:
            operation = "remove"
        else:
            # NOTE(bqian) The error message doesn't seem right. software version format
            # or any metadata semantic check should be done during upload. If data
            # invalid found subsequently, data is considered damaged, should recommend
            # delete and re-upload
            msg_error += "The software version format for this release is not correct.\n"
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # NOTE(bqian) shouldn't that patch release deploy and remove are doing the same thing
        # in terms of ostree commit, that it deploy to a commit specified by the commit-id that
        # associated to the release from the deploy start command?
        # If releases are such that:
        # R2 requires R1, R3 requires R2, R4 requires R3
        # If current running release is R2 and command issued is "software deploy start R4"
        # operation is "apply" with order [R3, R4]
        # If current running release is R4 and command issued is "software deploy start R2"
        # operation is "remove" with order [R4, R3]
        if operation == "apply":
            deployment_list = self.release_apply_order(deployment, running_release.sw_version)

            collect_current_load_for_hosts(deploy_sw_version, hostname=hostname)
            create_deploy_hosts(hostname=hostname)

            msg = "Deploy start order for apply operation: %s" % ",".join(deployment_list)
            LOG.info(msg)
            audit_log_info(msg)

            # todo(jcasteli) Do we need this block below?
            # Check for patches that can't be applied during an upgrade
            upgrade_check = True
            for release_id in deployment_list:
                release = self.release_collection.get_release_by_id(release_id)
                if release.sw_version != SW_VERSION and release.apply_active_release_only == "Y":
                    msg = "%s cannot be created during an upgrade" % release_id
                    LOG.error(msg)
                    msg_error += msg + "\n"
                    upgrade_check = False

            if not upgrade_check:
                return dict(info=msg_info, warning=msg_warning, error=msg_error)

            if kwargs.get("skip-semantic") != "yes":
                self.run_semantic_check(constants.SEMANTIC_PREAPPLY, deployment_list)

            running_release = self.release_collection.running_release
            to_deploy_release_id = deployment_list[-1]
            to_deploy_release = self.release_collection.get_release_by_id(to_deploy_release_id)
            reboot_required = self.is_deployment_list_reboot_required(deployment_list)

            collect_current_load_for_hosts(to_deploy_release.sw_version)
            release_state = ReleaseState(release_ids=deployment_list)
            release_state.start_deploy()

            # Setting deploy state to start, so that it can transition to start-done or start-failed
            deploy_state = DeployState.get_instance()
            to_release = to_deploy_release.sw_release
            deploy_state.start(running_release, to_release, feed_repo, None, reboot_required)

            # Start applying the releases
            self.install_releases_thread(deployment_list, feed_repo, running_release)

            msg_info += "%s is now starting, await for the states: " \
                        "[deploy-start-done | deploy-start-failed] in " \
                        "'software deploy show'\n" % deployment_list

        elif operation == "remove":
            collect_current_load_for_hosts(deploy_sw_version, hostname=hostname)
            create_deploy_hosts(hostname=hostname)
            deployment_list = self.release_remove_order(deployment, running_release.sw_version)

            msg = "Deploy start order for remove operation: %s" % ",".join(deployment_list)
            LOG.info(msg)
            audit_log_info(msg)

            remove_unremovable = False

            if kwargs.get("removeunremovable") == "yes":
                remove_unremovable = True

            # See if any of the patches are marked as unremovable
            unremovable_verification = True
            for release_id in deployment_list:
                release = self.release_collection.get_release_by_id(release_id)
                if release.unremovable:
                    if remove_unremovable:
                        msg = "Unremovable release %s being removed" % release_id
                        LOG.warning(msg)
                        msg_warning = msg + "\n"
                    else:
                        msg = "Release %s is not removable" % release_id
                        LOG.error(msg)
                        msg_error += msg + "\n"
                        unremovable_verification = False
                elif release.state == states.COMMITTED:
                    msg = "Release %s is committed and cannot be removed" % release_id
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

            collect_current_load_for_hosts(deploy_sw_version, hostname=hostname)
            release_state = ReleaseState(release_ids=deployment_list)
            release_state.start_remove()

            reboot_required = self.is_deployment_list_reboot_required(deployment_list)

            deploy_state = DeployState.get_instance()
            to_release = deploy_release.sw_release
            deploy_state.start(running_release, to_release, feed_repo, commit_id, reboot_required)

            try:
                for release_id in deployment_list:
                    release = self.release_collection.get_release_by_id(release_id)
                    msg = "Removing release: %s" % release_id
                    LOG.info(msg)
                    audit_log_info(msg)

                    if release.state == states.AVAILABLE:
                        msg = "The deployment for %s has not been created" % release_id
                        LOG.info(msg)
                        msg_info += msg + "\n"
                        continue

                    major_release_sw_version = release.sw_version
                    # this is an ostree patch
                    # Base commit is fetched from the patch metadata.
                    base_commit = release.base_commit_id
                    feed_repo = "%s/rel-%s/ostree_repo" % (constants.FEED_OSTREE_BASE_DIR, major_release_sw_version)
                    try:
                        # Reset the ostree HEAD
                        ostree_utils.reset_ostree_repo_head(base_commit, feed_repo)

                        # Delete all commits that belong to this release
                        # NOTE(bqian) there should be just one commit per release.
                        commit_to_delete = release.commit_id
                        ostree_utils.delete_ostree_repo_commit(commit_to_delete, feed_repo)

                        # Update the feed ostree summary
                        ostree_utils.update_repo_summary_file(feed_repo)

                    except OSTreeCommandFail:
                        LOG.exception("Failure while removing release %s.", release_id)

                    # Remove contents tag from metadata xml
                    self.remove_tags_from_metadata(release, constants.CONTENTS_TAG)

                    try:
                        # Move the metadata to the deleted dir
                        self.release_collection.update_state([release_id], states.REMOVING)
                        msg_info += "%s has been removed from the repo\n" % release_id
                    except shutil.Error:
                        msg = "Failed to move the metadata for %s" % release_id
                        LOG.Error(msg)
                        raise MetadataFail(msg)

                    if len(self.hosts) == 0:
                        msg = "service is running in incorrect state. No registered host"
                        raise InternalError(msg)

                    # only update lastest_feed_commit if it is an ostree patch
                    if release.base_commit_id is not None:
                        # Base Commit in this release's metadata.xml file represents the latest commit
                        # after this release has been removed from the feed repo
                        self.latest_feed_commit = release.base_commit_id

                    with self.hosts_lock:
                        self.interim_state[release_id] = list(self.hosts)

                # There is no defined behavior for deploy start for patching releases, so
                # move the deploy state to start-done
                deploy_state = DeployState.get_instance()
                deploy_state.start_done(self.latest_feed_commit)

                self.send_latest_feed_commit_to_agent()
                self.software_sync()
            except Exception as e:
                msg_error = "Deploy start removing failed"
                msg = "%s: %s" % (msg_error, e)
                LOG.exception(msg)
                audit_log_info(msg)

                # set state to failed
                deploy_state = DeployState.get_instance()
                deploy_state.start_failed()

        return dict(info=msg_info, warning=msg_warning, error=msg_error)

    def remove_tags_from_metadata(self, release, tag):
        LOG.info("Removing %s tag from %s metadata" % (tag, release.id))

        metadata_dir = states.RELEASE_STATE_TO_DIR_MAP[release.state]
        metadata_path = "%s/%s-metadata.xml" % (metadata_dir, release.id)
        tree = ET.parse(metadata_path)
        root = tree.getroot()
        metadata_tag = root.find(tag)

        if metadata_tag is not None:
            root.remove(metadata_tag)

            ET.indent(tree, '  ')
            with open(metadata_path, "wb") as outfile:
                tree = ET.tostring(root)
                outfile.write(tree)

    @require_deploy_state([DEPLOY_STATES.HOST_ROLLBACK_DONE, DEPLOY_STATES.COMPLETED, DEPLOY_STATES.START_DONE,
                           DEPLOY_STATES.START_FAILED],
                          "Deploy must be in the following states to be able to delete: %s, %s, %s, %s" % (
                          DEPLOY_STATES.HOST_ROLLBACK_DONE.value, DEPLOY_STATES.COMPLETED.value,
                          DEPLOY_STATES.START_DONE.value, DEPLOY_STATES.START_FAILED.value))
    def software_deploy_delete_api(self) -> dict:
        """
        Delete deployment and the data generated during the deploy.

        :return: dict of info, warning and error messages
        """

        if self.hostname != constants.CONTROLLER_0_HOSTNAME:
            raise SoftwareServiceError("Deployment deletion can only be performed on controller-0.")

        msg_info = ""
        msg_warning = ""
        msg_error = ""

        # hosts must be unlocked and online since during delete deployment
        # a request is sent to all host to clear flags and temporary data
        # created during the deployment procedure
        if not are_all_hosts_unlocked_and_online():
            msg = f"Hosts must be {constants.ADMIN_UNLOCKED} and {constants.AVAILABILITY_ONLINE}."
            raise SoftwareServiceError(error=msg)

        deploy = self.db_api_instance.get_current_deploy()
        to_release = deploy.get("to_release")
        from_release = deploy.get("from_release")

        deploy_state_instance = DeployState.get_instance()
        is_major_release = False

        if DEPLOY_STATES.COMPLETED == deploy_state_instance.get_deploy_state():
            deploying_release_state = ReleaseState(release_state=states.DEPLOYING)
            is_applying = deploying_release_state.has_release_id()

            if is_applying:
                is_major_release = deploying_release_state.is_major_release_deployment()

                major_release = utils.get_major_release_version(from_release)
                # In case of a major release deployment set all the releases related to from_release to unavailable
                if is_major_release:
                    unavailable_releases = []
                    for release in self.release_collection.iterate_releases():
                        if release.sw_version == major_release:
                            unavailable_releases.append(release.id)
                    ReleaseState(release_ids=unavailable_releases).replaced()

                # Set deploying releases to deployed state.
                deploying_release_state.deploy_completed()
            else:
                removing_release_state = ReleaseState(release_state=states.REMOVING)
                removing_release_state.available()

        elif DEPLOY_STATES.HOST_ROLLBACK_DONE == deploy_state_instance.get_deploy_state():
            major_release = utils.get_major_release_version(from_release)
            release_state = ReleaseState(release_state=states.DEPLOYING)
            is_major_release = release_state.is_major_release_deployment()

            release_state.available()

        elif deploy_state_instance.get_deploy_state() in [DEPLOY_STATES.START_DONE, DEPLOY_STATES.START_FAILED]:
            hosts_states = []
            for host in self.db_api_instance.get_deploy_host():
                hosts_states.append(host.get("state"))
            if (DEPLOY_HOST_STATES.DEPLOYED.value in hosts_states or
                    DEPLOY_HOST_STATES.DEPLOYING.value in hosts_states):
                raise SoftwareServiceError(f"There are hosts already {DEPLOY_HOST_STATES.DEPLOYED.value} "
                                           f"or in {DEPLOY_HOST_STATES.DEPLOYING.value} process")

            deploying_release_state = ReleaseState(release_state=states.DEPLOYING)
            is_applying = deploying_release_state.has_release_id()

            if is_applying:
                major_release = utils.get_major_release_version(to_release)
                is_major_release = deploying_release_state.is_major_release_deployment()

                if is_major_release:
                    try:
                        run_deploy_clean_up_script(to_release)
                    except subprocess.CalledProcessError as e:
                        msg_error = "Failed to delete deploy"
                        LOG.error("%s: %s" % (msg_error, e))
                        raise SoftwareServiceError(msg_error)
                else:
                    deployment_list = deploying_release_state.get_release_ids()
                    for release in self.release_collection.iterate_releases():
                        if release.sw_release == from_release:
                            self.reset_feed_commit(release)

                        if release.id in deployment_list:
                            self.remove_tags_from_metadata(release, constants.CONTENTS_TAG)

                deploying_release_state.available()
            else:
                msg_error = "Delete is not supported while removing a release"
                LOG.error(msg_error)
                raise SoftwareServiceError(msg_error)

        if os.path.isfile(INSTALL_LOCAL_FLAG):
            # Remove install local flag if enabled
            if os.path.isfile(INSTALL_LOCAL_FLAG):
                try:
                    os.remove(INSTALL_LOCAL_FLAG)
                except Exception:
                    msg_error = "Failed to clear install-local mode flag"
                    LOG.error(msg_error)
                    raise SoftwareServiceError(msg_error)
                LOG.info("Software deployment in local installation mode is stopped")

        if is_major_release:
            clean_up_deployment_data(major_release)

            # Send message to agents cleanup their ostree environment
            # if the deployment has completed or rolled-back successfully
            finished_deploy_states = [DEPLOY_STATES.COMPLETED, DEPLOY_STATES.HOST_ROLLBACK_DONE]
            if deploy_state_instance.get_deploy_state() in finished_deploy_states:
                cleanup_req = SoftwareMessageDeployDeleteCleanupReq()
                cleanup_req.major_release = utils.get_major_release_version(to_release)
                cleanup_req.encode()
                self.socket_lock.acquire()
                cleanup_req.send(self.sock_out)
                self.socket_lock.release()

            self.manage_software_alarm(fm_constants.FM_ALARM_ID_USM_CLEANUP_DEPLOYMENT_DATA,
                                       fm_constants.FM_ALARM_STATE_CLEAR,
                                       "%s=%s" % (fm_constants.FM_ENTITY_TYPE_HOST, constants.CONTROLLER_FLOATING_HOSTNAME))

        msg_info += "Deploy deleted with success"
        self.db_api_instance.delete_deploy_host_all()
        self.db_api_instance.delete_deploy()
        return dict(info=msg_info, warning=msg_warning, error=msg_error)

    def _deploy_complete(self):
        is_all_hosts_in_deployed_state = all(host_state.get("state") == DEPLOY_HOST_STATES.DEPLOYED.value
                                             for host_state in self.db_api_instance.get_deploy_host())
        if not is_all_hosts_in_deployed_state:
            raise SoftwareServiceError(f"Complete not allowed because there are hosts not"
                                       f" in {DEPLOY_HOST_STATES.DEPLOYED.value} state.")
        return True

    @require_deploy_state([DEPLOY_STATES.ACTIVATE_DONE],
                          "Deploy must be in %s state to be able to complete." % DEPLOY_STATES.ACTIVATE_DONE.value)
    def software_deploy_complete_api(self) -> dict:
        """
        Completes a deployment associated with the release
        :return: dict of info, warning and error messages
        """
        msg_info = ""
        msg_warning = ""
        msg_error = ""

        deploy_state = DeployState.get_instance()

        if self._deploy_complete():
            deploy_state.completed()
            msg_info += "Deployment has been completed\n"

        return dict(info=msg_info, warning=msg_warning, error=msg_error)

    def _activate(self):
        deploy = self.db_api_instance.get_deploy_all()
        if deploy:
            deploy = deploy[0]
        else:
            msg = "Deployment is missing unexpectedly"
            raise InvalidOperation(msg)

        deploying = ReleaseState(release_state=states.DEPLOYING)
        if deploying.is_major_release_deployment():
            return self._activate_major_release(deploy)
        else:
            return self._activate_patching_release()

    def _activate_patching_release(self):
        deploy_state = DeployState.get_instance()
        # patching release activate operations go here
        deploy_state.activate_done()
        return True

    def _activate_major_release(self, deploy):
        cmd_path = "/usr/bin/software-deploy-activate"
        from_release = utils.get_major_release_version(deploy.get("from_release"))
        to_release = utils.get_major_release_version(deploy.get("to_release"))

        upgrade_activate_cmd = [cmd_path, from_release, to_release]

        try:
            LOG.info("starting subprocess %s" % ' '.join(upgrade_activate_cmd))
            subprocess.Popen(' '.join(upgrade_activate_cmd), start_new_session=True, shell=True)
            LOG.info("subprocess started")
        except subprocess.SubprocessError as e:
            LOG.error("Failed to start command: %s. Error %s" % (' '.join(upgrade_activate_cmd), e))
            return False

        return True

    def _check_pre_activate(self):
        if not are_all_hosts_unlocked_and_online():
            msg = f"Hosts must be {constants.ADMIN_UNLOCKED} and {constants.AVAILABILITY_ONLINE}."
            raise SoftwareServiceError(error=msg)
        # check current deployment, deploy to all hosts have completed,
        # the deploy state is host-done, or
        # activate-failed' as reattempt from a previous failed activate
        deploy_state = DeployState.get_deploy_state()
        if deploy_state not in [DEPLOY_STATES.HOST_DONE, DEPLOY_STATES.ACTIVATE_FAILED]:
            msg = "Must complete deploying all hosts before activating the deployment"
            raise InvalidOperation(msg)

        deploy_hosts = self.db_api_instance.get_deploy_host()
        invalid_hosts = []
        for deploy_host in deploy_hosts:
            if deploy_host['state'] not in [states.DEPLOYED]:
                invalid_hosts.append(deploy_host)

        if len(invalid_hosts) > 0:
            msg = "All hosts must have completed deployment before activating the deployment"
            for invalid_host in invalid_hosts:
                msg += "%s: %s\n" % (invalid_host["hostname"], invalid_host["state"])
            raise InvalidOperation(msg)

    @require_deploy_state([DEPLOY_STATES.ACTIVATE, DEPLOY_STATES.ACTIVATE_DONE, DEPLOY_STATES.ACTIVATE_FAILED,
                          DEPLOY_STATES.COMPLETED, DEPLOY_STATES.HOST, DEPLOY_STATES.HOST_DONE,
                          DEPLOY_STATES.HOST_FAILED],
                          "Deploy must be in the following states to be able to abort: %s, %s, %s, %s, %s, %s, %s" %
                          (DEPLOY_STATES.ACTIVATE.value, DEPLOY_STATES.ACTIVATE_DONE.value,
                           DEPLOY_STATES.ACTIVATE_FAILED.value, DEPLOY_STATES.COMPLETED.value, DEPLOY_STATES.HOST.value,
                           DEPLOY_STATES.HOST_DONE.value, DEPLOY_STATES.HOST_FAILED.value))
    def software_deploy_abort_api(self) -> dict:
        """
        Aborts the deployment associated with the release
        :return: dict of info, warning and error messages
        """
        msg_info = ""
        msg_warning = ""
        msg_error = ""

        deploy = self.db_api_instance.get_current_deploy()
        from_release = deploy.get("from_release")
        to_release = deploy.get("to_release")
        from_release_deployment = self.release_collection.get_release_id_by_sw_release(from_release)
        to_release_deployment = self.release_collection.get_release_id_by_sw_release(to_release)

        try:
            is_major_release = ReleaseState(release_state=states.DEPLOYING).is_major_release_deployment()
        except AttributeError:
            release = self.release_collection.get_release_by_id(to_release_deployment)
            is_major_release = ReleaseState(release_ids=[release.id]).is_major_release_deployment()

        if not is_major_release:
            removing_release_state = ReleaseState(release_state=states.REMOVING)
            is_removing = removing_release_state.has_release_id()

            if is_removing:
                raise SoftwareServiceError("Abort operation is not supported in patch removal")

            from_deployment = self.release_collection.get_release_by_id(from_release_deployment)
            self.reset_feed_commit(from_deployment)

            self.send_latest_feed_commit_to_agent()
            self.software_sync()

        major_from_release = utils.get_major_release_version(from_release)
        feed_repo = "%s/rel-%s/ostree_repo" % (constants.FEED_OSTREE_BASE_DIR, major_from_release)
        deploy_release = self._release_basic_checks(from_release_deployment)
        commit_id = deploy_release.commit_id

        # TODO(lbonatti): remove this condition when commit-id is built into GA metadata.
        if is_major_release and commit_id in [constants.COMMIT_DEFAULT_VALUE, None]:
            commit_id = ostree_utils.get_feed_latest_commit(deploy_release.sw_version)

        # Update the deployment
        deploy_state = DeployState.get_instance()
        deploy_state.abort(feed_repo, commit_id)

        # Update the host deployment
        deploy_host = self.db_api_instance.get_deploy_host()
        for host in deploy_host:
            hostname = host.get("hostname")
            deploy_host_state = DeployHostState(hostname)
            deploy_host_state.abort()

        msg_info += "Deployment has been aborted\n"
        return dict(info=msg_info, warning=msg_warning, error=msg_error)

    @require_deploy_state([DEPLOY_STATES.HOST_DONE, DEPLOY_STATES.ACTIVATE_FAILED],
                          "Activate deployment only when current deployment state is {require_states}")
    def software_deploy_activate_api(self) -> dict:
        """
        Activates the deployment associated with the release
        :return: dict of info, warning and error messages
        """
        msg_info = ""
        msg_warning = ""
        msg_error = ""

        self._check_pre_activate()

        deploy_state = DeployState.get_instance()
        deploy_state.activate()

        try:
            self._activate()
            msg_info = "Deploy activate has started"
        except Exception:
            deploy_state.activate_failed()
            raise

        return dict(info=msg_info, warning=msg_warning, error=msg_error)

    def _activate_rollback_major_release(self, deploy):
        cmd_path = "/usr/bin/software-deploy-activate-rollback"
        from_release = utils.get_major_release_version(deploy.get("from_release"))
        to_release = utils.get_major_release_version(deploy.get("to_release"))

        upgrade_activate_rollback_cmd = [cmd_path, from_release, to_release]

        try:
            LOG.info("starting subprocess %s" % ' '.join(upgrade_activate_rollback_cmd))
            subprocess.Popen(' '.join(upgrade_activate_rollback_cmd), start_new_session=True, shell=True)
            LOG.info("subprocess started")
        except subprocess.SubprocessError as e:
            LOG.error("Failed to start command: %s. Error %s" % (' '.join(upgrade_activate_rollback_cmd), e))
            raise

    def _activate_rollback_patching_release(self):
        deploy_state = DeployState.get_instance()
        # patching release activate-rollback operations go here
        deploy_state.activate_rollback_done()

    def _activate_rollback(self):
        deploy = self.db_api_instance.get_current_deploy()
        if not deploy:
            msg = "Deployment is missing unexpectedly"
            raise InvalidOperation(msg)

        deploying = ReleaseState(release_state=states.DEPLOYING)
        if deploying.is_major_release_deployment():
            self._activate_rollback_major_release(deploy)
        else:
            self._activate_rollback_patching_release()

    @require_deploy_state([DEPLOY_STATES.ACTIVATE_ROLLBACK_PENDING, DEPLOY_STATES.ACTIVATE_ROLLBACK_FAILED],
                          "Activate-rollback deployment only when current deployment state is {require_states}")
    def software_deploy_activate_rollback_api(self) -> dict:
        """
        Rolls back activates the deployment associated with the release
        :return: dict of info, warning and error messages
        """
        msg_info = ""
        msg_warning = ""
        msg_error = ""

        deploy_state = DeployState.get_instance()
        deploy_state.activate_rollback()

        try:
            self._activate_rollback()
            msg_info = "Deploy activate-rollback has started"
        except Exception:
            deploy_state.activate_rollback_failed()
            raise

        return dict(info=msg_info, warning=msg_warning, error=msg_error)

    def software_deploy_show_api(self, from_release=None, to_release=None):
        # Retrieve deploy state from db
        if from_release and to_release:
            return self.db_api_instance.get_deploy(from_release, to_release)
        else:
            # Retrieve deploy state from db in list format
            return self.db_api_instance.get_deploy_all()

    def _deploy_host(self, hostname, force, async_req=False, rollback=False):
        msg_info = ""
        msg_warning = ""
        msg_error = ""

        try:
            ip = utils.gethostbyname(hostname)
        except socket.gaierror:
            msg_error += "Host %s not found\n" % hostname
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # NOTE(bqian) Get IP address to fulfill the need of patching structure.
        # need to review the design
        # ensure ip is in table as in some cases the host is aged out from the hosts table
        if ip not in self.hosts:
            raise HostIpNotFound(hostname)

        deploy_host = self.db_api_instance.get_deploy_host_by_hostname(hostname)
        if deploy_host is None:
            raise HostNotFound(hostname)
        deploy = self.db_api_instance.get_deploy_all()[0]
        commit_id = deploy.get("commit_id")
        if not self.install_local:
            deploy_host_validations(
                hostname,
                is_major_release=self.check_upgrade_in_progress(),
                rollback=rollback
            )
        deploy_state = DeployState.get_instance()
        deploy_host_state = DeployHostState(hostname)
        deploy_state.deploy_host()
        deploy_host_state.deploy_started()

        # if in a 'deploy host' reentrant scenario, i.e. retrying after
        # a failure, then clear the failure alarm before retrying
        entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_HOST, hostname)
        self.manage_software_alarm(fm_constants.FM_ALARM_ID_USM_DEPLOY_HOST_FAILURE,
                                   fm_constants.FM_ALARM_STATE_CLEAR,
                                   entity_instance_id)

        msg = "Running software deploy host for %s (%s), force=%s, async_req=%s" % (
            hostname, ip, force, async_req)
        LOG.info(msg)
        audit_log_info(msg)

        if self.allow_insvc_patching:
            LOG.info("Allowing in-service patching")
            force = True
            self.copy_install_scripts()

        # Check if there is a major release deployment in progress
        # and set agent request parameters accordingly
        major_release = None
        if self.check_upgrade_in_progress():
            upgrade_release = self.get_software_upgrade()
            major_release = upgrade_release["to_release"]
            force = False
            async_req = False
            msg = "Running major release deployment, major_release=%s, force=%s, async_req=%s, commit_id=%s" % (
                major_release, force, async_req, commit_id)
            msg_info += msg + "\n"
            LOG.info(msg)
            try:
                set_host_target_load(hostname, major_release)
                copy_pxeboot_update_file(major_release, rollback=rollback)
            except Exception:
                LOG.error("Fail to start deploy host")
                deploy_host_state.deploy_failed()
                raise

        self.hosts_lock.acquire()
        self.hosts[ip].install_pending = True
        self.hosts[ip].install_status = False
        self.hosts[ip].install_reject_reason = None
        self.hosts_lock.release()

        installreq = PatchMessageAgentInstallReq()
        installreq.ip = ip
        installreq.force = force
        installreq.major_release = major_release
        installreq.commit_id = commit_id
        installreq.encode()
        self.socket_lock.acquire()
        installreq.send(self.sock_out)
        self.socket_lock.release()

        if async_req:
            # async_req install requested, so return now
            msg = "Host deployment request sent to %s." % self.hosts[ip].hostname
            msg_info += msg + "\n"
            LOG.info("host-install async_req: %s", msg)
            # TODO(bqian) update deploy state to deploy-host

        # Now we wait, up to ten mins. future enhancement: Wait on a condition
        resp_rx = False
        max_time = time.time() + 600
        success = True
        # NOTE(bqian) loop below blocks REST API service (slow thread)
        # Consider remove.
        while time.time() < max_time:
            self.hosts_lock.acquire()
            if ip not in self.hosts:
                # The host aged out while we were waiting
                self.hosts_lock.release()
                success = False
                msg = "Agent expired while waiting: %s" % ip
                msg_error += msg + "\n"
                LOG.error("Error in host-install: %s", msg)
                break

            if not self.hosts[ip].install_pending:
                # We got a response
                resp_rx = True
                if self.hosts[ip].install_status:
                    msg = "Host deployment was successful on %s." % self.hosts[ip].hostname
                    msg_info += msg + "\n"
                    LOG.info("host-install: %s", msg)
                elif self.hosts[ip].install_reject_reason:
                    msg = "Host deployment rejected by %s. %s" % (
                        self.hosts[ip].hostname,
                        self.hosts[ip].install_reject_reason)
                    msg_error += msg + "\n"
                    LOG.error("Error in host-install: %s", msg)
                    success = False
                else:
                    msg = "Host deployment failed on %s." % self.hosts[ip].hostname
                    msg_error += msg + "\n"
                    LOG.error("Error in host-install: %s", msg)
                    success = False

                self.hosts_lock.release()
                break

            self.hosts_lock.release()

            time.sleep(0.5)

        if not resp_rx:
            msg = "Timeout occurred while waiting response from %s." % ip
            msg_error += msg + "\n"
            LOG.error("Error in host-install: %s", msg)
            success = False

        if not success:
            deploy_host_state.deploy_failed()

        return dict(info=msg_info, warning=msg_warning, error=msg_error)

    @require_deploy_state([DEPLOY_STATES.START_DONE, DEPLOY_STATES.HOST, DEPLOY_STATES.HOST_FAILED],
                          "Current deployment ({state}) is not ready to deploy host")
    def software_deploy_host_api(self, hostname, force, async_req=False):
        return self._deploy_host(hostname, force, async_req)

    @require_deploy_state([DEPLOY_STATES.ACTIVATE_ROLLBACK_DONE,
                           DEPLOY_STATES.HOST_ROLLBACK, DEPLOY_STATES.HOST_ROLLBACK_FAILED],
                          "Current deployment ({state}) is not ready to rollback host")
    def software_deploy_host_rollback_api(self, hostname, force, async_req=False):
        return self._deploy_host(hostname, force, async_req, rollback=True)

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

    def check_releases_state(self, release_ids, state):
        """check all releases to be in the specified state"""
        all_matched = True

        for release_id in release_ids:
            release = self.release_collection.get_release_by_id(release_id)
            if release is None:
                all_matched = False
                break

            if release.state != state:
                all_matched = False
                break
        return all_matched

    def is_available(self, release_ids):
        return self.check_releases_state(release_ids, states.AVAILABLE)

    def is_deployed(self, release_ids):
        return self.check_releases_state(release_ids, states.DEPLOYED)

    def is_committed(self, release_ids):
        return self.check_releases_state(release_ids, states.COMMITTED)

    # NOTE(bqian) report_app_dependencies function not being called?
    # which means self.app_dependencies will always be empty and file
    # app_dependency_filename will never exist?
    def report_app_dependencies(self, patch_ids, **kwargs):
        """
        Handle report of application dependencies
        """
        if "app" not in kwargs:
            raise ReleaseInvalidRequest

        appname = kwargs.get("app")

        LOG.info("Handling app dependencies report: app=%s, patch_ids=%s",
                 appname, ','.join(patch_ids))

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

        return True

    # NOTE(bqian) unused function query_app_dependencies
    def query_app_dependencies(self):
        """
        Query application dependencies
        """
        data = self.app_dependencies

        return dict(data)

    def is_host_next_to_be_deployed_api(self, hostname):
        is_major_release = ReleaseState(release_state=states.DEPLOYING).is_major_release_deployment()
        deploy_state = DeployState.get_deploy_state()
        # If there's no deploy in progress return False
        if deploy_state is None:
            return False
        is_rollback_action = deploy_state in [DEPLOY_STATES.HOST_ROLLBACK, DEPLOY_STATES.ACTIVATE_ROLLBACK_PENDING,
                                              DEPLOY_STATES.HOST_ROLLBACK_FAILED, DEPLOY_STATES.ACTIVATE_ROLLBACK_DONE,
                                              DEPLOY_STATES.ACTIVATE_ROLLBACK_FAILED]
        try:
            validate_host_deploy_order(hostname, is_major_release, is_rollback_action)
            return True
        except SoftwareServiceError:
            return False
        except Exception as err:
            msg_error = "Error to check deploy order"
            LOG.exception("%s: %s" % (msg_error, err))
            return False

    def deploy_host_list(self):
        deploy_hosts = self.db_api_instance.get_deploy_host()
        deploy = self.db_api_instance.get_deploy_all()
        if not deploy:
            return []
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

    def manage_software_alarm(self, alarm_id, alarm_state, entity_instance_id, **kwargs):
        try:
            if alarm_id not in constants.SOFTWARE_ALARMS:
                raise Exception("Unknown software alarm '%s'." % alarm_id)

            # deal with the alarm clear scenario
            if alarm_state == fm_constants.FM_ALARM_STATE_CLEAR:
                LOG.info("Clearing alarm: %s for %s" % (alarm_id, entity_instance_id))
                self.fm_api.clear_fault(alarm_id, entity_instance_id)
                return

            # if not clear alarm scenario, create the alarm
            alarm_data = constants.SOFTWARE_ALARMS.get(alarm_id)
            # update the alarm_data if it is present in kwargs
            if kwargs:
                for data in alarm_data:
                    if data in kwargs.keys():
                        alarm_data[data] = kwargs[data]

            alarm = fm_api.Fault(
                alarm_id=alarm_id,
                alarm_state=alarm_state,
                entity_type_id=alarm_data.get("entity_type_id"),
                entity_instance_id=entity_instance_id,
                severity=alarm_data.get("severity"),
                reason_text=alarm_data.get("reason_text"),
                alarm_type=alarm_data.get("alarm_type"),
                probable_cause=alarm_data.get("probable_cause"),
                proposed_repair_action=alarm_data.get("proposed_repair_action"),
                service_affecting=alarm_data.get("service_affecting"),
            )
            LOG.info("Raising alarm: %s for %s" % (alarm_id, entity_instance_id))
            self.fm_api.set_fault(alarm)
        except Exception as e:
            LOG.exception("Failed to manage alarm %s with action %s: %s" % (
                alarm_id, alarm_state, str(e)
            ))

    def get_out_of_sync_alarm(self):
        """Get the out-of-sync alarm instance from fm_api"""
        return self.fm_api.get_fault(fm_constants.FM_ALARM_ID_SW_UPGRADE_DEPLOY_STATE_OUT_OF_SYNC,
                                     constants.ALARM_INSTANCE_ID_OUT_OF_SYNC)

    def create_clean_up_deployment_alarm(self, target_state):
        """
        Creates the 900.022 alarm to warn the user to clean up the deployment data remaining for the specified release
        version.

        """
        if target_state in [DEPLOY_STATES.COMPLETED, DEPLOY_STATES.HOST_ROLLBACK_DONE]:
            is_major_release = ReleaseState(release_state=states.DEPLOYING).is_major_release_deployment()
            # Do not create in case of patch release.
            if not is_major_release:
                return
            deploy = self.db_api_instance.get_current_deploy()
            release_version = deploy.get('from_release')
            reason_text = constants.SOFTWARE_ALARMS[fm_constants.FM_ALARM_ID_USM_CLEANUP_DEPLOYMENT_DATA]["reason_text"]
            new_reason_text = reason_text % (target_state.value, release_version)
            self.manage_software_alarm(fm_constants.FM_ALARM_ID_USM_CLEANUP_DEPLOYMENT_DATA,
                                       fm_constants.FM_ALARM_STATE_SET,
                                       "%s=%s" % (fm_constants.FM_ENTITY_TYPE_HOST, constants.CONTROLLER_FLOATING_HOSTNAME),
                                       reason_text=new_reason_text)

    def handle_deploy_state_sync(self):
        """
        Handle the deploy state sync.
        If deploy state is in sync, clear the alarm.
        If not, raise the alarm.
        """
        is_in_sync = is_deploy_state_in_sync()

        # Deploy in sync state is not changed, no need to update the alarm
        if is_in_sync == self.usm_alarm.get(constants.LAST_IN_SYNC):
            return

        try:
            LOG.info("software.json in sync: %s", is_in_sync)
            out_of_sync_alarm_fault = self.get_out_of_sync_alarm()

            if out_of_sync_alarm_fault and is_in_sync:
                # There was an out of sync alarm raised, but local software.json is in sync,
                # we clear the alarm
                self.manage_software_alarm(
                    alarm_id=fm_constants.FM_ALARM_ID_SW_UPGRADE_DEPLOY_STATE_OUT_OF_SYNC,
                    alarm_state=fm_constants.FM_ALARM_STATE_CLEAR,
                    entity_instance_id=constants.ALARM_INSTANCE_ID_OUT_OF_SYNC
                )
                # Deploy in sync state is changed, update the cache
                self.usm_alarm[constants.LAST_IN_SYNC] = is_in_sync
            elif (not out_of_sync_alarm_fault) and (not is_in_sync):
                # There was no out of sync alarm raised, but local software.json is not in sync,
                # we raise the alarm
                self.manage_software_alarm(
                    alarm_id=fm_constants.FM_ALARM_ID_SW_UPGRADE_DEPLOY_STATE_OUT_OF_SYNC,
                    alarm_state=fm_constants.FM_ALARM_STATE_SET,
                    entity_instance_id=constants.ALARM_INSTANCE_ID_OUT_OF_SYNC
                )
                # Deploy in sync state is changed, update the cache
                self.usm_alarm[constants.LAST_IN_SYNC] = is_in_sync
            else:
                # Shouldn't come to here
                LOG.error("Unexpected case in handling deploy state sync. ")

        except Exception as ex:
            LOG.exception("Failed in handling deploy state sync. Error: %s" % str(ex))

    def _get_software_upgrade(self):
        """
        Get the current software upgrade from/to versions and state
        :return: dict of from_release, to_release and state
        """

        all_deploy = self.db_api_instance.get_deploy_all()

        if not all_deploy:
            return None

        deploy = all_deploy[0]
        from_maj_min_release = utils.get_major_release_version(deploy.get("from_release"))
        to_maj_min_release = utils.get_major_release_version(deploy.get("to_release"))
        state = deploy.get("state")

        return {
            "from_release": from_maj_min_release,
            "to_release": to_maj_min_release,
            "state": state
        }

    def check_upgrade_in_progress(self):
        """
        Check if major release upgrade is in progress
        """
        _upgrade_in_progress = False
        upgrade_release = self._get_software_upgrade()
        if not upgrade_release:
            return _upgrade_in_progress
        from_release = version.Version(upgrade_release["from_release"])
        to_release = version.Version(upgrade_release["to_release"])
        if (from_release.major != to_release.major) or (from_release.minor != to_release.minor):
            _upgrade_in_progress = True
        return _upgrade_in_progress

    def get_software_upgrade(self):
        return self._get_software_upgrade()

    def get_all_software_host_upgrade(self):
        """
        Get all software host upgrade from/to versions and state
        :return: list of dict of hostname, current_sw_version, target_sw_version and host_state
        """
        deploy = self._get_software_upgrade()
        deploy_hosts = self.db_api_instance.get_deploy_host()

        if deploy is None or deploy_hosts is None:
            return None

        from_maj_min_release = deploy.get("from_release")
        to_maj_min_release = deploy.get("to_release")

        all_host_upgrades = []
        for deploy_host in deploy_hosts:
            all_host_upgrades.append({
                "hostname": deploy_host.get("hostname"),
                "current_sw_version": to_maj_min_release if deploy_host.get(
                    "state") == states.DEPLOYED else from_maj_min_release,
                "target_sw_version": to_maj_min_release,
                "host_state": deploy_host.get("state")
            })

        return all_host_upgrades

    def get_one_software_host_upgrade(self, hostname):
        """
        Get the given software host upgrade from/to versions and state
        :param hostname: hostname
        :return: array of dict of hostname, current_sw_version, target_sw_version and host_state
        """

        all_host_upgrades = self.get_all_software_host_upgrade()

        if not all_host_upgrades:
            return None

        for host_upgrade in all_host_upgrades:
            if host_upgrade.get("hostname") == hostname:
                return [host_upgrade]

        return None


class PatchControllerApiThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.wsgi = None
        self.name = "PatchControllerApiThread"

    def run(self):
        global thread_death

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

                if thread_death.is_set():
                    LOG.info("%s exits as thread death is detected.", self.name)
                    return

                # Call garbage collect after wsgi request is handled,
                # to ensure any open file handles are closed in the case
                # of an upload.
                gc.collect()
        except Exception as ex:
            # Log all exceptions
            LOG.exception("%s: error occurred during request processing: %s" % (self.name, str(ex)))
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
        self.name = f"PatchControllerAuthApiThread_{port}"

    def run(self):
        global thread_death
        host = CONF.auth_api_bind_ip
        if host is None:
            host = utils.get_versioned_address_all()
        try:
            # Can only launch authenticated server post-config
            while not os.path.exists(VOLATILE_CONTROLLER_CONFIG_COMPLETE):
                LOG.info("Authorized API: Waiting for controller config complete.")
                time.sleep(5)

            LOG.info("Authorized API: Initializing")

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

                if thread_death.is_set():
                    LOG.info("%s exits as thread death is detected.", self.name)
                    return

                # Call garbage collect after wsgi request is handled,
                # to ensure any open file handles are closed in the case
                # of an upload.
                gc.collect()
        except Exception as ex:
            # Log all exceptions
            LOG.exception("%s: error occurred during request processing: %s" % (self.name, str(ex)))
            thread_death.set()

    def kill(self):
        # Must run from other thread
        if self.wsgi is not None:
            self.wsgi.shutdown()

        LOG.info("%s exits as requested", self.name)
        global thread_death
        thread_death.set()


class PatchControllerMainThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        # LOG.info ("Initializing Main thread")
        self.name = "PatchControllerMainThread"

    def run(self):
        global sc
        global thread_death

        # TODO(jvazhapp) Fix following temporary workaround
        # for eventlet issue resulting in error message:
        # 'Resolver configuration could not be read or
        # specified no nameservers eventlet fix version'
        with open('/etc/resolv.conf', 'a+') as f:
            f.seek(0)
            data = f.read()
            if "nameserver" not in data:
                f.writelines("nameserver 8.8.8.8")

        # Send periodic messages to the agents
        # We only can use one inverval
        SEND_MSG_INTERVAL_IN_SECONDS = 30.0

        try:
            if sc.pre_bootstrap and cfg.get_mgmt_ip():
                sc.pre_bootstrap = False

            if sc.pre_bootstrap or os.path.isfile(INSTALL_LOCAL_FLAG):
                sc.install_local = True
            else:
                sc.install_local = False

            # Update the out of sync alarm cache when the thread starts
            out_of_sync_alarm_fault = sc.get_out_of_sync_alarm()
            sc.usm_alarm[constants.LAST_IN_SYNC] = not out_of_sync_alarm_fault

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
                    LOG.info("%s exits as thread death is detected.", self.name)
                    return

                # Check for in-service patch restart flag
                if os.path.exists(insvc_patch_restart_controller):
                    LOG.info("In-service patch restart flag detected. Exiting.")
                    global keep_running
                    keep_running = False
                    os.remove(insvc_patch_restart_controller)
                    return

                # If bootstrap is completed re-initialize sockets
                if sc.pre_bootstrap and cfg.get_mgmt_ip():
                    sc.pre_bootstrap = False

                    sock_in = sc.setup_socket()
                    while sock_in is None:
                        time.sleep(30)
                        sock_in = sc.setup_socket()

                    sc.socket_lock.acquire()

                    hello = PatchMessageHello()
                    hello.send(sc.sock_out)

                    hello_agent = PatchMessageHelloAgent()
                    hello_agent.send(sc.sock_out)

                    sc.socket_lock.release()
                    for s in agent_query_conns.copy():
                        agent_query_conns.remove(s)
                        s.shutdown(socket.SHUT_RDWR)
                        s.close()

                local_mode = sc.pre_bootstrap or os.path.isfile(INSTALL_LOCAL_FLAG)
                if local_mode and not sc.install_local:
                    sc.install_local = True
                elif not local_mode and sc.install_local:
                    sc.install_local = False

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
                        elif msgdata['msgtype'] == messages.PATCHMSG_DEPLOY_STATE_UPDATE:
                            msg = SoftwareMessageDeployStateUpdate()
                        elif msgdata['msgtype'] == messages.PATCHMSG_DEPLOY_STATE_UPDATE_ACK:
                            msg = SoftwareMessageDeployStateUpdateAck()
                        elif msgdata['msgtype'] == messages.PATCHMSG_DEPLOY_STATE_CHANGED:
                            msg = SWMessageDeployStateChanged()
                        elif msgdata['msgtype'] == messages.PATCHMSG_DEPLOY_DELETE_CLEANUP_RESP:
                            msg = SoftwareMessageDeployDeleteCleanupResp()

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

                    if not is_simplex():
                        # Get out-of-sync alarm to request peer sync even if no deployment in progress
                        out_of_sync_alarm_fault = sc.get_out_of_sync_alarm()

                        # data sync always start only from the active controller
                        if utils.is_active_controller():
                            if out_of_sync_alarm_fault or is_deployment_in_progress():
                                sc.socket_lock.acquire()
                                try:
                                    deploy_state_update = SoftwareMessageDeployStateUpdate()
                                    deploy_state_update.send(sc.sock_out)
                                except Exception as e:
                                    LOG.exception("Failed to send deploy state update. Error: %s", str(e))
                                finally:
                                    sc.socket_lock.release()

                            if not sc.pre_bootstrap:
                                sc.handle_deploy_state_sync()

        except Exception as ex:
            # Log all exceptions
            LOG.exception("%s: error occurred during request processing: %s" % (self.name, str(ex)))
            thread_death.set()


def main():
    software_conf = constants.SOFTWARE_CONFIG_FILE_LOCAL

    pkg_feed = ('"http://controller:8080/updates/debian/rel-%s/ %s updates"'
                % (constants.STARLINGX_RELEASE, constants.DEBIAN_RELEASE))

    config = configparser.ConfigParser()
    config.read(software_conf)
    config.set("runtime", "package_feed", pkg_feed)
    with open(software_conf, "w+") as configfile:
        config.write(configfile)

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
