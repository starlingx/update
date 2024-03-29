"""
Copyright (c) 2014-2023 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import gc
import json
import os
import random
import requests
import select
import shutil
import socket
import subprocess
import sys
import time

from cgcs_patch import ostree_utils
from cgcs_patch.patch_functions import configure_logging
from cgcs_patch.patch_functions import LOG
import cgcs_patch.config as cfg
from cgcs_patch.base import PatchService
from cgcs_patch.exceptions import OSTreeCommandFail
import cgcs_patch.utils as utils
import cgcs_patch.messages as messages
import cgcs_patch.constants as constants

from tsconfig.tsconfig import http_port
from tsconfig.tsconfig import install_uuid
from tsconfig.tsconfig import subfunctions
from tsconfig.tsconfig import SW_VERSION

pidfile_path = "/var/run/patch_agent.pid"
agent_running_after_reboot_flag = \
    "/var/run/patch_agent_running_after_reboot"
node_is_patched_file = "/var/run/node_is_patched"
node_is_patched_rr_file = "/var/run/node_is_patched_rr"
patch_installing_file = "/var/run/patch_installing"
patch_failed_file = "/var/run/patch_install_failed"
node_is_locked_file = "/var/run/.node_locked"
ostree_pull_completed_deployment_pending_file = \
    "/var/run/ostree_pull_completed_deployment_pending"
mount_pending_file = "/var/run/mount_pending"
insvc_patch_scripts = "/run/patching/patch-scripts"
insvc_patch_flags = "/run/patching/patch-flags"
insvc_patch_restart_agent = "/run/patching/.restart.patch-agent"

run_insvc_patch_scripts_cmd = "/usr/sbin/run-patch-scripts"

pa = None

http_port_real = http_port


def setflag(fname):
    try:
        with open(fname, "w") as f:
            f.write("%d\n" % os.getpid())
    except Exception:
        LOG.exception("Failed to update %s flag", fname)


def clearflag(fname):
    if os.path.exists(fname):
        try:
            os.remove(fname)
        except Exception:
            LOG.exception("Failed to clear %s flag", fname)


def pull_restart_scripts_from_controller():
    # If the rsync fails, it raises an exception to
    # the caller "handle_install()" and fails the
    # host-install request for this host
    output = subprocess.check_output(["rsync",
                                      "-acv",
                                      "--delete",
                                      "--exclude", "tmp",
                                      "rsync://controller/repo/patch-scripts/",
                                      "%s/" % insvc_patch_scripts],
                                     stderr=subprocess.STDOUT)
    LOG.info("Synced restart scripts from controller: %s", output)


def check_install_uuid():
    controller_install_uuid_url = "http://controller:%s/feed/rel-%s/install_uuid" % (http_port_real, SW_VERSION)
    try:
        req = requests.get(controller_install_uuid_url)
        if req.status_code != 200:
            # If we're on controller-1, controller-0 may not have the install_uuid
            # matching this release, if we're in an upgrade. If the file doesn't exist,
            # bypass this check
            if socket.gethostname() == "controller-1":
                return True

            LOG.error("Failed to get install_uuid from controller")
            return False
    except requests.ConnectionError:
        LOG.error("Failed to connect to controller")
        return False

    controller_install_uuid = str(req.text).rstrip()

    if install_uuid != controller_install_uuid:
        LOG.error("Local install_uuid=%s doesn't match controller=%s", install_uuid, controller_install_uuid)
        return False

    return True


class PatchMessageSendLatestFeedCommit(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_SEND_LATEST_FEED_COMMIT)

    def decode(self, data):
        global pa
        messages.PatchMessage.decode(self, data)
        if 'latest_feed_commit' in data:
            pa.latest_feed_commit = data['latest_feed_commit']

    def encode(self):
        messages.PatchMessage.encode(self)

    def handle(self, sock, addr):
        global pa
        # Check if the node is patch current
        pa.query()


class PatchMessageHelloAgent(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_HELLO_AGENT)
        self.patch_op_counter = 0

    def decode(self, data):
        messages.PatchMessage.decode(self, data)
        if 'patch_op_counter' in data:
            self.patch_op_counter = data['patch_op_counter']

    def encode(self):
        messages.PatchMessage.encode(self)

    def handle(self, sock, addr):
        # Send response

        #
        # If a user tries to do a host-install on an unlocked node,
        # without bypassing the lock check (either via in-service
        # patch or --force option), the agent will set its state
        # to Install-Rejected in order to report back the rejection.
        # However, since this should just be a transient state,
        # we don't want the client reporting the Install-Rejected
        # state indefinitely, so reset it to Idle after a minute or so.
        #
        if pa.state == constants.PATCH_AGENT_STATE_INSTALL_REJECTED:
            if os.path.exists(node_is_locked_file):
                # Node has been locked since rejected attempt. Reset the state
                pa.state = constants.PATCH_AGENT_STATE_IDLE
            elif (time.time() - pa.rejection_timestamp) > 60:
                # Rejected state for more than a minute. Reset it.
                pa.state = constants.PATCH_AGENT_STATE_IDLE

        if self.patch_op_counter > 0:
            pa.handle_patch_op_counter(self.patch_op_counter)

        resp = PatchMessageHelloAgentAck()
        resp.send(sock)

    def send(self, sock):  # pylint: disable=unused-argument
        LOG.error("Should not get here")


class PatchMessageHelloAgentAck(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_HELLO_AGENT_ACK)

    def encode(self):
        global pa
        messages.PatchMessage.encode(self)
        self.message['query_id'] = pa.query_id
        self.message['out_of_date'] = pa.changes
        self.message['hostname'] = socket.gethostname()
        self.message['requires_reboot'] = pa.node_is_patched
        self.message['patch_failed'] = pa.patch_failed
        self.message['sw_version'] = SW_VERSION
        self.message['state'] = pa.state

    def handle(self, sock, addr):
        LOG.error("Should not get here")

    def send(self, sock):
        global pa
        self.encode()
        message = json.dumps(self.message)
        sock.sendto(str.encode(message), (pa.controller_address, cfg.controller_port))


class PatchMessageQueryDetailed(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_QUERY_DETAILED)

    def decode(self, data):
        messages.PatchMessage.decode(self, data)

    def encode(self):
        # Nothing to add to the HELLO_AGENT, so just call the super class
        messages.PatchMessage.encode(self)

    def handle(self, sock, addr):
        # Send response
        LOG.info("Handling detailed query")
        resp = PatchMessageQueryDetailedResp()
        resp.send(sock)

    def send(self, sock):  # pylint: disable=unused-argument
        LOG.error("Should not get here")


class PatchMessageQueryDetailedResp(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_QUERY_DETAILED_RESP)

    def encode(self):
        global pa
        messages.PatchMessage.encode(self)
        self.message['latest_sysroot_commit'] = pa.latest_sysroot_commit
        self.message['nodetype'] = cfg.nodetype
        self.message['sw_version'] = SW_VERSION
        self.message['subfunctions'] = subfunctions
        self.message['state'] = pa.state

    def handle(self, sock, addr):
        LOG.error("Should not get here")

    def send(self, sock):
        self.encode()
        message = json.dumps(self.message)
        sock.sendall(str.encode(message))


class PatchMessageAgentInstallReq(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_AGENT_INSTALL_REQ)
        self.force = False

    def decode(self, data):
        messages.PatchMessage.decode(self, data)
        if 'force' in data:
            self.force = data['force']

    def encode(self):
        # Nothing to add to the HELLO_AGENT, so just call the super class
        messages.PatchMessage.encode(self)

    def handle(self, sock, addr):
        LOG.info("Handling host install request, force=%s", self.force)
        global pa
        resp = PatchMessageAgentInstallResp()

        if not self.force:
            setflag(node_is_patched_rr_file)

        if not os.path.exists(node_is_locked_file):
            if self.force:
                LOG.info("Installing on unlocked node, with force option")
            else:
                LOG.info("Rejecting install request on unlocked node")
                pa.state = constants.PATCH_AGENT_STATE_INSTALL_REJECTED
                pa.rejection_timestamp = time.time()
                resp.status = False
                resp.reject_reason = 'Node must be locked.'
                resp.send(sock, addr)
                return
        resp.status = pa.handle_install()
        resp.send(sock, addr)

    def send(self, sock):  # pylint: disable=unused-argument
        LOG.error("Should not get here")


class PatchMessageAgentInstallResp(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_AGENT_INSTALL_RESP)
        self.status = False
        self.reject_reason = None

    def encode(self):
        global pa
        messages.PatchMessage.encode(self)
        self.message['status'] = self.status
        if self.reject_reason is not None:
            self.message['reject_reason'] = self.reject_reason

    def handle(self, sock, addr):
        LOG.error("Should not get here")

    def send(self, sock, addr):
        address = (addr[0], cfg.controller_port)
        self.encode()
        message = json.dumps(self.message)
        sock.sendto(str.encode(message), address)

        # Send a hello ack to follow it
        resp = PatchMessageHelloAgentAck()
        resp.send(sock)


class PatchAgent(PatchService):
    def __init__(self):
        PatchService.__init__(self)
        self.sock_out = None
        self.sock_in = None
        self.controller_address = None
        self.listener = None
        self.changes = False
        self.latest_feed_commit = None
        self.latest_sysroot_commit = None
        self.patch_op_counter = 0
        self.node_is_patched = os.path.exists(node_is_patched_file)
        self.node_is_patched_timestamp = 0
        self.query_id = 0
        self.state = constants.PATCH_AGENT_STATE_IDLE
        self.last_config_audit = 0
        self.rejection_timestamp = 0
        self.last_repo_revision = None

        # Check state flags
        if os.path.exists(patch_installing_file):
            # We restarted while installing. Change to failed
            setflag(patch_failed_file)
            os.remove(patch_installing_file)

        if os.path.exists(patch_failed_file):
            self.state = constants.PATCH_AGENT_STATE_INSTALL_FAILED

        self.patch_failed = os.path.exists(patch_failed_file)

    def update_config(self):
        cfg.read_config()

        if self.port != cfg.agent_port:
            self.port = cfg.agent_port

        # Loopback interface does not support multicast messaging, therefore
        # revert to using unicast messaging when configured against the
        # loopback device
        if cfg.get_mgmt_iface() == constants.LOOPBACK_INTERFACE_NAME:
            self.mcast_addr = None
            self.controller_address = cfg.get_mgmt_ip()
        else:
            self.mcast_addr = cfg.agent_mcast_group
            self.controller_address = cfg.controller_mcast_group

    def setup_tcp_socket(self):
        address_family = utils.get_management_family()
        self.listener = socket.socket(address_family, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(('', self.port))
        self.listener.listen(2)  # Allow two connections, for two controllers

    def query(self):
        """Check current patch state """
        if not check_install_uuid():
            LOG.info("Failed install_uuid check. Skipping query")
            return False

        # Generate a unique query id
        self.query_id = random.random()

        # determine OSTREE state of the system and the patches
        self.changes = False

        active_sysroot_commit = ostree_utils.get_sysroot_latest_commit()
        self.latest_sysroot_commit = active_sysroot_commit
        self.last_repo_revision = active_sysroot_commit

        # latest_feed_commit is sent from patch controller
        # if unprovisioned (no mgmt ip) attempt to query it
        if self.latest_feed_commit is None:
            if self.sock_out is None:
                try:
                    self.latest_feed_commit = ostree_utils.get_feed_latest_commit(SW_VERSION)
                except OSTreeCommandFail:
                    LOG.warning("Unable to query latest feed commit")
                    # latest_feed_commit will remain as None

        if self.latest_feed_commit:
            if active_sysroot_commit != self.latest_feed_commit:
                LOG.info("Active Sysroot Commit:%s does not match "
                         "active controller's Feed Repo Commit: %s",
                         active_sysroot_commit, self.latest_feed_commit)
                self.changes = True

        return True

    def handle_install(self,
                       verbose_to_stdout=False,
                       disallow_insvc_patch=False,
                       delete_older_deployments=False):
        #
        # The disallow_insvc_patch parameter is set when we're installing
        # the patch during init. At that time, we don't want to deal with
        # in-service patch scripts, so instead we'll treat any patch as
        # a reboot-required when this parameter is set. Rather than running
        # any scripts, the RR flag will be set, which will result in the node
        # being rebooted immediately upon completion of the installation.
        #
        # The delete_older_deployments is set when the system has
        # been rebooted.
        #

        LOG.info("Handling install")

        # Check the INSTALL_UUID first. If it doesn't match the active
        # controller, we don't want to install patches.
        if not check_install_uuid():
            LOG.error("Failed install_uuid check. Skipping install")

            self.patch_failed = True
            setflag(patch_failed_file)
            self.state = constants.PATCH_AGENT_STATE_INSTALL_FAILED

            # Send a hello to provide a state update
            if self.sock_out is not None:
                hello_ack = PatchMessageHelloAgentAck()
                hello_ack.send(self.sock_out)

            return False

        self.state = constants.PATCH_AGENT_STATE_INSTALLING
        setflag(patch_installing_file)

        if delete_older_deployments:
            ostree_utils.delete_older_deployments()

        try:
            # Create insvc patch directories
            if not os.path.exists(insvc_patch_scripts):
                os.makedirs(insvc_patch_scripts, 0o700)
            if not os.path.exists(insvc_patch_flags):
                os.makedirs(insvc_patch_flags, 0o700)
        except Exception:
            LOG.exception("Failed to create in-service patch directories")

        # Send a hello to provide a state update
        if self.sock_out is not None:
            hello_ack = PatchMessageHelloAgentAck()
            hello_ack.send(self.sock_out)

        # Build up the install set
        if verbose_to_stdout:
            print("Checking for software updates...")
        self.query()  # sets self.changes

        changed = False
        success = True

        if self.changes or \
                os.path.exists(ostree_pull_completed_deployment_pending_file) or \
                os.path.exists(mount_pending_file):
            try:
                # Pull changes from remote to the sysroot ostree
                # The remote value is configured inside
                # "/sysroot/ostree/repo/config" file
                ostree_utils.pull_ostree_from_remote()
                setflag(ostree_pull_completed_deployment_pending_file)
            except OSTreeCommandFail:
                LOG.exception("Failed to pull changes and create deployment"
                              "during host-install.")
                success = False

            try:
                # Create a new deployment once the changes are pulled
                ostree_utils.create_deployment()

                changed = True
                clearflag(ostree_pull_completed_deployment_pending_file)

                # Creating a new deployment restores the kernel.env from ostree
                # which does not have local modifications (such as selecting a RT kernel)
                # We need to re-align that file after creating a deployment.
                ostree_utils.update_deployment_kernel_env()

            except OSTreeCommandFail:
                LOG.exception("Failed to pull changes and create deployment"
                              "during host-install.")
                success = False

            if changed:
                # Update the node_is_patched flag
                setflag(node_is_patched_file)

                self.node_is_patched = True
                if verbose_to_stdout:
                    print("This node has been patched.")

                if os.path.exists(node_is_patched_rr_file):
                    LOG.info("Reboot is required. Skipping patch-scripts")
                elif disallow_insvc_patch:
                    LOG.info("Disallowing patch-scripts. Treating as reboot-required")
                    setflag(node_is_patched_rr_file)
                else:
                    LOG.info("Mounting the new deployment")
                    try:
                        pending_deployment = ostree_utils.fetch_pending_deployment()
                        deployment_dir = constants.OSTREE_BASE_DEPLOYMENT_DIR + pending_deployment
                        setflag(mount_pending_file)
                        ostree_utils.mount_new_deployment(deployment_dir)
                        clearflag(mount_pending_file)
                        LOG.info("Running in-service patch-scripts")
                        pull_restart_scripts_from_controller()
                        subprocess.check_output(run_insvc_patch_scripts_cmd, stderr=subprocess.STDOUT)

                        # Clear the node_is_patched flag, since we've handled it in-service
                        clearflag(node_is_patched_file)
                        self.node_is_patched = False
                    except subprocess.CalledProcessError as e:
                        LOG.exception("In-Service patch installation failed")
                        LOG.error("Command output: %s", e.output)
                        success = False

        # Clear the in-service patch dirs
        if os.path.exists(insvc_patch_scripts):
            shutil.rmtree(insvc_patch_scripts, ignore_errors=True)
        if os.path.exists(insvc_patch_flags):
            shutil.rmtree(insvc_patch_flags, ignore_errors=True)

        if success:
            self.patch_failed = False
            clearflag(patch_failed_file)
            self.state = constants.PATCH_AGENT_STATE_IDLE
        else:
            # Update the patch_failed flag
            self.patch_failed = True
            setflag(patch_failed_file)
            self.state = constants.PATCH_AGENT_STATE_INSTALL_FAILED

        clearflag(patch_installing_file)
        self.query()

        if self.changes:
            LOG.warning("Installing the patch did not change the patch current status")

        # Send a hello to provide a state update
        if self.sock_out is not None:
            hello_ack = PatchMessageHelloAgentAck()
            hello_ack.send(self.sock_out)

        # Call python garbage collector to ensure the removal of cleared flags
        gc.collect()

        # Indicate if the method was successful
        # success means no change needed, or a change worked.
        return success

    def handle_patch_op_counter(self, counter):
        changed = False
        if os.path.exists(node_is_patched_file):
            # The node has been patched. Run a query if:
            # - node_is_patched didn't exist previously
            # - node_is_patched timestamp changed
            timestamp = os.path.getmtime(node_is_patched_file)
            if not self.node_is_patched:
                self.node_is_patched = True
                self.node_is_patched_timestamp = timestamp
                changed = True
            elif self.node_is_patched_timestamp != timestamp:
                self.node_is_patched_timestamp = timestamp
                changed = True
        elif self.node_is_patched:
            self.node_is_patched = False
            self.node_is_patched_timestamp = 0
            changed = True

        if self.patch_op_counter < counter:
            self.patch_op_counter = counter
            changed = True

        if changed:
            rc = self.query()
            if not rc:
                # Query failed. Reset the op counter
                self.patch_op_counter = 0

    def run(self):
        self.setup_socket()

        while self.sock_out is None:
            # Check every thirty seconds?
            # Once we've got a conf file, tied into packstack,
            # we'll get restarted when the file is updated,
            # and this should be unnecessary.
            time.sleep(30)
            self.setup_socket()

        self.setup_tcp_socket()

        # Ok, now we've got our socket.
        # Let's let the controllers know we're here
        hello_ack = PatchMessageHelloAgentAck()
        hello_ack.send(self.sock_out)

        first_hello = True

        connections = []

        timeout = time.time() + 30.0
        remaining = 30

        while True:
            inputs = [self.sock_in, self.listener] + connections
            outputs = []

            rlist, wlist, xlist = select.select(inputs, outputs, inputs, remaining)

            remaining = int(timeout - time.time())
            if remaining <= 0 or remaining > 30:
                timeout = time.time() + 30.0
                remaining = 30

            if (len(rlist) == 0 and
                    len(wlist) == 0 and
                    len(xlist) == 0):
                # Timeout hit
                self.audit_socket()
                continue

            for s in rlist:
                if s == self.listener:
                    conn, addr = s.accept()
                    connections.append(conn)
                    continue

                data = ''
                addr = None
                msg = None

                if s == self.sock_in:
                    # Receive from UDP
                    data, addr = s.recvfrom(1024)
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
                            # End of TCP message received
                            break

                    if data == '':
                        # Connection dropped
                        connections.remove(s)
                        s.close()
                        continue

                msgdata = json.loads(data)

                # For now, discard any messages that are not msgversion==1
                if 'msgversion' in msgdata and msgdata['msgversion'] != 1:
                    continue

                if 'msgtype' in msgdata:
                    if msgdata['msgtype'] == messages.PATCHMSG_HELLO_AGENT:
                        if first_hello:
                            self.query()
                            first_hello = False

                        msg = PatchMessageHelloAgent()
                    elif msgdata['msgtype'] == messages.PATCHMSG_QUERY_DETAILED:
                        msg = PatchMessageQueryDetailed()
                    elif msgdata['msgtype'] == messages.PATCHMSG_SEND_LATEST_FEED_COMMIT:
                        msg = PatchMessageSendLatestFeedCommit()
                    elif msgdata['msgtype'] == messages.PATCHMSG_AGENT_INSTALL_REQ:
                        msg = PatchMessageAgentInstallReq()

                if msg is None:
                    msg = messages.PatchMessage()

                msg.decode(msgdata)
                if s == self.sock_in:
                    msg.handle(self.sock_out, addr)
                else:
                    msg.handle(s, addr)

            for s in xlist:
                if s in connections:
                    connections.remove(s)
                    s.close()

            # Check for in-service patch restart flag
            if os.path.exists(insvc_patch_restart_agent):
                # Make sure it's safe to restart, ie. no reqs queued
                rlist, wlist, xlist = select.select(inputs, outputs, inputs, 0)
                if (len(rlist) == 0 and
                        len(wlist) == 0 and
                        len(xlist) == 0):
                    # Restart
                    LOG.info("In-service patch restart flag detected. Exiting.")
                    os.remove(insvc_patch_restart_agent)
                    exit(0)


def main():
    global pa

    configure_logging()

    cfg.read_config()

    pa = PatchAgent()
    pa.query()
    if os.path.exists(agent_running_after_reboot_flag):
        delete_older_deployments_flag = False
    else:
        setflag(agent_running_after_reboot_flag)
        delete_older_deployments_flag = True

    if len(sys.argv) <= 1:
        pa.run()
    elif sys.argv[1] == "--install":
        if not check_install_uuid():
            # In certain cases, the lighttpd server could still be running using
            # its default port 80, as opposed to the port configured in platform.conf
            global http_port_real
            LOG.info("Failed install_uuid check via http_port=%s. Trying with default port 80", http_port_real)
            http_port_real = 80

        pa.handle_install(verbose_to_stdout=True,
                          disallow_insvc_patch=True,
                          delete_older_deployments=delete_older_deployments_flag)
    elif sys.argv[1] == "--status":
        rc = 0
        if pa.changes:
            rc = 1
        exit(rc)
