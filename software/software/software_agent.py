"""
Copyright (c) 2024-2025 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
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
from packaging import version

import software.ostree_utils as ostree_utils
from software.software_functions import configure_logging
from software.software_functions import execute_agent_hooks
from software.software_functions import LOG
from software.software_functions import remove_major_release_deployment_flags
import software.config as cfg
from software.base import PatchService
from software.exceptions import OSTreeCommandFail
import software.utils as utils
import software.messages as messages
import software.constants as constants
import software.deploy_utils as deploy_utils

from tsconfig.tsconfig import http_port
from tsconfig.tsconfig import install_uuid
from tsconfig.tsconfig import subfunctions
from tsconfig.tsconfig import SW_VERSION

SOFTWARE_PERSIST_FOLDER = "/var/persist/software-agent"

pidfile_path = "/var/run/software_agent.pid"
node_is_patched_file = "/var/run/node_is_patched"
node_is_software_updated_rr_file = "%s/node_is_software_updated_rr" % SOFTWARE_PERSIST_FOLDER
patch_installing_file = "%s/patch_installing" % SOFTWARE_PERSIST_FOLDER
patch_failed_file = "/var/run/software_install_failed"
node_is_locked_file = "/var/run/.node_locked"
ostree_pull_completed_deployment_pending_file = \
    "/var/run/ostree_pull_completed_deployment_pending"
run_hooks_flag = "/var/run/run_hooks"
mount_pending_file = "/var/run/mount_pending"
insvc_software_scripts = "/run/software/software-scripts"
insvc_software_flags = "/run/software/software-flags"
insvc_software_restart_agent = "/run/software/.restart.software-agent"

run_install_software_scripts_cmd = "/usr/sbin/run-software-scripts"

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


def pull_install_scripts_from_controller(install_local=False):
    # If the rsync fails, it raises an exception to
    # the caller "handle_install()" and fails the
    # host-install request for this host.
    # The restart_scripts are optional, so if the files
    # are not present, it should not raise any exception
    host = constants.CONTROLLER
    if install_local:
        host = '127.0.0.1'
    try:
        output = subprocess.check_output(["rsync",
                                          "-acv",
                                          "--delete",
                                          "--exclude", "tmp",
                                          "rsync://%s/repo/software-scripts/" % host,
                                          "%s/" % insvc_software_scripts],
                                         stderr=subprocess.STDOUT)
        LOG.info("Synced restart scripts from controller: %s", output)
    except subprocess.CalledProcessError as e:
        if "No such file or directory" in e.output.decode("utf-8"):
            LOG.info("No restart scripts contained in the release")
        else:
            LOG.exception("Failed to sync restart scripts from controller")
            raise


def run_post_install_script():
    LOG.info("Running post-install patch-scripts")

    try:
        subprocess.check_output([run_install_software_scripts_cmd, "postinstall"],
                                stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        LOG.exception("Failed to execute post-install scripts.")
        LOG.error("Command output: %s", e.output)


def check_install_uuid():
    controller_install_uuid_url = "http://%s:%s/feed/rel-%s/install_uuid" % (constants.CONTROLLER,
                                                                             http_port_real,
                                                                             SW_VERSION)
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
        self.major_release = None
        self.commit_id = None
        self.additional_data = {}

    def decode(self, data):
        messages.PatchMessage.decode(self, data)
        msg = f"Received InstallReq {data}"
        LOG.info(msg)
        if 'force' in data:
            self.force = data['force']
        if 'major_release' in data:
            self.major_release = data['major_release']
        if 'commit_id' in data:
            self.commit_id = data['commit_id']
        if 'additional_data' in data:
            self.additional_data = data['additional_data']

    def encode(self):
        # Nothing to add to the HELLO_AGENT, so just call the super class
        messages.PatchMessage.encode(self)

    def handle(self, sock, addr):
        LOG.info("Handling host install request, force=%s, major_release=%s, commit_id=%s",
                 self.force, self.major_release, self.commit_id)
        global pa
        resp = PatchMessageAgentInstallResp()

        if not self.force:
            setflag(node_is_software_updated_rr_file)
            resp.reboot_required = True

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
        resp.status = pa.handle_install(major_release=self.major_release,
                                        commit_id=self.commit_id,
                                        additional_data=self.additional_data)
        resp.send(sock, addr)

    def send(self, sock):  # pylint: disable=unused-argument
        LOG.error("Should not get here")


class PatchMessageAgentInstallResp(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_AGENT_INSTALL_RESP)
        self.status = False
        self.reject_reason = None
        self.reboot_required = False

    def encode(self):
        global pa
        messages.PatchMessage.encode(self)
        self.message['status'] = self.status
        if self.reject_reason is not None:
            self.message['reject_reason'] = self.reject_reason
        self.message['reboot_required'] = self.reboot_required

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


class SoftwareMessageDeployDeleteCleanupReq(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_DEPLOY_DELETE_CLEANUP_REQ)
        self.major_release = None

    def decode(self, data):
        messages.PatchMessage.encode(self)
        if "major_release" in data:
            self.major_release = data["major_release"]

    def handle(self, sock, addr):
        LOG.info("Handling deploy delete cleanup request, major_release=%s" % self.major_release)

        # remove temporary remote and ref created during the upgrade process
        success_ostree_remote_cleanup = ostree_utils.delete_temporary_refs_and_remotes()

        # update the default remote 'debian' to point to the to-release feed
        nodetype = utils.get_platform_conf("nodetype")
        success_ostree_remote_update = ostree_utils.add_ostree_remote(
            self.major_release, nodetype, replace_default_remote=True)

        # remove the local upgrade flags created for the upgrade process
        success_remove_upgrade_flags = remove_major_release_deployment_flags()

        # undeploy the from-release ostree deployment to free sysroot disk space
        success_ostree_undeploy_from_release = ostree_utils.delete_older_deployments(
            delete_pending=True)

        deploy_utils.delete_etc_backup()
        cleanup_results = [
            (success_ostree_remote_cleanup, "cleaning temporary refs/remotes"),
            (success_ostree_remote_update, "updating default remote"),
            (success_remove_upgrade_flags, "removing local upgrade flags"),
            (success_ostree_undeploy_from_release, "undeploying from-release ostree deployment"),
        ]
        for result, log_msg in cleanup_results:
            if result not in [None, False]:
                LOG.info("Success %s" % log_msg)
            else:
                LOG.error("Failure %s, manual cleanup is required" % log_msg)
        success = all(x not in [None, False] for x, _ in cleanup_results)

        resp = SoftwareMessageDeployDeleteCleanupResp()
        resp.success = success
        resp.send(sock, addr)

    def send(self, sock):  # pylint: disable=unused-argument
        LOG.error("Should not get here")


class SoftwareMessageDeployDeleteCleanupResp(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_DEPLOY_DELETE_CLEANUP_RESP)
        self.success = None

    def encode(self):
        messages.PatchMessage.encode(self)
        self.message["success"] = self.success

    def handle(self, sock, addr):
        LOG.error("Should not get here")

    def send(self, sock, addr):
        self.encode()
        message = json.dumps(self.message)
        sock.sendto(str.encode(message), (addr[0], cfg.controller_port))


class SoftwareMessageCheckAgentAliveReq(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_CHECK_AGENT_ALIVE_REQ)

    def decode(self, data):
        messages.PatchMessage.decode(self, data)

    def handle(self, sock, addr):
        LOG.info("Handling check agent alive from %s", addr[0])
        check_alive_resp = SoftwareMessageCheckAgentAliveResp()
        check_alive_resp.send(sock, addr)

    def send(self, sock):  # pylint: disable=unused-argument
        LOG.error("Should not get here")


class SoftwareMessageCheckAgentAliveResp(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_CHECK_AGENT_ALIVE_RESP)

    def encode(self):
        messages.PatchMessage.encode(self)

    def handle(self, sock, addr):
        LOG.error("Should not get here")

    def send(self, sock, addr):
        LOG.info("Sending check agent alive resp to %s", addr[0])
        self.encode()
        message = json.dumps(self.message)
        sock.sendto(str.encode(message), (addr[0], cfg.controller_port))


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

        # Create persist folder
        if not os.path.exists(SOFTWARE_PERSIST_FOLDER):
            try:
                os.makedirs(SOFTWARE_PERSIST_FOLDER, exist_ok=True)
            except PermissionError:
                LOG.error("Permission denied: Cannot create %s", SOFTWARE_PERSIST_FOLDER)

        # Check state flags
        if os.path.exists(patch_installing_file):
            # We restarted while installing. Change to failed
            setflag(patch_failed_file)
            clearflag(patch_installing_file)

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
        if self.pre_bootstrap:
            self.mcast_addr = None
            self.controller_address = utils.gethostbyname(constants.PREBOOTSTRAP_HOSTNAME)
        elif cfg.get_mgmt_iface() == constants.LOOPBACK_INTERFACE_NAME:
            self.mcast_addr = None
            self.controller_address = cfg.get_mgmt_ip()
        else:
            self.mcast_addr = cfg.agent_mcast_group
            self.controller_address = cfg.controller_mcast_group

    def setup_tcp_socket(self):
        hostname = None
        if self.pre_bootstrap:
            hostname = constants.PREBOOTSTRAP_HOSTNAME
        address_family = utils.get_management_family(hostname)
        if self.listener is not None:
            self.listener.close()
        self.listener = socket.socket(address_family, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(('', self.port))
        self.listener.listen(2)  # Allow two connections, for two controllers

    def set_install_failed_flags(self):
        """Set flags and states for a failed patch"""
        self.patch_failed = True
        setflag(patch_failed_file)
        self.state = constants.PATCH_AGENT_STATE_INSTALL_FAILED

    @ostree_utils.ostree_lock
    def query(self, major_release=None):
        """Check current patch state """
        if not self.install_local and not check_install_uuid():
            LOG.info("Failed install_uuid check. Skipping query")
            return False

        # Generate a unique query id
        self.query_id = random.random()

        # determine OSTREE state of the system and the patches
        self.changes = False

        active_sysroot_commit = ostree_utils.get_sysroot_latest_commit()
        self.latest_sysroot_commit = active_sysroot_commit
        self.last_repo_revision = active_sysroot_commit

        # checks if this is a major release deployment operation
        if major_release:
            self.changes = True
            self.latest_feed_commit = None
            return True

        # latest_feed_commit is sent from patch controller
        # if unprovisioned (no mgmt ip) attempt to query it
        if self.latest_feed_commit is None:
            if self.sock_out is None:
                try:
                    self.latest_feed_commit = utils.get_controller_feed_latest_commit(SW_VERSION)
                except OSTreeCommandFail:
                    LOG.warning("Unable to query latest feed commit")
                    # latest_feed_commit will remain as None

        if self.latest_feed_commit:
            if active_sysroot_commit != self.latest_feed_commit:
                LOG.info("Active Sysroot Commit:%s does not match "
                         "active controller's Feed Repo Commit: %s",
                         active_sysroot_commit, self.latest_feed_commit)
                self.changes = True

            latest_deployment_commit = ostree_utils.get_latest_deployment_commit()
            if latest_deployment_commit:
                if latest_deployment_commit != self.latest_feed_commit:
                    LOG.info("Latest deployment Commit:%s does not match "
                             "active controller's Feed Repo Commit: %s",
                             latest_deployment_commit, self.latest_feed_commit)
                    self.changes = True
                else:
                    self.changes = False

        return True

    def handle_install(self,
                       verbose_to_stdout=False,
                       disallow_insvc_patch=False,
                       major_release=None,
                       commit_id=None,
                       additional_data=None):
        #
        # The disallow_insvc_patch parameter is set when we're installing
        # the patch during init. At that time, we don't want to deal with
        # in-service patch scripts, so instead we'll treat any patch as
        # a reboot-required when this parameter is set. Rather than running
        # any scripts, the RR flag will be set, which will result in the node
        # being rebooted immediately upon completion of the installation.
        #

        LOG.info("Handling install")

        # Check the INSTALL_UUID first. If it doesn't match the active
        # controller, we don't want to install patches.
        if not self.install_local and not check_install_uuid():
            LOG.error("Failed install_uuid check. Skipping install")
            self.set_install_failed_flags()

            # Send a hello to provide a state update
            if self.sock_out is not None:
                hello_ack = PatchMessageHelloAgentAck()
                hello_ack.send(self.sock_out)

            return False

        # if commit-id is provided, check if it is already deployed
        if commit_id:
            active_commit_id = ostree_utils.get_latest_deployment_commit()
            if commit_id == active_commit_id:
                LOG.info("The provided commit-id is already deployed. Skipping install.")
                success = True

                # when in major release deployment, if hooks failed in a previous deploy
                # host attempt, a flag is created so that their execution is reattempted here
                if major_release and os.path.exists(run_hooks_flag):
                    additional_data.update({'from_commit_id': active_commit_id,
                                            'to_commit_id': commit_id})

                    LOG.info("Major release deployment %s flag found. "
                             "Running hooks." % run_hooks_flag)
                    try:
                        execute_agent_hooks(major_release, additional_data=additional_data)
                        clearflag(run_hooks_flag)
                    except Exception:
                        success = False

                if success:
                    self.patch_failed = False
                    clearflag(patch_failed_file)
                    self.state = constants.PATCH_AGENT_STATE_IDLE
                else:
                    self.set_install_failed_flags()
                return success

        # prepare major release deployment
        remote = None
        ref = None
        if major_release:
            LOG.info("Major release deployment for %s with commit %s" % (major_release, commit_id))

            # add remote
            nodetype = utils.get_platform_conf("nodetype")
            remote = ostree_utils.add_ostree_remote(major_release, nodetype)
            if not remote:
                LOG.exception("Unable to continue major release deployment as "
                              "there was an error adding the remote.")
                return False
            LOG.info("OSTree remote added: %s" % remote)

            # check if remote commit_id matches with the one sent by the controller
            commit_id_match = ostree_utils.check_commit_id(remote, commit_id)
            if not commit_id_match:
                LOG.exception("The OSTree commit_id %s sent by the controller "
                              "doesn't match with the remote commit_id." % commit_id)
                ostree_utils.delete_ostree_remote(remote)
                ostree_utils.delete_ostree_ref(constants.OSTREE_REF)
                LOG.info("OSTree remote deleted: %s" % remote)
                return False

            ref = "%s:%s" % (remote, constants.OSTREE_REF)

        self.state = constants.PATCH_AGENT_STATE_INSTALLING
        setflag(patch_installing_file)

        try:
            # Create insvc patch directories
            if not os.path.exists(insvc_software_scripts):
                os.makedirs(insvc_software_scripts, 0o700)
            if not os.path.exists(insvc_software_flags):
                os.makedirs(insvc_software_flags, 0o700)
        except Exception:
            LOG.exception("Failed to create in-service patch directories")

        # Send a hello to provide a state update
        if self.sock_out is not None:
            hello_ack = PatchMessageHelloAgentAck()
            hello_ack.send(self.sock_out)

        # Build up the install set
        if verbose_to_stdout:
            print("Checking for software updates...")
        self.query(major_release=major_release)  # sets self.changes

        changed = False
        success = True

        if self.changes or \
                os.path.exists(ostree_pull_completed_deployment_pending_file) or \
                os.path.exists(mount_pending_file):
            try:
                LOG.info("Running pre-install patch-scripts")
                pull_install_scripts_from_controller(install_local=self.install_local)
                subprocess.check_output([run_install_software_scripts_cmd, "preinstall"],
                                        stderr=subprocess.STDOUT)

                # Pull changes from remote to the sysroot ostree
                # The remote value is configured inside
                # "/sysroot/ostree/repo/config" file
                ostree_utils.pull_ostree_from_remote(remote=remote)

                self.query(major_release=major_release)  # Updates following self variables

                if major_release and version.Version(major_release) > version.Version(constants.SW_VERSION):
                    # no backup for rollback
                    deploy_utils.backup_etc(commit_id)

                if self.latest_feed_commit:
                    # If latest_feed_commit is not null, the node can check the deployment health
                    if self.latest_sysroot_commit == self.latest_feed_commit:
                        LOG.info("Pull from remote was successful")
                        setflag(ostree_pull_completed_deployment_pending_file)

                        # Retry deployment creation until successful or maximum retries reached
                        retries = 0
                        while not changed and retries < constants.MAX_OSTREE_DEPLOY_RETRIES:
                            latest_deployment = None
                            try:
                                # Create a new deployment once the changes are pulled
                                ostree_utils.create_deployment(ref=ref)
                                latest_deployment = ostree_utils.get_latest_deployment_commit()
                            except OSTreeCommandFail:
                                LOG.warning("Failed to create deployment during host-install.")

                            if latest_deployment and \
                                    latest_deployment == self.latest_feed_commit:
                                changed = True
                                clearflag(ostree_pull_completed_deployment_pending_file)
                            else:
                                retries += 1
                                LOG.warning("Deloyment not created in %d attempt(s)", retries)
                                time.sleep(10)
                    else:
                        LOG.error("Sysroot commit does not match the feed commit. "
                                  "Skipping deployment retries")
                else:
                    # If not able to retrieve latest_feed_commit, proceed without retries
                    LOG.info("Creating ostree deployment without live retry")
                    setflag(ostree_pull_completed_deployment_pending_file)
                    ostree_utils.create_deployment(ref=ref)
                    changed = True
                    clearflag(ostree_pull_completed_deployment_pending_file)

                # Creating a new deployment restores the kernel.env from ostree
                # which does not have local modifications (such as selecting a RT kernel)
                # We need to re-align that file after creating a deployment.
                ostree_utils.update_deployment_kernel_env()

            except OSTreeCommandFail:
                LOG.exception("Failed to pull changes and create deployment"
                              "during host-install.")
            except subprocess.CalledProcessError as e:
                LOG.exception("Failed to execute pre-install scripts.")
                LOG.error("Command output: %s", e.output)

            success = changed  # If a change was made, success is true otherwise false

            if changed:
                # Update the node_is_patched flag
                setflag(node_is_patched_file)

                self.node_is_patched = True
                if verbose_to_stdout:
                    print("This node has been patched.")

                if os.path.exists(node_is_software_updated_rr_file):
                    LOG.info("Reboot is required. Skipping patch-scripts")
                elif disallow_insvc_patch:
                    LOG.info("Disallowing patch-scripts. Treating as reboot-required")
                    setflag(node_is_software_updated_rr_file)
                else:
                    LOG.info("Mounting the new deployment")
                    try:
                        pending_deployment = ostree_utils.fetch_pending_deployment()
                        deployment_dir = constants.OSTREE_BASE_DEPLOYMENT_DIR + pending_deployment
                        active_deployment = ostree_utils.fetch_active_deployment()
                        active_dir = constants.OSTREE_BASE_DEPLOYMENT_DIR + active_deployment
                        setflag(mount_pending_file)
                        ostree_utils.mount_new_deployment(deployment_dir, active_dir)
                        clearflag(mount_pending_file)
                        LOG.info("Running post-install patch-scripts")
                        subprocess.check_output([run_install_software_scripts_cmd, "postinstall"],
                                                stderr=subprocess.STDOUT)

                        # Clear the node_is_patched flag, since we've handled it in-service
                        clearflag(node_is_patched_file)
                        self.node_is_patched = False
                    except subprocess.CalledProcessError as e:
                        LOG.exception("Failed to execute post-install scripts.")
                        LOG.error("Command output: %s", e.output)
                        success = False

        # Clear the in-service patch dirs
        if os.path.exists(insvc_software_scripts):
            shutil.rmtree(insvc_software_scripts, ignore_errors=True)
        if os.path.exists(insvc_software_flags):
            shutil.rmtree(insvc_software_flags, ignore_errors=True)

        if success:
            self.patch_failed = False
            clearflag(patch_failed_file)
            self.state = constants.PATCH_AGENT_STATE_IDLE

            # run deploy host hooks for major release
            if major_release:
                try:
                    execute_agent_hooks(major_release, additional_data=additional_data)
                except Exception:
                    setflag(run_hooks_flag)
                    self.set_install_failed_flags()
                    success = False
        else:
            self.set_install_failed_flags()

        clearflag(patch_installing_file)

        self.query()  # Update self.changes
        if self.changes:
            LOG.warning("Installing the patch did not change the patch current status")

            if os.path.exists(node_is_software_updated_rr_file):
                LOG.error("No deployment created and reboot required flag exists")
                self.set_install_failed_flags()
                # Clear flag to avoid reboot loop
                clearflag(node_is_software_updated_rr_file)

        # Send a hello to provide a state update
        if self.sock_out is not None:
            hello_ack = PatchMessageHelloAgentAck()
            hello_ack.send(self.sock_out)

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

    def handle_bootstrap(self, connections):
        # If bootstrap is completed re-initialize sockets
        self.pre_bootstrap = False
        self.install_local = False
        self.setup_socket()
        while self.sock_out is None:
            time.sleep(30)
            self.setup_socket()
        self.setup_tcp_socket()
        hello_ack = PatchMessageHelloAgentAck()
        hello_ack.send(self.sock_out)

        for s in connections:
            connections.remove(s)
            s.close()

    @utils.interval_task(interval_sec=10)
    def update_node(self):
        update = PatchMessageHelloAgentAck()
        update.send(self.sock_out)

    @staticmethod
    @utils.interval_task(interval_sec=30)
    def check_for_restart():
        # Check for in-service patch restart flag
        if os.path.exists(insvc_software_restart_agent):
            # Restart
            LOG.info("In-service software restart flag detected. Exiting.")
            os.remove(insvc_software_restart_agent)
            exit(0)

    def run(self):
        # Check if bootstrap stage is completed
        if self.pre_bootstrap and cfg.get_mgmt_ip():
            self.pre_bootstrap = False

        if self.pre_bootstrap or os.path.isfile(constants.INSTALL_LOCAL_FLAG):
            self.install_local = True
        else:
            self.install_local = False

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

        min_interval_sec = 2

        while True:
            if self.pre_bootstrap and cfg.get_mgmt_ip():
                self.handle_bootstrap(connections)
                first_hello = True

            if os.path.isfile(constants.INSTALL_LOCAL_FLAG) or self.pre_bootstrap:
                self.install_local = True
            else:
                self.install_local = False

            inputs = [self.sock_in, self.listener] + connections
            outputs = []

            rlist, wlist, xlist = select.select(inputs, outputs, inputs, min_interval_sec)

            if (len(rlist) == 0 and
                    len(wlist) == 0 and
                    len(xlist) == 0):
                # Timeout hit
                self.audit_socket()

                self.check_for_restart()
                self.update_node()
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
                    elif msgdata['msgtype'] == messages.PATCHMSG_DEPLOY_DELETE_CLEANUP_REQ:
                        msg = SoftwareMessageDeployDeleteCleanupReq()
                    elif msgdata['msgtype'] == messages.PATCHMSG_CHECK_AGENT_ALIVE_REQ:
                        msg = SoftwareMessageCheckAgentAliveReq()

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


def main():
    global pa

    cfg.read_config()

    configure_logging()

    pa = PatchAgent()
    if os.path.isfile(constants.INSTALL_LOCAL_FLAG):
        pa.install_local = True
    else:
        pa.install_local = False

    pa.query()

    # Run on reboot after the node was updated by a reboot required patch/ISO
    if os.path.exists(node_is_software_updated_rr_file):
        ostree_utils.delete_older_deployments()
        run_post_install_script()
        clearflag(node_is_software_updated_rr_file)

    if len(sys.argv) <= 1:
        pa.run()
    elif sys.argv[1] == "--install":
        if not pa.install_local and not check_install_uuid():
            # In certain cases, the lighttpd server could still be running using
            # its default port 80, as opposed to the port configured in platform.conf
            global http_port_real
            LOG.info("Failed install_uuid check via http_port=%s. Trying with default port 80", http_port_real)
            http_port_real = 80

        pa.handle_install(verbose_to_stdout=True,
                          disallow_insvc_patch=True)
    elif sys.argv[1] == "--status":
        rc = 0
        if pa.changes:
            rc = 1
        exit(rc)
