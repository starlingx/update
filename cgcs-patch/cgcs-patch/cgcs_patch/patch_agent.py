"""
Copyright (c) 2014-2019 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import dnf
import dnf.callback
import dnf.comps
import dnf.exceptions
import dnf.rpm
import dnf.sack
import dnf.transaction
import json
import libdnf.transaction
import os
import random
import requests
import select
import shutil
import socket
import subprocess
import sys
import time

from cgcs_patch.patch_functions import configure_logging
from cgcs_patch.patch_functions import LOG
import cgcs_patch.config as cfg
from cgcs_patch.base import PatchService
import cgcs_patch.utils as utils
import cgcs_patch.messages as messages
import cgcs_patch.constants as constants

from tsconfig.tsconfig import http_port
from tsconfig.tsconfig import install_uuid
from tsconfig.tsconfig import subfunctions
from tsconfig.tsconfig import SW_VERSION

pidfile_path = "/var/run/patch_agent.pid"
node_is_patched_file = "/var/run/node_is_patched"
node_is_patched_rr_file = "/var/run/node_is_patched_rr"
patch_installing_file = "/var/run/patch_installing"
patch_failed_file = "/var/run/patch_install_failed"
node_is_locked_file = "/var/run/.node_locked"

insvc_patch_scripts = "/run/patching/patch-scripts"
insvc_patch_flags = "/run/patching/patch-flags"
insvc_patch_restart_agent = "/run/patching/.restart.patch-agent"

run_insvc_patch_scripts_cmd = "/usr/sbin/run-patch-scripts"

pa = None

http_port_real = http_port

# DNF commands
dnf_cmd = ['/bin/dnf']
dnf_quiet = dnf_cmd + ['--quiet']
dnf_makecache = dnf_quiet + ['makecache',
                             '--disablerepo="*"',
                             '--enablerepo', 'platform-base',
                             '--enablerepo', 'platform-updates']


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
        sock.sendto(message, (pa.controller_address, cfg.controller_port))


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
        self.message['installed'] = pa.installed
        self.message['to_remove'] = pa.to_remove
        self.message['missing_pkgs'] = pa.missing_pkgs
        self.message['nodetype'] = cfg.nodetype
        self.message['sw_version'] = SW_VERSION
        self.message['subfunctions'] = subfunctions
        self.message['state'] = pa.state

    def handle(self, sock, addr):
        LOG.error("Should not get here")

    def send(self, sock):
        self.encode()
        message = json.dumps(self.message)
        sock.sendall(message)


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
        sock.sendto(message, address)

        # Send a hello ack to follow it
        resp = PatchMessageHelloAgentAck()
        resp.send(sock)


class PatchAgentDnfTransLogCB(dnf.callback.TransactionProgress):
    def __init__(self):
        dnf.callback.TransactionProgress.__init__(self)

        self.log_prefix = 'dnf trans'

    def progress(self, package, action, ti_done, ti_total, ts_done, ts_total):
        if action in dnf.transaction.ACTIONS:
            action_str = dnf.transaction.ACTIONS[action]
        elif action == dnf.transaction.TRANS_POST:
            action_str = 'Post transaction'
        else:
            action_str = 'unknown(%d)' % action

        if ti_done is not None:
            # To reduce the volume of logs, only log 0% and 100%
            if ti_done == 0 or ti_done == ti_total:
                LOG.info('%s PROGRESS %s: %s %0.1f%% [%s/%s]',
                         self.log_prefix, action_str, package,
                         (ti_done * 100 / ti_total),
                         ts_done, ts_total)
        else:
            LOG.info('%s PROGRESS %s: %s [%s/%s]',
                     self.log_prefix, action_str, package, ts_done, ts_total)

    def filelog(self, package, action):
        if action in dnf.transaction.FILE_ACTIONS:
            msg = '%s: %s' % (dnf.transaction.FILE_ACTIONS[action], package)
        else:
            msg = '%s: %s' % (package, action)
        LOG.info('%s FILELOG %s', self.log_prefix, msg)

    def scriptout(self, msgs):
        if msgs:
            LOG.info("%s SCRIPTOUT :\n%s", self.log_prefix, msgs)

    def error(self, message):
        LOG.error("%s ERROR: %s", self.log_prefix, message)


class PatchAgent(PatchService):
    def __init__(self):
        PatchService.__init__(self)
        self.sock_out = None
        self.sock_in = None
        self.controller_address = None
        self.listener = None
        self.changes = False
        self.installed = {}
        self.installed_dnf = []
        self.to_install = {}
        self.to_install_dnf = []
        self.to_downgrade_dnf = []
        self.to_remove = []
        self.to_remove_dnf = []
        self.missing_pkgs = []
        self.missing_pkgs_dnf = []
        self.patch_op_counter = 0
        self.node_is_patched = os.path.exists(node_is_patched_file)
        self.node_is_patched_timestamp = 0
        self.query_id = 0
        self.state = constants.PATCH_AGENT_STATE_IDLE
        self.last_config_audit = 0
        self.rejection_timestamp = 0
        self.dnfb = None

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

    @staticmethod
    def pkgobjs_to_list(pkgobjs):
        # Transform pkgobj list to format used by patch-controller
        output = {}
        for pkg in pkgobjs:
            if pkg.epoch != 0:
                output[pkg.name] = "%s:%s-%s@%s" % (pkg.epoch, pkg.version, pkg.release, pkg.arch)
            else:
                output[pkg.name] = "%s-%s@%s" % (pkg.version, pkg.release, pkg.arch)

        return output

    def dnf_reset_client(self):
        if self.dnfb is not None:
            self.dnfb.close()
            self.dnfb = None

        self.dnfb = dnf.Base()
        self.dnfb.conf.substitutions['infra'] = 'stock'

        # Reset default installonlypkgs list
        self.dnfb.conf.installonlypkgs = []

        self.dnfb.read_all_repos()

        # Ensure only platform repos are enabled for transaction
        for repo in self.dnfb.repos.all():
            if repo.id == 'platform-base' or repo.id == 'platform-updates':
                repo.enable()
            else:
                repo.disable()

        # Read repo info
        self.dnfb.fill_sack()

    def query(self):
        """ Check current patch state """
        if not check_install_uuid():
            LOG.info("Failed install_uuid check. Skipping query")
            return False

        if self.dnfb is not None:
            self.dnfb.close()
            self.dnfb = None

        # TODO(dpenney): Use python APIs for makecache
        try:
            subprocess.check_output(dnf_makecache, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            LOG.error("Failed to run dnf makecache")
            LOG.error("Command output: %s", e.output)
            # Set a state to "unknown"?
            return False

        # Generate a unique query id
        self.query_id = random.random()

        self.changes = False
        self.installed_dnf = []
        self.installed = {}
        self.to_install_dnf = []
        self.to_downgrade_dnf = []
        self.to_remove = []
        self.to_remove_dnf = []
        self.missing_pkgs = []
        self.missing_pkgs_dnf = []

        self.dnf_reset_client()

        # Get the repo data
        pkgs_installed = dnf.sack._rpmdb_sack(self.dnfb).query().installed()  # pylint: disable=protected-access
        avail = self.dnfb.sack.query().available().latest()

        # There are three possible actions:
        # 1. If installed pkg is not in a repo, remove it.
        # 2. If installed pkg version does not match newest repo version, update it.
        # 3. If a package in the grouplist is not installed, install it.

        for pkg in pkgs_installed:
            highest = avail.filter(name=pkg.name, arch=pkg.arch)
            if highest:
                highest_pkg = highest[0]

                if pkg.evr_eq(highest_pkg):
                    continue

                if pkg.evr_gt(highest_pkg):
                    self.to_downgrade_dnf.append(highest_pkg)
                else:
                    self.to_install_dnf.append(highest_pkg)
            else:
                self.to_remove_dnf.append(pkg)
                self.to_remove.append(pkg.name)

            self.installed_dnf.append(pkg)
            self.changes = True

        # Look for new packages
        self.dnfb.read_comps()
        grp_id = 'updates-%s' % '-'.join(subfunctions)
        pkggrp = None
        for grp in self.dnfb.comps.groups_iter():
            if grp.id == grp_id:
                pkggrp = grp
                break

        if pkggrp is None:
            LOG.error("Could not find software group: %s", grp_id)

        for pkg in pkggrp.packages_iter():
            try:
                res = pkgs_installed.filter(name=pkg.name)
                if len(res) == 0:
                    found_pkg = avail.filter(name=pkg.name)
                    self.missing_pkgs_dnf.append(found_pkg[0])
                    self.missing_pkgs.append(found_pkg[0].name)
                    self.changes = True
            except dnf.exceptions.PackageNotFoundError:
                self.missing_pkgs_dnf.append(pkg)
                self.missing_pkgs.append(pkg.name)
                self.changes = True

        self.installed = self.pkgobjs_to_list(self.installed_dnf)
        self.to_install = self.pkgobjs_to_list(self.to_install_dnf + self.to_downgrade_dnf)

        LOG.info("Patch state query returns %s", self.changes)
        LOG.info("Installed: %s", self.installed)
        LOG.info("To install: %s", self.to_install)
        LOG.info("To remove: %s", self.to_remove)
        LOG.info("Missing: %s", self.missing_pkgs)

        return True

    def resolve_dnf_transaction(self, undo_failure=True):
        LOG.info("Starting to process transaction: undo_failure=%s", undo_failure)
        self.dnfb.resolve()
        self.dnfb.download_packages(self.dnfb.transaction.install_set)

        tid = self.dnfb.do_transaction(display=PatchAgentDnfTransLogCB())

        transaction_rc = True
        for t in self.dnfb.transaction:
            if t.state != libdnf.transaction.TransactionItemState_DONE:
                transaction_rc = False
                break

        self.dnf_reset_client()

        if not transaction_rc:
            if undo_failure:
                LOG.error("Failure occurred... Undoing last transaction (%s)", tid)
                old = self.dnfb.history.old((tid,))[0]
                mobj = dnf.db.history.MergedTransactionWrapper(old)

                self.dnfb._history_undo_operations(mobj, old.tid, True)  # pylint: disable=protected-access

                if not self.resolve_dnf_transaction(undo_failure=False):
                    LOG.error("Failed to undo transaction")

        LOG.info("Transaction complete: undo_failure=%s, success=%s", undo_failure, transaction_rc)
        return transaction_rc

    def handle_install(self, verbose_to_stdout=False, disallow_insvc_patch=False):
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

        try:
            # Create insvc patch directories
            if os.path.exists(insvc_patch_scripts):
                shutil.rmtree(insvc_patch_scripts, ignore_errors=True)
            if os.path.exists(insvc_patch_flags):
                shutil.rmtree(insvc_patch_flags, ignore_errors=True)
            os.mkdir(insvc_patch_scripts, 0o700)
            os.mkdir(insvc_patch_flags, 0o700)
        except Exception:
            LOG.exception("Failed to create in-service patch directories")

        # Send a hello to provide a state update
        if self.sock_out is not None:
            hello_ack = PatchMessageHelloAgentAck()
            hello_ack.send(self.sock_out)

        # Build up the install set
        if verbose_to_stdout:
            print("Checking for software updates...")
        self.query()

        changed = False
        rc = True

        if len(self.to_install_dnf) > 0 or len(self.to_downgrade_dnf) > 0:
            LOG.info("Adding pkgs to installation set: %s", self.to_install)
            for pkg in self.to_install_dnf:
                self.dnfb.package_install(pkg)

            for pkg in self.to_downgrade_dnf:
                self.dnfb.package_downgrade(pkg)

            changed = True

        if len(self.missing_pkgs_dnf) > 0:
            LOG.info("Adding missing pkgs to installation set: %s", self.missing_pkgs)
            for pkg in self.missing_pkgs_dnf:
                self.dnfb.package_install(pkg)
            changed = True

        if len(self.to_remove_dnf) > 0:
            LOG.info("Adding pkgs to be removed: %s", self.to_remove)
            for pkg in self.to_remove_dnf:
                self.dnfb.package_remove(pkg)
            changed = True

        if changed:
            # Run the transaction set
            transaction_rc = False
            try:
                transaction_rc = self.resolve_dnf_transaction()
            except dnf.exceptions.DepsolveError:
                LOG.error("Failures resolving dependencies in transaction")
            except dnf.exceptions.DownloadError:
                LOG.error("Failures downloading in transaction")

            if not transaction_rc:
                LOG.error("Failures occurred during transaction")
                rc = False
                if verbose_to_stdout:
                    print("WARNING: Software update failed.")

        else:
            if verbose_to_stdout:
                print("Nothing to install.")
            LOG.info("Nothing to install")

        if changed and rc:
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
                LOG.info("Running in-service patch-scripts")

                try:
                    subprocess.check_output(run_insvc_patch_scripts_cmd, stderr=subprocess.STDOUT)

                    # Clear the node_is_patched flag, since we've handled it in-service
                    clearflag(node_is_patched_file)
                    self.node_is_patched = False
                except subprocess.CalledProcessError as e:
                    LOG.exception("In-Service patch scripts failed")
                    LOG.error("Command output: %s", e.output)
                    # Fail the patching operation
                    rc = False

        # Clear the in-service patch dirs
        if os.path.exists(insvc_patch_scripts):
            shutil.rmtree(insvc_patch_scripts, ignore_errors=True)
        if os.path.exists(insvc_patch_flags):
            shutil.rmtree(insvc_patch_flags, ignore_errors=True)

        if rc:
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

        # Send a hello to provide a state update
        if self.sock_out is not None:
            hello_ack = PatchMessageHelloAgentAck()
            hello_ack.send(self.sock_out)

        return rc

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
                            data += packet

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

    configure_logging(dnf_log=True)

    cfg.read_config()

    pa = PatchAgent()
    pa.query()

    if len(sys.argv) <= 1:
        pa.run()
    elif sys.argv[1] == "--install":
        if not check_install_uuid():
            # In certain cases, the lighttpd server could still be running using
            # its default port 80, as opposed to the port configured in platform.conf
            global http_port_real
            LOG.info("Failed install_uuid check via http_port=%s. Trying with default port 80", http_port_real)
            http_port_real = 80

        pa.handle_install(verbose_to_stdout=True, disallow_insvc_patch=True)
    elif sys.argv[1] == "--status":
        rc = 0
        if pa.changes:
            rc = 1
        exit(rc)
