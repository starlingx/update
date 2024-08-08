"""
Copyright (c) 2024 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import filecmp
import glob
import os
import shutil
import socket
import subprocess

import software.constants as constants
from software.software_functions import LOG
import software.utils as utils


class BaseHook(object):
    """Base Hook object"""
    def __init__(self, attrs=None):
        pass

    def run(self):
        pass


class UsmInitHook(BaseHook):
    def run(self):
        cmd = "systemctl enable usm-initialize.service"
        try:
            subprocess.check_call(cmd, shell=True)
        except subprocess.CalledProcessError as e:
            LOG.exception("Error enabling usm-initialize.service: %s" % str(e))
            raise
        LOG.info("Enabled usm-initialize.service on next reboot")


class EnableNewServicesHook(BaseHook):
    SYSTEM_PRESET_DIR = "/etc/systemd/system-preset"
    DEPLOYED_OSTREE_DIR = "/ostree/1"
    SYSTEMD_LIB_DIR = "/lib/systemd/system"
    SYSTEMD_ETC_DIR = "%s/etc/systemd/system/multi-user.target.wants" % DEPLOYED_OSTREE_DIR

    def find_new_services(self):
        # get preset name
        system_preset = None
        presets = os.listdir(self.SYSTEM_PRESET_DIR)
        for preset in presets:
            if preset.startswith("10-"):
                system_preset = os.readlink("%s/%s" % (self.SYSTEM_PRESET_DIR, preset))
        if not system_preset:
            raise FileNotFoundError("System preset not found.")

        # read from-release preset
        with open(system_preset, "r") as fp:
            from_preset = fp.readlines()
            from_services = [line.strip().split(" ")[1] for line in from_preset
                             if line.startswith("enable")]
        # read to-release preset
        with open("%s/%s" % (self.DEPLOYED_OSTREE_DIR, system_preset), "r") as fp:
            to_preset = fp.readlines()
            to_services = [line.strip().split(" ")[1] for line in to_preset
                           if line.startswith("enable")]

        # compare to find new services
        # output will come as "+ <service>" for new service in to-release
        new_services = list(set(to_services) - set(from_services))
        LOG.info("New services found: %s" % ", ".join(new_services))
        return new_services

    def enable_new_services(self, services):
        for service in services:
            src = "%s/%s" % (self.SYSTEMD_LIB_DIR, service)
            dst = "%s/%s" % (self.SYSTEMD_ETC_DIR, service)
            try:
                os.symlink(src, dst)
                LOG.info("Enabled %s" % service)
            except subprocess.CalledProcessError as e:
                LOG.exception("Error enabling %s: %s" % (service, str(e)))
                raise

    def run(self):
        new_services = self.find_new_services()
        self.enable_new_services(new_services)


class CopyPxeFilesHook(BaseHook):
    """
    Copy pxeboot files from the target feed post deploy host during
    major release deployment. These files are copied during the
    release upload, but only to the host where it is uploaded, so
    this post action is needed to copy the files to other hosts.
    """
    def __init__(self, attrs):
        super().__init__()
        self._major_release = None
        if "major_release" in attrs:
            self._major_release = attrs.get("major_release")

    def run(self):
        """Execute the hook"""
        nodetype = utils.get_platform_conf("nodetype")
        if nodetype == constants.CONTROLLER:
            if self._major_release:
                # copy to_release pxeboot files to /var/pxeboot/pxelinux.cfg.files
                pxeboot_feed_dir = ("/var/www/pages/feed/rel-%s/pxeboot/pxelinux.cfg.files/*" %
                                    self._major_release)
                pxeboot_dest_dir = "/var/pxeboot/pxelinux.cfg.files/"
                cmd = "rsync -ac %s %s" % (pxeboot_feed_dir, pxeboot_dest_dir)
                try:
                    subprocess.check_call(cmd, shell=True)
                    LOG.info(
                        "Copied %s pxeboot files to %s." % (
                            self._major_release, pxeboot_dest_dir))
                except subprocess.CalledProcessError as e:
                    LOG.exception("Error copying pxeboot files from %s to %s: %s" % (
                        pxeboot_feed_dir, pxeboot_dest_dir, str(e)))
                    raise
            else:
                LOG.error("Cannot copy pxeboot files, major_release value is %s" %
                          self._major_release)


class ReconfigureKernelHook(BaseHook):
    """
    Reconfigure the kernel post deploy host command by updating the
    /boot/1/kernel.env file, to ensure the host kernel type (low-latency
    or standard) persists after the host is unlocked and reboots running
    N+1 release.
    """
    def __init__(self, attrs):
        super().__init__()

    def run(self):
        """Execute the hook"""
        try:
            subfunctions = utils.get_platform_conf("subfunction")
            # copy /boot/2/kernel.env to /boot/1/kernel.env
            # this is to preserve args (ie: apparmor)
            # if the files are identical, do nothing
            if not filecmp.cmp("/boot/1/kernel.env",
                               "/boot/2/kernel.env",
                               shallow=False):
                shutil.copy2("/boot/2/kernel.env",
                             "/boot/1/kernel.env")
            # Determine the appropriate kernel for this env
            desired_kernel = None
            for kernel in glob.glob(os.path.join("/boot/1", "vmlinuz*-amd64")):
                kernel_entry = os.path.basename(kernel)
                # If we are running in lowlatency mode, we want the rt-amd64 kernel
                if 'lowlatency' in subfunctions and 'rt-amd64' in kernel_entry:
                    desired_kernel = kernel_entry
                    break
                # If we are not running lowlatency we want the entry that does NOT contain rt-amd64
                if 'lowlatency' not in subfunctions and 'rt-amd64' not in kernel_entry:
                    desired_kernel = kernel_entry
                    break
            if desired_kernel is None:  # This should never happen
                LOG.warning("Unable to find a valid kernel under /boot/1")
            else:
                # Explicitly update /boot/1/kernel.env using the
                # /usr/local/bin/puppet-update-grub-env.py utility
                LOG.info("Updating /boot/1/kernel.env to:%s", desired_kernel)
                cmd = "python /usr/local/bin/puppet-update-grub-env.py --set-kernel %s" % desired_kernel
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            msg = ("Failed to run puppet-update-grub-env.py: rc=%s, output=%s"
                   % (e.returncode, e.stderr.decode("utf-8")))
            LOG.exception(msg)
        except Exception as e:
            msg = "Failed to manually update /boot/1/kernel.env. Err=%s" % str(e)
            LOG.exception(msg)


class CreateUSMUpgradeInProgressFlag(BaseHook):
    def __init__(self, attrs):
        super().__init__(attrs)

    def run(self):
        flag_file = constants.USM_UPGRADE_IN_PROGRESS_FLAG
        with open(flag_file, "w") as _:
            LOG.info("Created %s flag" % flag_file)


class RemoveKubernetesConfigSymlinkHook(BaseHook):
    K8S_ENCRYPTION_PROVIDER_FILE = "/etc/kubernetes/encryption-provider.yaml"

    def run(self):
        try:
            os.unlink(self.K8S_ENCRYPTION_PROVIDER_FILE)
            LOG.info("%s symlink removed" % self.K8S_ENCRYPTION_PROVIDER_FILE)
        except Exception as e:
            LOG.exception("Failed to remove symlink: %s" % str(e))
            raise


class RemoveCephMonHook(BaseHook):
    """
    Remove additional ceph-mon added for each controller
    """
    PMON_FILE = "/ostree/1/etc/pmon.d/ceph-fixed-mon.conf"

    def run(self):
        system_type = utils.get_platform_conf("system_type")
        system_mode = utils.get_platform_conf("system_mode")
        nodetype = utils.get_platform_conf("nodetype")
        hostname = socket.gethostname()
        # additional monitors were added only for AIO-DX
        if (system_type == constants.SYSTEM_TYPE_ALL_IN_ONE and
                system_mode != constants.SYSTEM_MODE_SIMPLEX and
                nodetype == constants.CONTROLLER):
            cmd = ["ceph", "mon", "rm", hostname]
            try:
                subprocess.check_call(cmd)
                LOG.info("Removed mon.%s from ceph cluster." % hostname)
            except subprocess.CalledProcessError as e:
                LOG.exception("Failure removing mon.%s from ceph cluster: %s" % (hostname, str(e)))
                raise
            os.unlink(self.PMON_FILE)
            LOG.info("Removed %s from pmon." % self.PMON_FILE)


# pre and post keywords
PRE = "pre"
POST = "post"

# actions
MAJOR_RELEASE_UPGRADE = "major_release_upgrade"
MAJOR_RELEASE_ROLLBACK = "major_release_rollback"

# agent hooks mapping per action
AGENT_HOOKS = {
    MAJOR_RELEASE_UPGRADE: {
        PRE: [
            CreateUSMUpgradeInProgressFlag,
            UsmInitHook,
        ],
        POST: [
            CopyPxeFilesHook,
            ReconfigureKernelHook,
            EnableNewServicesHook,
        ],
    },
    MAJOR_RELEASE_ROLLBACK: {
        PRE: [
            RemoveKubernetesConfigSymlinkHook,
            UsmInitHook,
        ],
        POST: [
            ReconfigureKernelHook,
            RemoveCephMonHook,
        ],
    },
}


class HookManager(object):
    """
    Object to manage the execution of agent hooks
    """
    def __init__(self, action, attrs=None):
        self._action = action
        self._attrs = attrs
        self._pre_hooks = AGENT_HOOKS.get(action).get(PRE)
        self._post_hooks = AGENT_HOOKS.get(action).get(POST)

    def _run_hooks(self, timing):
        """
        Run all hooks registered under the self._action value
        :param timing: pre (before install) or post (after successful install)
        """
        if timing == PRE:
            hooks = self._pre_hooks
        elif timing == POST:
            hooks = self._post_hooks
        else:
            LOG.error("Invalid parameter: timing=%s" % timing)
            return

        LOG.info("Running %s-hooks for '%s'" % (timing, self._action))
        for hook in hooks:
            pg = hook(self._attrs)
            pg.run()

    def run_pre_hooks(self):
        self._run_hooks(PRE)

    def run_post_hooks(self):
        self._run_hooks(POST)
