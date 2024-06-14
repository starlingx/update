"""
Copyright (c) 2024 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import os
import socket
import subprocess
import tempfile
import yaml

from software.software_functions import LOG
from software.software_functions import mount_remote_directory
from software import constants


class BaseHook(object):
    """Base Hook object"""
    def __init__(self, attrs=None):
        pass

    def run(self):
        pass


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
        else:
            LOG.exception("Cannot copy pxeboot files, major_release value is %s" %
                          self._major_release)


class ReconfigureKernelHook(BaseHook):
    """
    Reconfigure the kernel post deploy host command by using
    the kernel puppet manifest to ensure the host kernel type
    (low-latency or standard) persists after the host is unlocked
    and reboots running N+1 release.
    """
    def __init__(self, attrs):
        super().__init__()
        self._major_release = None
        if "major_release" in attrs:
            self._major_release = attrs.get("major_release")

    @staticmethod
    def apply_manifest(manifest_file, puppet_path, personalities=constants.CONTROLLER):
        """
        Apply kernel puppet manifest
        :param manifest_file: yaml file containing the puppet classes to be executed
        :param puppet_path: hieradata directory location
        :param personalities: host personalities that manifest should be applied
        """
        try:
            cmd = [
                "/usr/local/bin/puppet-manifest-apply.sh",
                puppet_path,
                socket.gethostname(),
                personalities,
                "runtime",
                manifest_file,
            ]
            subprocess.check_call(cmd)
            LOG.info("Executed kernel puppet manifest.")
        except subprocess.CalledProcessError as e:
            LOG.exception("Error running kernel puppet manifest: %s" % str(e))

    def run(self):
        """Execute the hook"""
        # create manifest file
        fp, manifest_file = tempfile.mkstemp(suffix=".yaml")
        classes = {"classes": ["platform::grub::kernel_image"]}
        with open(manifest_file, "w") as fd:
            yaml.dump(classes, fd, default_flow_style=False)

        try:
            # set host personalities and puppet hieradata path
            personalities = "%s,%s" % (constants.CONTROLLER, constants.WORKER)
            puppet_path = os.path.join(constants.tsc.PLATFORM_PATH, "puppet",
                                       self._major_release, "hieradata")
            if os.path.isdir(puppet_path):
                ReconfigureKernelHook.apply_manifest(manifest_file, puppet_path,
                                                     personalities=personalities)
                return

            # if not running on active controller then must remote mount hieradata
            remote_dir = "controller-platform-nfs:" + constants.tsc.PLATFORM_PATH
            local_dir = os.path.join(constants.tsc.VOLATILE_PATH, "platform")
            LOG.info("Not running in active controller, mounting %s into %s" % (remote_dir,
                                                                                local_dir))
            with mount_remote_directory(remote_dir, local_dir):
                # try to use the TO release puppet hieradata if available for the host,
                # and if not available then use the FROM hieradata path, since the kernel
                # manifest does not rely on any specific host hieradata information
                puppet_path = os.path.join(local_dir, "puppet/%s/hieradata")
                host_hieradata = os.path.join(puppet_path, "%s.yaml" % socket.gethostname())
                if os.path.isfile(host_hieradata % self._major_release):
                    puppet_path = puppet_path % self._major_release
                else:
                    puppet_path = puppet_path % constants.SW_VERSION
                ReconfigureKernelHook.apply_manifest(manifest_file, puppet_path,
                                                     personalities=personalities)
        except Exception as e:
            LOG.exception("Error running reconfigure kernel hook: %s" % str(e))
        finally:
            os.close(fp)
            os.remove(manifest_file)


# pre and post keywords
PRE = "pre"
POST = "post"

# actions
MAJOR_RELEASE_UPGRADE = "major_release_upgrade"

# agent hooks mapping per action
AGENT_HOOKS = {
    MAJOR_RELEASE_UPGRADE: {
        PRE: [],
        POST: [
            CopyPxeFilesHook,
            ReconfigureKernelHook,
        ]
    }
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
