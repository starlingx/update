"""
Copyright (c) 2024 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import filecmp
import glob
import os
import re
import shutil
import subprocess

import software.constants as constants
from software.software_functions import LOG
import software.utils as utils


class BaseHook(object):
    """Base Hook object"""
    DEPLOYED_OSTREE_DIR = "/ostree/1"
    ROLLBACK_OSTREE_DIR = "/ostree/2"
    SYSTEMD_LIB_DIR = "/lib/systemd/system"
    SYSTEMD_ETC_DIR = "%s/etc/systemd/system/multi-user.target.wants" % DEPLOYED_OSTREE_DIR

    def __init__(self, attrs=None):
        pass

    def run(self):
        pass

    def enable_service(self, service):
        src = "%s/%s" % (self.SYSTEMD_LIB_DIR, service)
        dst = "%s/%s" % (self.SYSTEMD_ETC_DIR, service)
        # Add check to enable reentrant
        if not os.path.islink(dst):
            try:
                os.symlink(src, dst)
                LOG.info("Enabled %s" % service)
            except subprocess.CalledProcessError as e:
                LOG.exception("Error enabling %s: %s" % (service, str(e)))
                raise


class UsmInitHook(BaseHook):
    def run(self):
        self.enable_service("usm-initialize.service")
        LOG.info("Enabled usm-initialize.service on next reboot")


class EnableNewServicesHook(BaseHook):
    SYSTEM_PRESET_DIR = "/etc/systemd/system-preset"

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
            self.enable_service(service)

    def run(self):
        new_services = self.find_new_services()
        self.enable_new_services(new_services)


class CopyPxeFilesHook(BaseHook):
    """
    Copy pxeboot files from the to-release ostree on 'deploy host'
    for major release deployment. These files are copied during the
    release upload, but only to the host where it is uploaded, so
    this post hook is needed to copy the files to other hosts.
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
                pxeboot_dst_dir = "/var/pxeboot/pxelinux.cfg.files/"
                pxeboot_src_dir = self.DEPLOYED_OSTREE_DIR + pxeboot_dst_dir  # deployed to-release ostree dir
                cmd = "rsync -ac %s %s" % (pxeboot_src_dir, pxeboot_dst_dir)
                try:
                    subprocess.run(cmd, shell=True, check=True, capture_output=True)
                    LOG.info("Copied %s pxeboot files to %s" %
                             (self._major_release, pxeboot_dst_dir))
                except subprocess.CalledProcessError as e:
                    LOG.exception("Error copying pxeboot files from %s to %s: %s" % (
                        pxeboot_src_dir, pxeboot_dst_dir, e.stderr.decode("utf-8")))
                    raise

                # ensure the script pxeboot-update-<from-release>.sh is in to-release /etc
                try:
                    cmd = "rsync -aci %s %s/etc" % (self.ROLLBACK_OSTREE_DIR + "/etc/pxeboot-update-*.sh",
                                                    self.DEPLOYED_OSTREE_DIR)
                    output = subprocess.run(cmd, shell=True, check=True, capture_output=True)
                    LOG.info("Copied pxeboot-update-*.sh to /etc: %s" % output.stdout.decode("utf-8"))
                except subprocess.CalledProcessError as e:
                    LOG.exception("Error copying pxeboot-update-*.sh to /etc: %s" %
                                  e.stderr.decode("utf-8"))
                    raise
            else:
                LOG.error("Cannot copy pxeboot files, major_release value is %s" %
                          self._major_release)


class UpdateKernelParametersHook(BaseHook):
    """
    Update the kernel parameters
    isolcpus=<cpu_range> ==> isolcpus=nohz,domain,managed_irq,<cpu_range>
    """
    def __init__(self, attrs):
        super().__init__()

    def read_isolcpus_kernel_parameters(self):

        isolcpus = ''
        try:
            BOOT_ENV = "/boot/efi/EFI/BOOT/boot.env"
            cmd = f'grub-editenv {BOOT_ENV} list'
            output = subprocess.check_output(cmd.split()).decode('utf-8')
        except Exception as e:
            err = str(e)
            msg = f"Failed to run {cmd} - {err}"
            LOG.exception(msg)
            raise

        kernel_params = ''
        for line in output.split('\n'):
            if line.startswith('kernel_params='):
                kernel_params = line[len('kernel_params='):]
                break

        for param in kernel_params.split():
            if param.startswith('isolcpus='):
                isolcpus = param
                break

        return isolcpus

    def run(self):
        """Execute the hook"""
        try:
            # Get the isolcpus cpu range
            isolcpus = self.read_isolcpus_kernel_parameters()
            if not isolcpus:
                # do nothing 'isolcpus' kernel parameter not configured
                return

            _, val = isolcpus.split("=")
            isolcpus_ranges = []  # only numeric values
            isolcpus_prefix = ['nohz', 'domain', 'managed_irq']

            for cpu_range in val.split(","):
                if re.search(r"^\d+-?\d*$", cpu_range):
                    isolcpus_ranges.append(cpu_range)
                    isolcpus_prefix.append(cpu_range)

            if not isolcpus_ranges:
                # isolated application cpus not configured
                return

            # Convert to list to string
            isolcpus_prefix = ",".join(isolcpus_prefix)

            # remove 'isolcpus' kernel parameter
            cmd = "python /usr/local/bin/puppet-update-grub-env.py --remove-kernelparams isolcpus"
            subprocess.run(cmd, shell=True, check=True, capture_output=True)

            # add updated 'isolcpus' kernel parameter
            cmd = f"python /usr/local/bin/puppet-update-grub-env.py --add-kernelparams isolcpus={isolcpus_prefix}"
            subprocess.run(cmd, shell=True, check=True, capture_output=True)

            LOG.info("Successfully updated kernel parameter isolcpus=%s", isolcpus_prefix)

        except subprocess.CalledProcessError as e:
            msg = ("Failed to run puppet-update-grub-env.py: rc=%s, output=%s"
                   % (e.returncode, e.stderr.decode("utf-8")))
            LOG.exception(msg)
        except Exception as e:
            err = str(e)
            msg = f"Failed to update isolcpus kernel paramater. Error = {err}"
            LOG.exception(msg)

        return


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
        flag_file = "%s/%s" % (self.DEPLOYED_OSTREE_DIR, constants.USM_UPGRADE_IN_PROGRESS_FLAG)
        with open(flag_file, "w") as _:
            LOG.info("Created %s flag" % flag_file)


class RemoveKubernetesConfigSymlinkHook(BaseHook):
    K8S_ENCRYPTION_PROVIDER_FILE = "/etc/kubernetes/encryption-provider.yaml"
    DEPLOYED_K8S_ENCRYPTION_PROVIDER_FILE = \
        BaseHook.DEPLOYED_OSTREE_DIR + K8S_ENCRYPTION_PROVIDER_FILE
    LUKS_K8S_ENCRYPTION_PROVIDER_FILE = \
        "/var/luks/stx/luks_fs/controller" + K8S_ENCRYPTION_PROVIDER_FILE

    def __init__(self, attrs):
        super().__init__(attrs)
        self._major_release = None
        if "major_release" in attrs:
            self._major_release = attrs.get("major_release")

    def run(self):
        if self._major_release == "22.12":
            nodetype = utils.get_platform_conf("nodetype")
            if nodetype == constants.CONTROLLER:
                try:
                    # Remove the K8S encryption provider symlink
                    for symlink in (self.K8S_ENCRYPTION_PROVIDER_FILE, self.DEPLOYED_K8S_ENCRYPTION_PROVIDER_FILE):
                        if os.path.exists(symlink):
                            os.unlink(symlink)
                            LOG.info("%s symlink removed" % symlink)

                    # Copy the LUKS K8S encryption provider file to /etc/kubernetes and remove it afterward
                    if os.path.exists(self.LUKS_K8S_ENCRYPTION_PROVIDER_FILE):
                        shutil.copy2(self.LUKS_K8S_ENCRYPTION_PROVIDER_FILE, "/etc/kubernetes")
                        LOG.info("Copied %s to /etc/kubernetes" % self.LUKS_K8S_ENCRYPTION_PROVIDER_FILE)
                        os.remove(self.LUKS_K8S_ENCRYPTION_PROVIDER_FILE)
                        LOG.info("%s file removed" % self.LUKS_K8S_ENCRYPTION_PROVIDER_FILE)

                except Exception as e:
                    LOG.exception("Failed to manage symlink or file: %s" % str(e))
                    raise


# TODO(heitormatsui): delete in the future, not needed for stx-10 -> <future-releases>
class RemoveCephMonHook(BaseHook):
    """
    Remove additional ceph-mon added for each controller
    """
    PMON_FILE = "/etc/pmon.d/ceph-fixed-mon.conf"

    def __init__(self, attrs):
        super().__init__(attrs)
        self._major_release = None
        if "major_release" in attrs:
            self._major_release = attrs.get("major_release")

    def run(self):
        # (DX only) on 22.12 there is 1 mon, on 24.09 there are 3
        # so only in 24.09 -> 22.12 rollback this hook is needed
        if self._major_release == "22.12":
            system_type = utils.get_platform_conf("system_type")
            system_mode = utils.get_platform_conf("system_mode")
            nodetype = utils.get_platform_conf("nodetype")
            # additional monitors were added only for AIO-DX
            if (system_type == constants.SYSTEM_TYPE_ALL_IN_ONE and
                    system_mode != constants.SYSTEM_MODE_SIMPLEX and
                    nodetype == constants.CONTROLLER):
                cmd_remove_mon_controller_0 = ["timeout", "30", "ceph", "mon", "rm", "controller-0"]
                cmd_remove_mon_controller_1 = ["timeout", "30", "ceph", "mon", "rm", "controller-1"]
                try:
                    subprocess.check_call(cmd_remove_mon_controller_0)
                    subprocess.check_call(cmd_remove_mon_controller_1)
                    LOG.info("Removed mon.controller-0 and mon.controller-1 from ceph cluster.")
                except subprocess.CalledProcessError as e:
                    LOG.exception("Failure removing mon.controller-0 and mon.controller-1 from ceph cluster: %s" % str(e))
                    raise
                try:
                    os.unlink(self.PMON_FILE)
                    LOG.info("Removed %s from pmon." % self.PMON_FILE)
                except FileNotFoundError:
                    pass  # ignore if link doesn't exist


class RestartKubeApiServer(BaseHook):
    """
    Restart the kube-apiserver after the host rollback to
    resolve issues with the pods that are pending
    or show errors with kubectl exec following a host-swact
    on controller-1. This action ensures all pods run correctly
    and enables successful exec operations.
    """
    def __init__(self, attrs):
        super().__init__()

    def run(self):
        nodetype = utils.get_platform_conf("nodetype")
        if nodetype == constants.CONTROLLER:
            try:
                # Get and stop all kube-apiserver container IDs
                cmd = "crictl ps | awk '/kube-apiserver/{print $1}' | xargs crictl stop"
                subprocess.run(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True
                )
                LOG.info("Successfully stopped kube-apiserver containers.")
            except subprocess.CalledProcessError as e:
                LOG.exception("An error occurred while trying to stop kube-apiserver"
                              "containers: %s", e)
                LOG.error("Command '%s' failed:\n%s\n%s\n" % (
                    cmd, e.stdout.decode('utf-8'), e.stderr.decode('utf-8')))


class UpdateKernelParameters(BaseHook):
    def __init__(self, attrs):
        super().__init__()
        self._major_release = None
        if "major_release" in attrs:
            self._major_release = attrs.get("major_release")
        if "from_release" in attrs:
            self._from_release = attrs.get("from_release")
        if "additional_data" in attrs:
            self._additional_data = attrs.get("additional_data")
        else:
            self._additional_data = {}
        msg = f"attrs {attrs} additional data {self._additional_data}"
        LOG.info(msg)

    def update_kernel_parameters(self, names):
        for name in names:
            if name in self._additional_data:
                value = self._additional_data[name]
                try:
                    if value:
                        cmd = f"python /usr/local/bin/puppet-update-grub-env.py --remove-kernelparams {name}"
                        subprocess.run(cmd, shell=True, check=True, capture_output=True)
                        msg = f"Removed kernel parameter: {name}"
                        LOG.info(msg)

                        cmd = f"python /usr/local/bin/puppet-update-grub-env.py --add-kernelparams {name}={value}"
                        subprocess.run(cmd, shell=True, check=True, capture_output=True)
                        msg = f"Updated kernel parameter: {name}={value}"
                        LOG.info(msg)
                    else:
                        cmd = f"python /usr/local/bin/puppet-update-grub-env.py --remove-kernelparams {name}"
                        subprocess.run(cmd, shell=True, check=True, capture_output=True)
                        msg = f"Removed kernel parameter: {name}"
                        LOG.info(msg)
                except subprocess.CalledProcessError as e:
                    LOG.exception("Failed to update boot.env for out of tree drivers.: %s" % str(e))

    def run(self):
        """Execute the hook"""
        parameter_names = []
        subfunction = utils.get_platform_conf("subfunction")
        if self._major_release and "22.12" == self._from_release:
            if "worker" in subfunction:
                parameter_names.append("oot_drivers")
                LOG.info("Set out-of-tree-drivers for rollback to 22.12")

        self.update_kernel_parameters(parameter_names)


# pre and post keywords
PRE = "pre"
POST = "post"

# actions
MAJOR_RELEASE_UPGRADE = "major_release_upgrade"
MAJOR_RELEASE_ROLLBACK = "major_release_rollback"

# agent hooks mapping per action
AGENT_HOOKS = {
    MAJOR_RELEASE_UPGRADE: [
            CreateUSMUpgradeInProgressFlag,
            CopyPxeFilesHook,
            ReconfigureKernelHook,
            UpdateKernelParametersHook,
            EnableNewServicesHook,
            UpdateKernelParameters,
            # enable usm-initialize service for next reboot only
            # if everything else is done
            UsmInitHook,
        ],
    MAJOR_RELEASE_ROLLBACK: [
            RemoveKubernetesConfigSymlinkHook,
            ReconfigureKernelHook,
            RemoveCephMonHook,
            RestartKubeApiServer,
            UpdateKernelParameters,
            # enable usm-initialize service for next reboot only
            # if everything else is done
            UsmInitHook,
        ],
}


class HookManager(object):
    """
    Object to manage the execution of agent hooks
    """
    def __init__(self, action, attrs=None):
        self._action = action
        self._attrs = attrs
        self._hooks = AGENT_HOOKS.get(action)

    def _run_hooks(self):
        """
        Run all hooks
        """
        LOG.info("Running hooks for '%s'" % self._action)
        for hook in self._hooks:
            pg = hook(self._attrs)
            pg.run()

    def run_hooks(self):
        self._run_hooks()

    @staticmethod
    def create_hook_manager(software_version, additional_data=None):
        # check if received version is greater (upgrade) or not (rollback)
        if utils.compare_release_version(software_version, constants.SW_VERSION):
            LOG.info("Upgrading from %s to %s additional_data %s" % (constants.SW_VERSION,
                                                                     software_version,
                                                                     additional_data))
            return HookManager(MAJOR_RELEASE_UPGRADE, {"major_release": software_version,
                                                       "from_release": constants.SW_VERSION,
                                                       "additional_data": additional_data})
        LOG.info("Rolling back from %s to %s additional_data %s" % (constants.SW_VERSION,
                                                                    software_version,
                                                                    additional_data))
        return HookManager(MAJOR_RELEASE_ROLLBACK, {"major_release": software_version,
                                                    "from_release": constants.SW_VERSION,
                                                    "additional_data": additional_data})
