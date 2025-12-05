"""
Copyright (c) 2024-2025 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

#####################################################################
# NOTE: This module is loaded and executed by the N-1 python runtime
#       environment in upgrade scenario and by the N+1 counterpart
#       in rollback scenario, so:
#       1. This module needs to be independent and should NOT import
#          other project modules like constants, utils, tsconfig, etc
#       2. This module needs to be compatible with both N+1 and N-1
#          python environments
#####################################################################

from abc import ABC
from abc import abstractmethod
import configparser
import contextlib
import filecmp
import glob
import logging as LOG
import os
import re
import shutil
import subprocess

from packaging import version

log_format = ('%(asctime)s: ' + '[%(process)s]: '
              '%(filename)s(%(lineno)s): %(levelname)s: %(message)s')
LOG.basicConfig(filename="/var/log/software.log",
                format=log_format, level=LOG.INFO, datefmt="%FT%T")


class BaseHook(object):
    """Base Hook object"""
    # directories
    TO_RELEASE_OSTREE_DIR = "/ostree/1"
    FROM_RELEASE_OSTREE_DIR = "/ostree/2"
    SYSTEMD_LIB_DIR = "/lib/systemd/system"
    SYSTEMD_ETC_DIR = "%s/etc/systemd/system/multi-user.target.wants" % TO_RELEASE_OSTREE_DIR
    PLATFORM_CONF_PATH = "/etc/platform/"
    PLATFORM_CONF_FILE = os.path.join(PLATFORM_CONF_PATH, "platform.conf")

    # keywords
    CONTROLLER = "controller"
    SIMPLEX = "simplex"

    def __init__(self, attrs):
        self._major_release = attrs.get("major_release")
        self._from_release = attrs.get("from_release")
        self._to_release = attrs.get("to_release")
        self._action = attrs.get("hook_action")
        self._additional_data = attrs.get("additional_data") or {}
        self._to_commit_id = self._additional_data.get("to_commit_id")
        self._from_commit_id = self._additional_data.get("from_commit_id")

    def run(self):
        pass

    @staticmethod
    def get_platform_conf(key):
        default = "DEFAULT"
        with open(BaseHook.PLATFORM_CONF_FILE, "r") as fp:
            cp = configparser.ConfigParser()
            cp.read_string(f"[{default}]\n" + fp.read())
        return cp[default][key]

    def get_etc_backup_path(self, commit_id=None):
        ETC_BACKUP_PATH = '/sysroot/upgrade/deploy-%s'
        if commit_id is None:
            commit_id = '*'
        return ETC_BACKUP_PATH % commit_id

    def get_etc_backup(self):
        if self._to_commit_id:
            return self.get_etc_backup_path(self._to_commit_id)
        return None

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

    @staticmethod
    def get_new_deploy_path(relative_path):
        path = os.path.join(BaseHook.TO_RELEASE_OSTREE_DIR, relative_path.lstrip('/'))
        return path


class UsmInitHook(BaseHook):
    """
    Enable the USM services on the next host reboot
    """
    USM_CONTROLLER_SERVICES = ["software-controller.service"]

    def _enable_controller_services(self):
        nodetype = self.get_platform_conf("nodetype")
        if nodetype == self.CONTROLLER:
            LOG.info("Enabling USM controller services")
            for service in self.USM_CONTROLLER_SERVICES:
                self.enable_service(service)
                LOG.info("Enabled %s" % service)

    def run(self):
        self.enable_service("usm-initialize.service")
        LOG.info("Enabled usm-initialize.service on next reboot")
        self._enable_controller_services()


class EtcMerger(BaseHook):
    """
    This is to perform customized etc merging
    This hook runs when deploying N+1 load. After ostree etc merge.
    This hook copies etc config files from <n+1 deploy>/{USM_ETC_FILE_PATH}
    to new merged etc directory. This ensures an etc config file can be forcefully
    overwritten by the new file from deployment.
    """

    USM_ETC_FILE_PATH = "/usr/share/starlingx/usm/etc/"

    def __init__(self, attrs):
        super().__init__(attrs)
        self._major_release = None
        self._action = None
        self._from_release = None

        if "major_release" in attrs:
            self._major_release = attrs.get("major_release")
        if "from_release" in attrs:
            self._from_release = attrs.get("from_release")
        if "to_release" in attrs:
            self._to_release = attrs.get("to_release")
        if "hook_action" in attrs:
            self._action = attrs.get("hook_action")

    def copy_files(self):
        def iterate_etc_files(path):
            for root, _, files in os.walk(path):
                for file in files:
                    yield os.path.join(root, file)

        new_deploy_etc_file_path = self.get_new_deploy_path(self.USM_ETC_FILE_PATH)
        for source_file in iterate_etc_files(new_deploy_etc_file_path):
            destination_file = os.path.join('/etc', os.path.relpath(source_file,
                                            new_deploy_etc_file_path))
            try:
                LOG.info(f"Replacing {destination_file} with {source_file}")
                shutil.copyfile(source_file, destination_file)
            except FileNotFoundError:
                # imposible?
                LOG.error(f"copy file {source_file} not found")
            except Exception:
                LOG.exception(f"Fail to replace file {destination_file} with {source_file}")
                raise

    def run(self):
        LOG.info("Running EtcMerger hook")
        self.copy_files()


class EnableNewServicesHook(BaseHook):
    """
    Find the new services between FROM and TO release
    and enable the new services on the next host reboot
    """
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
        with open("%s/%s" % (self.TO_RELEASE_OSTREE_DIR, system_preset), "r") as fp:
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
    def run(self):
        """Execute the hook"""
        nodetype = self.get_platform_conf("nodetype")
        if nodetype == self.CONTROLLER:
            if self._to_release:
                # copy to_release pxeboot files to /var/pxeboot/pxelinux.cfg.files
                pxeboot_dst_dir = "/var/pxeboot/pxelinux.cfg.files/"
                pxeboot_src_dir = self.TO_RELEASE_OSTREE_DIR + pxeboot_dst_dir  # deployed to-release ostree dir
                cmd = "rsync -ac %s %s" % (pxeboot_src_dir, pxeboot_dst_dir)
                try:
                    subprocess.run(cmd, shell=True, check=True, capture_output=True)
                    LOG.info("Copied %s pxeboot files to %s" %
                             (self._to_release, pxeboot_dst_dir))
                except subprocess.CalledProcessError as e:
                    LOG.exception("Error copying pxeboot files from %s to %s: %s" % (
                        pxeboot_src_dir, pxeboot_dst_dir, e.stderr.decode("utf-8")))
                    raise

                # ensure the script pxeboot-update-<from-release>.sh is in to-release /etc
                try:
                    cmd = "rsync -aci %s %s/etc" % (self.FROM_RELEASE_OSTREE_DIR + "/etc/pxeboot-update-*.sh",
                                                    self.TO_RELEASE_OSTREE_DIR)
                    output = subprocess.run(cmd, shell=True, check=True, capture_output=True)
                    LOG.info("Copied pxeboot-update-*.sh to /etc: %s" % output.stdout.decode("utf-8"))
                except subprocess.CalledProcessError as e:
                    LOG.exception("Error copying pxeboot-update-*.sh to /etc: %s" %
                                  e.stderr.decode("utf-8"))
                    raise
            else:
                LOG.error("Cannot copy pxeboot files, to_release value is %s" %
                          self._to_release)


class UpdateKernelParametersHook(BaseHook):
    """
    Update the kernel parameters
    isolcpus=<cpu_range> ==> isolcpus=nohz,domain,managed_irq,<cpu_range>
    '' ==> rcutree.kthread_prio=21 (default value if not set)
    """

    PLATFORM_DIR = "/opt/platform"

    def read_kernel_parameters(self) -> str:
        kernel_params = ''

        try:
            BOOT_ENV = "/boot/efi/EFI/BOOT/boot.env"
            cmd = f'grub-editenv {BOOT_ENV} list'
            output = subprocess.check_output(cmd.split()).decode('utf-8')
        except Exception as e:
            err = str(e)
            msg = f"Failed to run {cmd} - {err}"
            LOG.exception(msg)
            raise

        for line in output.split('\n'):
            if line.startswith('kernel_params='):
                kernel_params = line[len('kernel_params='):]
                break

        return kernel_params

    def read_isolcpus(self, kernel_params: str) -> str:
        isolcpus = ''
        for param in kernel_params.split():
            if param.startswith('isolcpus='):
                isolcpus = param
                break
        return isolcpus

    def update_isolcpus(self, isolcpus: str) -> None:
        if not isolcpus:
            LOG.info("Do nothing. Kernel param 'isolcpus' is not configured.")
            return

        try:
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

            LOG.info(f"Successfully updated kernel parameter isolcpus={isolcpus_prefix}")

        except subprocess.CalledProcessError as e:
            msg = ("Failed to run puppet-update-grub-env.py: rc=%s, output=%s"
                   % (e.returncode, e.stderr.decode("utf-8")))
            LOG.exception(msg)
        except Exception as e:
            err = str(e)
            msg = f"Failed to update isolcpus kernel parameter. Error = {err}"
            LOG.exception(msg)

    def read_kthread_prio(self, kernel_params: str) -> str:
        kthread_prio = ''
        for param in kernel_params.split():
            if param.startswith('rcutree.kthread_prio='):
                kthread_prio = param
                break
        return kthread_prio

    def add_kthread_prio_if_not_set(self, kthread_prio: str) -> None:
        if kthread_prio:
            LOG.info(f"Do nothing. Kernel param '{kthread_prio}' is already set.")
            return

        lowlatency = 'lowlatency' in self.get_platform_conf("subfunction")
        if not lowlatency:
            LOG.info("Standard kernel 'rcutree.kthread_prio' will not be set.")
            return

        # if lowlatency kernel and not previously set, use default value
        default_kthread_prio = 'rcutree.kthread_prio=21'
        try:
            LOG.info(f"Adding kernel parameter '{default_kthread_prio}'")

            # add 'rcutree.kthread_prio' kernel parameter
            cmd = f"python /usr/local/bin/puppet-update-grub-env.py --add-kernelparams {default_kthread_prio}"
            subprocess.run(cmd, shell=True, check=True, capture_output=True)

            LOG.info(f"Successfully added kernel parameter '{default_kthread_prio}'")

        except subprocess.CalledProcessError as e:
            msg = ("Failed to run puppet-update-grub-env.py: rc=%s, output=%s"
                   % (e.returncode, e.stderr.decode("utf-8")))
            LOG.exception(msg)
        except Exception as e:
            err = str(e)
            msg = f"Failed to update {default_kthread_prio} kernel parameter. Error = {err}"
            LOG.exception(msg)

    def remove_kthread_prio(self):
        kthread_prio = 'rcutree.kthread_prio'
        try:
            LOG.info(f"Remove kernel parameter '{kthread_prio}'")

            # remove 'rcutree.kthread_prio' kernel parameter
            cmd = f"python /usr/local/bin/puppet-update-grub-env.py --remove-kernelparams {kthread_prio}"
            subprocess.run(cmd, shell=True, check=True, capture_output=True)

        except subprocess.CalledProcessError as e:
            msg = ("Failed to run %s: rc=%s, output=%s"
                   % (cmd, e.returncode, e.stderr.decode("utf-8")))
            LOG.exception(msg)
        except Exception as e:
            err = str(e)
            msg = f"Failed to remove {kthread_prio} kernel parameter. Error = {err}"
            LOG.exception(msg)
        else:
            LOG.info(f"Successfully remove kernel parameter '{kthread_prio}'")

    def read_intel_idle(self, kernel_params: str) -> str:
        intel_idle = ''
        for param in kernel_params.split():
            if param.startswith('intel_idle.max_cstate='):
                intel_idle = param
                break
        return intel_idle

    def check_subfunction_worker(self) -> bool:
        worker = 'worker' in self.get_platform_conf("subfunction")
        return worker

    def mount_platform_dir(self):
        os.makedirs(self.PLATFORM_DIR, exist_ok=True)

        cmd = f"nfs-mount controller-platform-nfs:{self.PLATFORM_DIR} {self.PLATFORM_DIR}"

        try:
            subprocess.run(cmd, shell=True, check=True, capture_output=True)

        except subprocess.CalledProcessError as e:
            msg = ("Failed to run %s: rc=%s, output=%s"
                   % (cmd, e.returncode, e.stderr.decode("utf-8")))
            LOG.exception(msg)
            raise

        except Exception as e:
            err = str(e)
            msg = f"Failed to '{cmd}'. Error = {err}"
            LOG.exception(msg)
            raise

        else:
            LOG.info(f"Success to '{cmd}'")

    def umount_platform_dir(self):
        cmd = f"umount {self.PLATFORM_DIR}"

        try:
            subprocess.run(cmd, shell=True, check=True, capture_output=True)

        except subprocess.CalledProcessError as e:
            msg = ("Failed to run %s: rc=%s, output=%s"
                   % (cmd, e.returncode, e.stderr.decode("utf-8")))
            LOG.exception(msg)
            raise

        except Exception as e:
            err = str(e)
            msg = f"Failed to '{cmd}'. Error = {err}"
            LOG.exception(msg)
            raise

        LOG.info(f"Success to '{cmd}'")

    def get_hieradata_file(self) -> str:
        HIERADATA_PATH = f"/opt/platform/puppet/{self._to_release}/hieradata/"
        HOSTNAME_FILE_PATH = "/etc/hostname"

        try:
            with open(HOSTNAME_FILE_PATH, 'r') as f:
                hostname = f.read().strip()

            hieradata_file_name = f"{hostname}.yaml"
            hieradata_file = os.path.join(HIERADATA_PATH, hieradata_file_name)

            return hieradata_file

        except FileNotFoundError:
            msg = f"Error: Hostname file not found at {HOSTNAME_FILE_PATH}"
            LOG.exception(msg)
            raise

        except Exception as e:
            err = str(e)
            msg = f"An unexpected error occurred while reading hostname. Error = {err}"
            LOG.exception(msg)
            raise

    def remove_intel_idle_if_set(self, intel_idle: str) -> None:
        if not intel_idle:
            LOG.info("Do nothing. Kernel param 'intel_idle.max_cstate' is already not set.")
            return

        intel_idle_key = 'intel_idle.max_cstate'
        try:
            LOG.info(f"Remove kernel parameter '{intel_idle_key}'")

            # remove 'intel_idle.max_cstate' kernel parameter
            cmd = f"python /usr/local/bin/puppet-update-grub-env.py --remove-kernelparams {intel_idle_key}"
            subprocess.run(cmd, shell=True, check=True, capture_output=True)

        except subprocess.CalledProcessError as e:
            msg = ("Failed to run %s: rc=%s, output=%s"
                   % (cmd, e.returncode, e.stderr.decode("utf-8")))
            LOG.exception(msg)
            raise

        except Exception as e:
            err = str(e)
            msg = f"Failed to remove {intel_idle_key} kernel parameter. Error = {err}"
            LOG.exception(msg)
            raise

        else:
            LOG.info(f"Successfully remove kernel parameter '{intel_idle_key}'")

    def check_bios_cstate(self) -> bool:
        YAML_FILE = self.get_hieradata_file()
        mount_platform_dir_flag = False

        if not os.path.exists(YAML_FILE):
            self.mount_platform_dir()
            mount_platform_dir_flag = True

        cmd = f"sudo grep bios_cstate {YAML_FILE}"

        try:
            output_bytes = subprocess.check_output(
                cmd,
                shell=True,  # Critical for the pipe command
                stderr=subprocess.STDOUT  # Combine stderr with stdout for easier capture/debugging
            )
            output = output_bytes.decode('utf-8').strip()

        except subprocess.CalledProcessError as e:
            # grep returns a non-zero exit code (1) if it doesn't find a match.
            err = str(e)
            msg = f"Command '{cmd}' failed (grep found no match or other issue): {err}"
            LOG.info(msg)
            if mount_platform_dir_flag:
                self.umount_platform_dir()
            return False

        except Exception as e:
            # Handle other errors
            err = str(e)
            msg = f"Failed to run command '{cmd}' - {err}"
            LOG.exception(msg)
            if mount_platform_dir_flag:
                self.umount_platform_dir()
            raise

        if mount_platform_dir_flag:
            self.umount_platform_dir()

        return "true" in output

    def check_power_management(self) -> bool:
        YAML_FILE = self.get_hieradata_file()
        mount_platform_dir_flag = False

        if not os.path.exists(YAML_FILE):
            self.mount_platform_dir()
            mount_platform_dir_flag = True

        cmd = f"sudo grep power-management {YAML_FILE}"

        try:
            output_bytes = subprocess.check_output(
                cmd,
                shell=True,  # Critical for the pipe command
                stderr=subprocess.STDOUT  # Combine stderr with stdout for easier capture/debugging
            )
            output = output_bytes.decode('utf-8').strip()

        except subprocess.CalledProcessError as e:
            # grep returns a non-zero exit code (1) if it doesn't find a match.
            err = str(e)
            msg = f"Command '{cmd}' failed (grep found no match or other issue): {err}"
            LOG.info(msg)
            if mount_platform_dir_flag:
                self.umount_platform_dir()
            return False

        except Exception as e:
            # Handle other errors
            err = str(e)
            msg = f"Failed to run command '{cmd}' - {err}"
            LOG.exception(msg)
            if mount_platform_dir_flag:
                self.umount_platform_dir()
            raise

        if mount_platform_dir_flag:
            self.umount_platform_dir()

        return "enabled" in output

    def add_intel_idle_if_needed(self):
        if not self.check_subfunction_worker():
            LOG.info("Do nothing. The worker personality is not set for this node.")
            return

        kernel_params = self.read_kernel_parameters()
        intel_idle = self.read_intel_idle(kernel_params)
        if intel_idle:
            LOG.info(f"Do nothing. Kernel param '{intel_idle}' is already set.")
            return

        bios_cstate = self.check_bios_cstate()
        power_management = self.check_power_management()

        # Logic replicated from puppet-manifests/src/modules/platform/manifests/compute.pp
        # to ensure consistent verification for the rollback process.
        if not power_management and bios_cstate:
            intel_idle_key = 'intel_idle.max_cstate=0'
        else:
            intel_idle_key = ''

        try:
            if intel_idle_key:
                LOG.info(f"Adding kernel parameter '{intel_idle_key}'")
                cmd = f"python /usr/local/bin/puppet-update-grub-env.py --add-kernelparams {intel_idle_key}"
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
                LOG.info(f"Successfully added kernel parameter '{intel_idle_key}'")
            else:
                LOG.info("Do nothing. Kernel param intel_idle.max_cstate does not need to be set")

        except subprocess.CalledProcessError as e:
            msg = ("Failed to run puppet-update-grub-env.py: rc=%s, output=%s"
                   % (e.returncode, e.stderr.decode("utf-8")))
            LOG.exception(msg)
        except Exception as e:
            err = str(e)
            msg = f"Failed to update {intel_idle_key} kernel parameter. Error = {err}"
            LOG.exception(msg)

    def run(self):
        """Execute the hook"""
        if self._action == HookManager.MAJOR_RELEASE_UPGRADE:
            kernel_params = self.read_kernel_parameters()

            isolcpus = self.read_isolcpus(kernel_params)
            self.update_isolcpus(isolcpus)

            kthread_prio = self.read_kthread_prio(kernel_params)
            self.add_kthread_prio_if_not_set(kthread_prio)

            intel_idle = self.read_intel_idle(kernel_params)
            self.remove_intel_idle_if_set(intel_idle)
        elif self._action == HookManager.MAJOR_RELEASE_ROLLBACK:
            # TODO(jtognoll): remove when 25.09 is no longer a supported from
            # release.
            if self._to_release == '25.09':
                self.add_intel_idle_if_needed()


class ReconfigureKernelHook(BaseHook):
    """
    Reconfigure the kernel post deploy host command by updating the
    /boot/1/kernel.env file, to ensure the host kernel type (low-latency
    or standard) persists after the host is unlocked and reboots running
    N+1 release.
    """
    def run(self):
        """Execute the hook"""
        try:
            subfunctions = self.get_platform_conf("subfunction")
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
                deployment_dir = self.TO_RELEASE_OSTREE_DIR
                if version.Version(self._from_release) >= version.Version(self._to_release):
                    deployment_dir = self.FROM_RELEASE_OSTREE_DIR
                # Explicitly update /boot/1/kernel.env using the
                # /usr/local/bin/puppet-update-grub-env.py utility
                boot_index = 1
                LOG.info("Updating /boot/%s/kernel.env to: %s", boot_index, desired_kernel)
                cmd = ("python %s/usr/local/bin/puppet-update-grub-env.py "
                       "--set-kernel %s --boot-index %s") % (deployment_dir,
                                                             desired_kernel, boot_index)
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            msg = ("Failed to run puppet-update-grub-env.py: rc=%s, output=%s"
                   % (e.returncode, e.stderr.decode("utf-8")))
            LOG.exception(msg)
            raise
        except Exception as e:
            msg = "Failed to manually update /boot/1/kernel.env. Err=%s" % str(e)
            LOG.exception(msg)
            raise


class UpdateGrubConfigHook(BaseHook):
    """
    Get the grub.cfg.stx file from the to-release files
    and replace the grub.cfg on /boot contents with it;
    this approach works both for forward and rollback paths
    """
    BOOT_GRUB_CFG = "/boot/efi/EFI/BOOT/grub.cfg"

    def run(self):
        to_release_grub_cfg = os.path.join(self.TO_RELEASE_OSTREE_DIR,
                                           "var/pxeboot/pxelinux.cfg.files/grub.cfg.stx")
        if os.path.isfile(to_release_grub_cfg):
            # replace boot grub.cfg for the new file
            LOG.info("Copying %s into %s", to_release_grub_cfg, self.BOOT_GRUB_CFG)
            shutil.copy2(to_release_grub_cfg, self.BOOT_GRUB_CFG)
        else:
            LOG.warning("No %s file present in to-release filesystem",
                        os.path.basename(to_release_grub_cfg))

        deployment_dir = self.TO_RELEASE_OSTREE_DIR
        if version.Version(self._from_release) >= version.Version(self._to_release):
            deployment_dir = self.FROM_RELEASE_OSTREE_DIR
        system_mode = self.get_platform_conf("system_mode")
        try:
            LOG.info(f"Updating system_mode={system_mode} in boot.env")
            cmd = [
                os.path.join(deployment_dir, "usr/local/bin/puppet-update-grub-env.py"),
                "--set-boot-variable",
                f"system_mode={system_mode}",
            ]
            LOG.info("Executing command: %s", cmd)
            subprocess.run(cmd, check=True, text=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            LOG.error("Failed to update system_mode in boot.env: %s", e.stderr)


class CreateUSMUpgradeInProgressFlag(BaseHook):
    USM_UPGRADE_IN_PROGRESS_FLAG = os.path.join(BaseHook.PLATFORM_CONF_PATH,
                                                ".usm_upgrade_in_progress")

    def run(self):
        flag_file = "%s/%s" % (self.TO_RELEASE_OSTREE_DIR, self.USM_UPGRADE_IN_PROGRESS_FLAG)
        with open(flag_file, "w") as _:
            LOG.info("Created %s flag" % flag_file)


# TODO(mdecastr): Only required in stx 12. Remove in future releases.
class CreateKubeApiserverPortUpdatedFlag(BaseHook):
    def __init__(self, attrs):
        super().__init__(attrs)
        self.KUBE_APISERVER_PORT_UPDATED_FLAG = \
            os.path.join(BaseHook.PLATFORM_CONF_PATH, ".upgrade_kube_apiserver_port_updated")

    def run(self):
        if (self._to_release == '25.09' and
                self.get_platform_conf("nodetype") == self.CONTROLLER):
            flag_file = "%s/%s" % (self.TO_RELEASE_OSTREE_DIR,
                                   self.KUBE_APISERVER_PORT_UPDATED_FLAG)
            with open(flag_file, "w") as _:
                LOG.info("Created %s flag" % flag_file)


class DeleteControllerFeedRemoteHook(BaseHook):
    """
    This hook deletes the controller-feed ostree remote for non-controller
    hosts, so that the remote is recreated pointing to the to-release feed
    after a successful deployment with the to-release ostree commit-id
    """
    OSTREE_AUX_REMOTE = "controller-feed"

    def run(self):
        nodetype = self.get_platform_conf("nodetype")
        if nodetype != self.CONTROLLER:
            cmd = ["ostree", "remote", "delete", self.OSTREE_AUX_REMOTE]
            try:
                subprocess.run(cmd, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                LOG.info("Deleted ostree %s remote" % self.OSTREE_AUX_REMOTE)
            except subprocess.CalledProcessError as e:
                LOG.exception("Error deleting %s remote: %s" % (self.OSTREE_AUX_REMOTE, e.stdout))
                raise
        else:
            LOG.info("Host nodetype is %s, no ostree remote to delete" % self.CONTROLLER)


class AbstractSysctlFlagHook(BaseHook, ABC):
    """
    Abstract base class for managing CIS benchmark sysctl flags on the kernel.
    """

    def __init__(self, attrs):
        super(AbstractSysctlFlagHook, self).__init__(attrs)
        # This property must be implemented by derived classes
        self._parameters_to_set = None

    @property
    @abstractmethod
    def parameters_to_set(self):
        pass

    @abstractmethod
    def run(self):
        pass

    def _set_sysctl_param(self, config_file: str, param_name: str, param_value: int, lines: list):
        """
        Helper function to set or update a specific sysctl parameter in the list of lines.
        Handles commented-out lines by uncommenting and updating them.
        Returns True if the line was found/updated, False otherwise (meaning it needs to be added).
        """
        setting_to_set = f"{param_name} = {param_value}"
        setting_pattern = re.compile(rf"^\s*#?\s*{re.escape(param_name)}\s*=")

        updated_in_place = False
        for i, line in enumerate(lines):
            if setting_pattern.match(line):
                # If the line is already exactly what we want (uncommented and correct value)
                if line.strip() == setting_to_set:
                    LOG.info(f"'{param_name}' already set to '{param_value}' in {config_file}")
                else:
                    # If it's a matching line but needs updating or uncommenting
                    lines[i] = setting_to_set + '\n'
                    LOG.info(f"Updated '{param_name}' to '{param_value}' (uncommented if necessary) in {config_file}")
                updated_in_place = True
                break

        return updated_in_place

    def _configure_sysctl_parameters(self, ostree_dir):
        """
        Configures multiple sysctl parameters in /etc/sysctl.conf
        and applies the changes using sysctl -p.
        Handles commented-out lines by uncommenting and updating them.
        Uses the parameters defined by the derived class's 'parameters_to_set' property.
        """
        config_file = os.path.normpath(ostree_dir + "/etc/sysctl.conf")

        if self.parameters_to_set is None:
            LOG.error("Derived class must define 'parameters_to_set' property.")
            return

        try:
            if not os.path.exists(config_file):
                LOG.error(f"Error: {config_file} not found. Please ensure the file exists.")
                return

            with open(config_file, 'r') as f:
                lines = f.readlines()

            new_lines = list(lines)

            for param_name, param_value in self.parameters_to_set.items():
                param_found_and_updated = self._set_sysctl_param(
                    config_file, param_name, param_value, new_lines
                )

                if not param_found_and_updated:
                    setting_to_add = f"{param_name} = {param_value}"
                    # Ensure we don't add extra blank lines if the file already ends with one
                    if new_lines and not new_lines[-1].strip():
                        new_lines.append(setting_to_add + '\n')
                    else:
                        new_lines.append('\n' + setting_to_add + '\n')
                    LOG.info(f"Added '{setting_to_add}' to {config_file}")

            if new_lines != lines:  # Simple check if content has changed
                with open(config_file, 'w') as f:
                    f.writelines(new_lines)
                LOG.debug(f"Successfully modified {config_file}")
            else:
                LOG.debug(f"No changes detected for {config_file}. Skipping file write.")

        except FileNotFoundError:
            LOG.error(f"Error: Could not find the file {config_file}.")
        except PermissionError:
            LOG.error(f"Error: Permission denied for {config_file}. Please run with sufficient permissions.")
        except subprocess.CalledProcessError as e:
            LOG.error(f"Error applying sysctl changes: {e}")
            LOG.error(f"Command: {e.cmd}")
            LOG.error(f"Return Code: {e.returncode}")
            LOG.error(f"Stdout: {e.stdout}")
            LOG.error(f"Stderr: {e.stderr}")
        except Exception as e:
            LOG.error(f"An unexpected error occurred: {e}", exc_info=True)


class CISSysctlFlagHookUpgrade(AbstractSysctlFlagHook):
    """
    Hook to upgrade CIS benchmark sysctl flags to their hardened values.
    """
    @property
    def parameters_to_set(self):
        if self._parameters_to_set is None:
            self._parameters_to_set = {
                "net.ipv4.icmp_echo_ignore_broadcasts": 1,
                "net.ipv4.tcp_syncookies": 1,
                "net.ipv4.conf.all.rp_filter": 1,
                "net.ipv4.conf.default.rp_filter": 1,
                "net.ipv4.conf.all.accept_source_route": 0
            }
        return self._parameters_to_set

    def run(self):
        LOG.info("Starting CIS Sysctl Flag Upgrade...")
        self._configure_sysctl_parameters(self.TO_RELEASE_OSTREE_DIR)
        LOG.debug("CIS Sysctl Flag Upgrade finished.")


class CISSysctlFlagHookRollback(AbstractSysctlFlagHook):
    """
    Hook to rollback CIS benchmark sysctl flags to their original values.
    """
    @property
    def parameters_to_set(self):
        if self._parameters_to_set is None:
            self._parameters_to_set = {
                "net.ipv4.icmp_echo_ignore_broadcasts": 1,
                "net.ipv4.tcp_syncookies": 1,
                "net.ipv4.conf.all.rp_filter": 0,
                "net.ipv4.conf.default.rp_filter": 0,
                "net.ipv4.conf.all.accept_source_route": 0
            }
        return self._parameters_to_set

    def run(self):
        LOG.info("Starting CIS Sysctl Flag Rollback...")
        self._configure_sysctl_parameters(self.FROM_RELEASE_OSTREE_DIR)
        LOG.debug("CIS Sysctl Flag Rollback finished.")


class FixedEtcMergeHook(BaseHook):
    RENAME_FILES = {
        # N release : N+1 release
        "sysctl.d/k8s.conf": "sysctl.d/80-k8s.conf",
        "sysctl.d/100-monitor-tools.conf": "sysctl.d/10-monitor-tools.conf",
    }

    def _rename_file(self, src, dst):
        with contextlib.suppress(Exception):
            LOG.info(f"Attempting to rename '{src}' to '{dst}'.")
            # If the source file does not exist, do nothing
            if not os.path.exists(src):
                return
            # If the destination file already exists, do nothing
            if os.path.exists(dst):
                return
            os.rename(src, dst)

    def cleanup_deprecated_config_files(self):
        for src, dst in self.RENAME_FILES.items():
            deprecated_file = \
                os.path.normpath(f"{self.TO_RELEASE_OSTREE_DIR}/etc/{src}")
            replacement_file = \
                os.path.normpath(f"{self.TO_RELEASE_OSTREE_DIR}/etc/{dst}")
            self._rename_file(deprecated_file, replacement_file)

    def restart_sysctl_service(self):
        cmd = ["systemctl", "restart", "systemd-sysctl.service"]
        LOG.info(f"Restarting the systemd-sysctl service: {' '.join(cmd)}")
        try:
            subprocess.run(cmd, check=True,
                           text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            LOG.exception(f"Failed to restart systemd-sysctl service: {e}")
            raise
        except Exception as e:
            LOG.exception(f"Unexpected error restarting systemd-sysctl service: {e}")
            raise

    def run(self):
        LOG.info("Starting FixedEtcMergeHook Started.")
        self.cleanup_deprecated_config_files()
        self.restart_sysctl_service()
        LOG.info("FixedEtcMergeHook finished.")


class FixedEtcMergeRollBackHook(FixedEtcMergeHook):

    def cleanup_deprecated_config_files_rollback(self):
        for src, dst in self.RENAME_FILES.items():
            deprecated_file = \
                os.path.normpath(f"{self.TO_RELEASE_OSTREE_DIR}/etc/{src}")
            replacement_file = \
                os.path.normpath(f"{self.TO_RELEASE_OSTREE_DIR}/etc/{dst}")
            # During rollback reverse source and destination files
            self._rename_file(replacement_file, deprecated_file)

    def run(self):
        LOG.info("Starting FixedEtcMergeRollBackHook.")
        self.cleanup_deprecated_config_files_rollback()
        self.restart_sysctl_service()
        LOG.info("FixedEtcMergeRollBackHook finished.")


class OOTDriverHook(BaseHook):
    """
    Hook to remove out-of-tree driver kernel parameters during upgrade.
    """

    PARAM_NAME = "out-of-tree-drivers"

    def _remove_kernel_param(self):
        try:
            cmd = (
                "python /usr/local/bin/puppet-update-grub-env.py "
                f"--remove-kernelparams {self.PARAM_NAME}"
            )
            subprocess.run(cmd, shell=True, check=True, capture_output=True)
            LOG.info("Removed kernel parameter: %s", self.PARAM_NAME)
        except subprocess.CalledProcessError as e:
            LOG.exception(
                "Failed to remove kernel parameter %s: %s",
                self.PARAM_NAME, str(e)
            )

    def run(self):
        if self._from_release == "25.09":
            # Upgrade path: remove kernel param
            self._remove_kernel_param()
            LOG.info("Upgrade OOTDriverHook completed.")
        else:
            LOG.info(
                "OOTDriverHook: nothing to do for this release transition."
            )


class HookManager(object):
    """
    Object to manage the execution of agent hooks
    """
    # actions
    MAJOR_RELEASE_UPGRADE = "major_release_upgrade"
    MAJOR_RELEASE_ROLLBACK = "major_release_rollback"

    # agent hooks mapping per action
    AGENT_HOOKS = {
        MAJOR_RELEASE_UPGRADE: [
            CreateUSMUpgradeInProgressFlag,
            OOTDriverHook,
            EtcMerger,
            CopyPxeFilesHook,
            ReconfigureKernelHook,
            UpdateKernelParametersHook,
            UpdateGrubConfigHook,
            EnableNewServicesHook,
            DeleteControllerFeedRemoteHook,
            FixedEtcMergeHook,
            CISSysctlFlagHookUpgrade,
            # enable usm-initialize service for next
            # reboot only if everything else is done
            UsmInitHook,
        ],
        MAJOR_RELEASE_ROLLBACK: [
            ReconfigureKernelHook,
            UpdateGrubConfigHook,
            DeleteControllerFeedRemoteHook,
            FixedEtcMergeRollBackHook,
            CISSysctlFlagHookRollback,
            CreateKubeApiserverPortUpdatedFlag,
            # enable usm-initialize service for next
            # reboot only if everything else is done
            UsmInitHook,
        ],
    }

    def __init__(self, action, attrs=None):
        self._action = action
        self._attrs = attrs
        self._hooks = self.AGENT_HOOKS.get(action)

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
        sw_version = BaseHook.get_platform_conf("sw_version")

        hook_attrs = {"to_release": software_version,
                      "from_release": sw_version,
                      "additional_data": additional_data}

        # check if the version is greater, i.e. upgrade
        if version.Version(software_version) > version.Version(sw_version):
            hook_attrs['hook_action'] = HookManager.MAJOR_RELEASE_UPGRADE
            LOG.info("Upgrading from %s to %s, additional_data %s" % (
                     sw_version, software_version, additional_data))
            return HookManager(HookManager.MAJOR_RELEASE_UPGRADE, attrs=hook_attrs)

        # otherwise the operation is a rollback
        LOG.info("Rolling back from %s to %s, additional_data %s" % (
                 sw_version, software_version, additional_data))
        hook_attrs['hook_action'] = HookManager.MAJOR_RELEASE_ROLLBACK
        return HookManager(HookManager.MAJOR_RELEASE_ROLLBACK, attrs=hook_attrs)
