#!/usr/bin/python3
"""
Copyright (c) 2024-2026 Wind River Systems, Inc.

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

import argparse
import configparser
import contextlib
import filecmp
import functools
import glob
import json
import logging as LOG
import os
import re
import shutil
import subprocess
import sys
import tempfile

from packaging import version
from ruamel.yaml import YAML

from software.constants import SW_VERSION
from software.software_functions import load_module

log_format = ('%(asctime)s: ' + '[%(process)s]: '
              '%(filename)s(%(lineno)s): %(levelname)s: %(message)s')
LOG.basicConfig(filename="/var/log/software.log",
                format=log_format, level=LOG.INFO, datefmt="%FT%T")
yaml = YAML()
yaml.preserve_quotes = True


class BaseHook(object):
    """Base Hook object"""
    # directories
    TO_RELEASE_OSTREE_DIR = "/ostree/1"
    FROM_RELEASE_OSTREE_DIR = "/ostree/2"
    SYSTEMD_LIB_DIR = "/lib/systemd/system"
    SYSTEMD_ETC_DIR = "%s/etc/systemd/system/multi-user.target.wants" % TO_RELEASE_OSTREE_DIR
    PLATFORM_CONF_PATH = "/etc/platform/"
    PLATFORM_CONF_FILE = os.path.join(PLATFORM_CONF_PATH, "platform.conf")
    BACKUP_DIR = "/sysroot/upgrade/backup"
    INSTALLATION_PATH = "/usr/lib/python3/dist-packages/software/agent_hooks.py"

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
    def _get_debian_codename(root_dir='/'):
        os_release = os.path.join(root_dir, "usr/lib/os-release")
        with open(os_release, "r") as f:
            for line in f:
                if line.strip().startswith("VERSION_CODENAME="):
                    return line.strip().split("=", 1)[1].strip("'\"")
        raise ValueError("VERSION_CODENAME not found in %s" % os_release)

    @staticmethod
    @functools.lru_cache(maxsize=1)
    def get_from_release_debian_codename():
        return BaseHook._get_debian_codename(BaseHook.FROM_RELEASE_OSTREE_DIR)

    @staticmethod
    @functools.lru_cache(maxsize=1)
    def get_to_release_debian_codename():
        return BaseHook._get_debian_codename(BaseHook.TO_RELEASE_OSTREE_DIR)

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
            destination_file = \
                os.path.join(f'{self.TO_RELEASE_OSTREE_DIR}/etc',
                             os.path.relpath(source_file,
                                             new_deploy_etc_file_path))
            try:
                LOG.info(f"Replacing {destination_file} with {source_file}")
                shutil.copyfile(source_file, destination_file)
            except FileNotFoundError:
                # impossible?
                LOG.error(f"copy file {source_file} not found")
            except Exception:
                LOG.exception(f"Fail to replace file {destination_file} with {source_file}")
                raise

    def run(self):
        LOG.info("Running EtcMerger hook")
        self.copy_files()


class NtpToNtpsecMigrationHook(BaseHook):
    """
    Handle ntp->ntpsec transition during bullseye->trixie upgrade.
    Upgrade: Replace ntp with ntpsec in user/group files, migrate drift file,
             copy ntp defaults to ntpsec path, remove old ntp artifacts.
    Rollback: Restore ntp user/group, copy defaults back, remove ntpsec
              artifacts and stale systemd symlinks.
    """

    # Files where ntp->ntpsec replacement is needed
    USER_FILES = ["passwd", "group", "shadow", "gshadow"]
    NTP_DEFAULT_BACKUP = os.path.join(BaseHook.BACKUP_DIR, "etc_default_ntp")

    def _replace_user_entry(self, src_file, dst_file, old_name, new_name):
        """Replace old_name entry with new_name in dst_file, using src_file as source."""
        with open(src_file, "r") as f:
            new_line = next((ln for ln in f if ln.startswith(new_name + ":")), None)
        if not new_line:
            return
        if not new_line.endswith("\n"):
            new_line += "\n"
        with open(dst_file, "r") as f:
            lines = f.readlines()
        # Replace old entry in-place, skip if new already exists
        lines = [new_line if ln.startswith(old_name + ":") else ln
                 for ln in lines if not ln.startswith(new_name + ":")]
        # Append if neither old nor new was found
        if not any(ln.startswith(new_name + ":") for ln in lines):
            lines.append(new_line)
        with open(dst_file, "w") as f:
            f.writelines(lines)
        LOG.info("Replaced %s with %s in %s" % (old_name, new_name, dst_file))

    def _remove_paths(self, paths):
        """Remove files, directories, or symlinks."""
        for path in paths:
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path)
                LOG.info("Removed %s" % path)
            elif os.path.exists(path) or os.path.islink(path):
                os.remove(path)
                LOG.info("Removed %s" % path)

    def _upgrade(self):
        LOG.info("Running NtpToNtpsecMigrationHook (upgrade)")
        new_etc = os.path.join(self.TO_RELEASE_OSTREE_DIR, "etc")
        new_usr_etc = os.path.join(self.TO_RELEASE_OSTREE_DIR, "usr", "etc")
        # Replace ntp with ntpsec in all user/group files
        for filename in self.USER_FILES:
            self._replace_user_entry(
                os.path.join(new_usr_etc, filename),
                os.path.join(new_etc, filename),
                "ntp", "ntpsec")
        # Ensure ntpsec drift directory exists with correct ownership
        new_drift_dir = "/var/lib/ntpsec"
        os.makedirs(new_drift_dir, exist_ok=True)
        os.chown(new_drift_dir, 174, 174)
        # Migrate drift file if it exists
        old_drift = "/var/lib/ntp/drift"
        new_drift = os.path.join(new_drift_dir, "ntp.drift")
        if os.path.exists(old_drift) and not os.path.exists(new_drift):
            shutil.copy2(old_drift, new_drift)
            os.chown(new_drift, 174, 174)
            LOG.info("Migrated drift file to %s" % new_drift)
        # Backup /etc/default/ntp for potential rollback
        current_default = "/etc/default/ntp"
        if os.path.exists(current_default):
            os.makedirs(self.BACKUP_DIR, exist_ok=True)
            shutil.copy2(current_default, self.NTP_DEFAULT_BACKUP)
            LOG.info("Backed up %s" % current_default)
        # Remove old ntp artifacts
        self._remove_paths([
            os.path.join(new_etc, "default", "ntp"),
            os.path.join(new_etc, "ntp.conf"),
            os.path.join(new_etc, "systemd", "system",
                         "multi-user.target.wants", "ntp.service"),
            "/var/lib/ntp",
            "/var/log/ntpstats",
        ])
        LOG.info("NtpToNtpsecMigrationHook (upgrade) completed")

    def _rollback(self):
        LOG.info("Running NtpToNtpsecMigrationHook (rollback)")
        new_etc = os.path.join(self.TO_RELEASE_OSTREE_DIR, "etc")
        new_usr_etc = os.path.join(self.TO_RELEASE_OSTREE_DIR, "usr", "etc")
        # Restore ntp user/group from bullseye image base
        for filename in self.USER_FILES:
            self._replace_user_entry(
                os.path.join(new_usr_etc, filename),
                os.path.join(new_etc, filename),
                "ntpsec", "ntp")
        # Restore /etc/default/ntp from backup
        dst_default = os.path.join(new_etc, "default", "ntp")
        if os.path.exists(self.NTP_DEFAULT_BACKUP):
            os.makedirs(os.path.dirname(dst_default), exist_ok=True)
            shutil.copy2(self.NTP_DEFAULT_BACKUP, dst_default)
            os.remove(self.NTP_DEFAULT_BACKUP)
            LOG.info("Restored %s from backup" % dst_default)
        # Restore /etc/ntp.conf from image base if missing
        for filename in ["ntp.conf"]:
            src = os.path.join(new_usr_etc, filename)
            dst = os.path.join(new_etc, filename)
            if os.path.exists(src) and not os.path.exists(dst):
                shutil.copy2(src, dst)
                LOG.info("Restored %s" % dst)
        # Restore /var/lib/ntp with drift file from ntpsec if available
        old_ntp_dir = "/var/lib/ntp"
        os.makedirs(old_ntp_dir, exist_ok=True)
        os.chown(old_ntp_dir, 174, 174)
        ntpsec_drift = "/var/lib/ntpsec/ntp.drift"
        old_drift = os.path.join(old_ntp_dir, "drift")
        if os.path.exists(ntpsec_drift) and not os.path.exists(old_drift):
            shutil.copy2(ntpsec_drift, old_drift)
            os.chown(old_drift, 174, 174)
            LOG.info("Restored drift file to %s" % old_drift)
        # Remove all ntpsec artifacts
        systemd_dir = os.path.join(new_etc, "systemd", "system")
        self._remove_paths([
            os.path.join(systemd_dir, "ntp.service"),
            os.path.join(systemd_dir, "ntpd.service"),
            os.path.join(systemd_dir, "multi-user.target.wants", "ntpsec.service"),
            os.path.join(new_etc, "ntpsec"),
            os.path.join(new_etc, "cron.d", "ntpsec"),
            os.path.join(new_etc, "default", "ntpsec"),
            "/var/lib/ntpsec",
        ])
        LOG.info("NtpToNtpsecMigrationHook (rollback) completed")

    def run(self):
        if self.get_to_release_debian_codename() == "trixie":
            self._upgrade()
        elif self.get_from_release_debian_codename() == "trixie":
            self._rollback()


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


class RestorePlatformConfPermissionHook(BaseHook):
    """
    Restore the platform.conf file permission to 644
    """

    def run(self):
        try:
            # Restore the platform.conf file permission to 644
            os.chmod(self.PLATFORM_CONF_FILE, 0o644)
            LOG.info("Restore platform.conf file permission to 644")
        except Exception as e:
            LOG.exception("Failed to restore platform.conf file permission: %s" % e)
            raise

# TODO(bqian) split the framework based kernel parameters backup and restore
# from feature based kernel parameter pre-populate code.


class UpdateKernelParametersHook(BaseHook):
    """
    Update the kernel parameters
    isolcpus=<cpu_range> ==> isolcpus=nohz,domain,managed_irq,<cpu_range>
    '' ==> rcutree.kthread_prio=21 (default value if not set)
    """

    PLATFORM_DIR = "/opt/platform"
    BOOT_ENV = "/boot/efi/EFI/BOOT/boot.env"
    KERNEL_PARAMS_BACKUP = os.path.join(BaseHook.BACKUP_DIR, "kernel_params")

    def read_kernel_parameters(self) -> str:
        kernel_params = ''

        try:
            cmd = f'grub-editenv {self.BOOT_ENV} list'
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

    def backup_kernel_params(self, kernel_params: str):
        os.makedirs(self.BACKUP_DIR, exist_ok=True)
        with open(self.KERNEL_PARAMS_BACKUP, "w") as fd:
            fd.write(kernel_params)
        LOG.info("Backed up kernel parameters: %s", self.KERNEL_PARAMS_BACKUP)

    def restore_kernel_params(self):
        try:
            with open(self.KERNEL_PARAMS_BACKUP, "r") as fd:
                kernel_params = fd.read()
                cmd = ["grub-editenv", self.BOOT_ENV, "set", f"kernel_params={kernel_params}"]
                subprocess.run(cmd, check=True, capture_output=True, text=True)
        except FileNotFoundError:
            LOG.warning("Kernel parameters backup file not found, unable to restore...")
        except subprocess.CalledProcessError as e:
            LOG.error("Error restoring kernel parameters: %s", e.stderr)
            raise
        except Exception as e:
            LOG.error("Error restoring kernel parameters: %s", str(e))
            raise
        else:  # remove backup after restored
            LOG.info("Restored kernel parameters, deleting the backup...")
            os.remove(self.KERNEL_PARAMS_BACKUP)

    def run(self):
        """Execute the hook"""
        if self._action == HookManager.MAJOR_RELEASE_UPGRADE:
            kernel_params = self.read_kernel_parameters()

            self.backup_kernel_params(kernel_params)
            isolcpus = self.read_isolcpus(kernel_params)
            self.update_isolcpus(isolcpus)

            kthread_prio = self.read_kthread_prio(kernel_params)
            self.add_kthread_prio_if_not_set(kthread_prio)

            intel_idle = self.read_intel_idle(kernel_params)
            self.remove_intel_idle_if_set(intel_idle)
        elif self._action == HookManager.MAJOR_RELEASE_ROLLBACK:
            self.restore_kernel_params()
            # TODO(jtognoll): remove when 25.09 is no longer a supported from
            # release.
            # NOTE(bqian): keep for 25.09 to 26.09 upgrade/rollback
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


# TODO(mdecastr): Remove when stx 11 (25.09) is not supported as from side.
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


class FixedEtcMergeHook(BaseHook):
    DELETE_FILES = [
        # N release
        "sysctl.d/100-monitor-tools.conf",
        "sysctl.d/k8s.conf",
    ]

    def _delete_file(self, file_path):
        with contextlib.suppress(Exception):
            LOG.info(f"Attempting to delete '{file_path}'.")
            # If the file does not exist, do nothing
            if not os.path.exists(file_path):
                LOG.info(f"File not found: '{file_path}'.")
                return
            os.remove(file_path)
            LOG.info(f"Successfully deleted '{file_path}'.")

    def cleanup_deprecated_config_files(self):
        for file_name in self.DELETE_FILES:
            file_path = \
                os.path.normpath(f"{self.TO_RELEASE_OSTREE_DIR}/etc/{file_name}")
            self._delete_file(file_path)

    def run(self):
        LOG.info("Starting FixedEtcMergeHook Started.")
        self.cleanup_deprecated_config_files()
        LOG.info("FixedEtcMergeHook finished.")


class FixedEtcMergeRollBackHook(FixedEtcMergeHook):
    DELETE_FILES = [
        # N+1 release
        "sysctl.d/05-default-sysctl.conf",
        "sysctl.d/10-monitor-tools.conf",
        "sysctl.d/80-puppet.conf",
        "sysctl.d/80-k8s.conf",
        "sysctl.d/98-sysctl.conf",
        "sysctl.d/zzz-custom-user.conf",
    ]

    def run(self):
        LOG.info("Starting FixedEtcMergeRollBackHook.")
        self.cleanup_deprecated_config_files()
        LOG.info("FixedEtcMergeRollBackHook finished.")


class SSSDCacheCleanupRollBackHook(BaseHook):
    """Clean up SSSD cache database files during rollback.

    The SSSD cache database schema is upgraded in-place by newer SSSD
    versions (e.g., v0.22 -> v0.25 when going from Bullseye to Trixie).
    This migration is one-way — older SSSD versions cannot read a newer
    schema. During rollback, the older SSSD will fail to start with
    "Sysdb version is too new", breaking all user lookups via NSS/SSS
    and preventing kubelet and other services from starting.

    This hook removes the SSSD cache files so that SSSD rebuilds them
    from LDAP on the next start.
    """

    SSSD_DB_DIR = "/var/lib/sss/db"
    SSSD_CACHE_PATTERNS = [
        "cache_*.ldb",
        "timestamps_*.ldb",
    ]

    def _delete_file(self, file_path):
        with contextlib.suppress(Exception):
            LOG.info(f"Attempting to delete '{file_path}'.")
            if not os.path.exists(file_path):
                LOG.info(f"File not found: '{file_path}'.")
                return
            os.remove(file_path)
            LOG.info(f"Successfully deleted '{file_path}'.")

    def run(self):
        LOG.info("Starting SSSDCacheCleanupRollBackHook.")
        for pattern in self.SSSD_CACHE_PATTERNS:
            full_pattern = os.path.join(self.SSSD_DB_DIR, pattern)
            for db_file in glob.glob(full_pattern):
                self._delete_file(db_file)
        LOG.info("SSSDCacheCleanupRollBackHook finished.")


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
        # NOTE(bqian): keep for 25.09 to 26.09
        if self._from_release == "25.09":
            # Upgrade path: remove kernel param
            self._remove_kernel_param()
            LOG.info("Upgrade OOTDriverHook completed.")
        else:
            LOG.info(
                "OOTDriverHook: nothing to do for this release transition."
            )


class KubeletUpgradeHook(BaseHook):
    "Hook to write target kubelet version to be upgraded to"

    KUBELET_VERSION_FILE = '/etc/kubernetes/kubelet_version'

    def _write_version_details(self, to_kubelet_version):
        data = {
            "from_release": self._from_release,
            "to_release": self._to_release,
            "to_kubelet_version": to_kubelet_version,
        }
        version_file = "%s/%s" % (self.TO_RELEASE_OSTREE_DIR, self.KUBELET_VERSION_FILE)
        with open(version_file, "w") as file:
            json.dump(data, file)

    def run(self):
        try:
            # No need to check for AIO-SX. If to_kubelet_version is present, it is a simplex
            to_kubelet_version = self._additional_data.get("to_kubelet_version", None)
            if not to_kubelet_version:
                LOG.warning("'to_kubelet_version' not found in the additional data. Combined "
                            "platform and k8s upgrade may fail if it is being attempted.")
                return

            self._write_version_details(to_kubelet_version)

            LOG.info("Successfully written target kubelet version details to %s"
                     % self.KUBELET_VERSION_FILE)

        except Exception as ex:
            LOG.error("Failed to write target kubelet version details. Error: %s" % (ex))
            raise ex


class CgroupBootParamsHook(BaseHook):
    """
    Manage cgroup v2 migration during platform upgrade/rollback.

    This hook runs AFTER PuppetHieradataUpdate (which replaces hieradata
    with static defaults from the new release). We must run after it
    because we need to inject runtime DB values into hieradata that
    PuppetHieradataUpdate would otherwise overwrite.

    On upgrade, this hook:
    1. Reads cgroup_v2_enabled from the live sysinv DB (port 5432).
       This is the value the user set on the old release before upgrade.
    2. Updates boot.env kernel params:
       - true:  systemd.unified_cgroup_hierarchy=1, cgroup_no_v1=all
       - false/missing: keeps v1 defaults (no change)
    3. Updates puppet hieradata (global.yaml) with cgroup_v2_enabled
       value so the boot puppet manifest knows whether to create
       v1 cgroup dirs or skip them.

    On rollback:
    - Reverts boot.env to v1 kernel params
    - Sets hieradata to cgroup_v2_enabled=false

    Why each piece is needed:
    - boot.env: Controls which cgroup hierarchy the kernel mounts
    - config.yaml: Kubelet reads this at startup (before puppet runs)
    - hieradata: Puppet reads this during boot manifest to decide
      whether to create /sys/fs/cgroup/*/k8sinfra dirs (v1) or skip (v2)

    Without hieradata update, puppet would always try to create v1 dirs
    (because PuppetHieradataUpdate copies defaults without cgroup_v2_enabled),
    causing puppet failure on a v2 boot.
    """

    def _get_cgroup_v2_enabled(self):
        """Read cgroup_v2_enabled from the live sysinv DB.

        Returns the string value ('true'/'false') or None if not found.
        The DB is the old release's DB (port 5432) which has the user's
        setting from before the upgrade was initiated.
        """
        try:
            result = subprocess.run(
                ['sudo', '-u', 'postgres', 'psql', '-d', 'sysinv', '-t', '-c',
                 "SELECT value FROM service_parameter "
                 "WHERE service='platform' AND section='config' "
                 "AND name='cgroup_v2_enabled';"],
                capture_output=True, text=True, check=False
            )
            value = result.stdout.strip()
            if not value:
                return None
            LOG.info("CgroupBootParamsHook: Read cgroup_v2_enabled=%s from DB" % value)
            return value
        except Exception as e:
            LOG.exception("CgroupBootParamsHook: Failed to read cgroup_v2_enabled: %s" % e)
            return None

    def _set_v2_boot_params(self):
        """Set cgroup v2 kernel boot parameters in boot.env.

        Removes v1 params and adds v2 params so the next boot
        mounts the unified cgroup2 hierarchy.
        Uses puppet-update-grub-env.py.
        """
        try:
            subprocess.run("python /usr/local/bin/puppet-update-grub-env.py "
                           "--remove-kernelparams "
                           "\"systemd.unified_cgroup_hierarchy "
                           "SYSTEMD_CGROUP_ENABLE_LEGACY_FORCE\"",
                           shell=True, capture_output=True, check=False)
            subprocess.run("python /usr/local/bin/puppet-update-grub-env.py "
                           "--add-kernelparams "
                           "\"systemd.unified_cgroup_hierarchy=1 "
                           "cgroup_no_v1=all\"",
                           shell=True, capture_output=True, check=True)

            LOG.info("CgroupBootParamsHook: Boot params set for cgroup v2")
        except Exception as e:
            LOG.exception("CgroupBootParamsHook: Failed to set v2 boot params: %s" % e)
            raise

    def _set_v1_boot_params(self):
        """Set cgroup v1 kernel boot parameters (for rollback).

        Removes v2 params and restores v1 params so the next boot
        mounts the legacy per-controller cgroup hierarchy.
        """
        try:
            subprocess.run("python /usr/local/bin/puppet-update-grub-env.py "
                           "--remove-kernelparams "
                           "\"systemd.unified_cgroup_hierarchy cgroup_no_v1\"",
                           shell=True, capture_output=True, check=False)
            subprocess.run("python /usr/local/bin/puppet-update-grub-env.py "
                           "--add-kernelparams "
                           "\"systemd.unified_cgroup_hierarchy=0 "
                           "SYSTEMD_CGROUP_ENABLE_LEGACY_FORCE=1\"",
                           shell=True, capture_output=True, check=True)
            LOG.info("CgroupBootParamsHook: Boot params set for cgroup v1")
        except Exception as e:
            LOG.exception("CgroupBootParamsHook: Failed to set v1 boot params: %s" % e)
            raise

    def _update_hieradata(self, cgroup_v2=False):
        """Update puppet hieradata so boot manifest knows cgroup version.

        PuppetHieradataUpdate (which runs before us) replaces hieradata
        with static defaults from the new release package. Those defaults
        don't include cgroup_v2_enabled. Without this, puppet's
        platform::kubernetes::cgroup class would always try to create
        v1 cgroup dirs, failing on a v2 system.

        We write to /ostree/1/etc/puppet/hieradata/global.yaml which
        becomes /etc/puppet/hieradata/global.yaml after reboot.
        """
        hieradata_key = "platform::params::cgroup_v2_enabled"
        value = "true" if cgroup_v2 else "false"
        hieradata_path = os.path.join(self.TO_RELEASE_OSTREE_DIR,
                                      "etc/puppet/hieradata/global.yaml")
        try:
            if not os.path.exists(hieradata_path):
                LOG.info("CgroupBootParamsHook: %s not found, skipping"
                         % hieradata_path)
                return
            with open(hieradata_path, 'r') as f:
                data = yaml.load(f)
            data[hieradata_key] = value
            with open(hieradata_path, 'w') as f:
                yaml.dump(data, f)
            LOG.info("CgroupBootParamsHook: set %s: %s in hieradata"
                     % (hieradata_key, value))
        except Exception as e:
            LOG.exception("CgroupBootParamsHook: failed to update hieradata: %s"
                          % e)

    def _revert_kubelet_cgroup_config_from_2610(self):
        """Revert cgroupRoot back to /k8s-infra for rollback.

        On rollback, the system goes back to the old release which
        uses k8s-infra as the cgroup name. The config.yaml was
        migrated to /k8sinfra during upgrade and must be reverted,
        otherwise kubelet will look for k8sinfra dirs that don't
        exist on the old release.
        """
        config_path = "/var/lib/kubelet/config.yaml"
        if not os.path.exists(config_path):
            LOG.info("CgroupBootParamsHook: %s not found, skipping" % config_path)
            return
        try:
            with open(config_path, 'r') as f:
                content = f.read()
            changed = False
            if 'cgroupRoot: /k8sinfra' in content:
                content = content.replace('cgroupRoot: /k8sinfra',
                                          'cgroupRoot: /k8s-infra')
                changed = True
                LOG.info("CgroupBootParamsHook: reverted cgroupRoot to /k8s-infra")
            if 'cgroupDriver: systemd' in content:
                content = content.replace('cgroupDriver: systemd',
                                          'cgroupDriver: cgroupfs')
                changed = True
                LOG.info("CgroupBootParamsHook: reverted cgroupDriver to cgroupfs")
            if changed:
                with open(config_path, 'w') as f:
                    f.write(content)
        except Exception as e:
            LOG.exception("CgroupBootParamsHook: failed to revert %s: %s"
                          % (config_path, e))

    def _rollback_cgroup_config_from_2610(self):
        """Handle rollback: revert all cgroup changes to old release state.

        Restores:
        - Boot params: v1 kernel params
        - config.yaml: cgroupRoot /k8sinfra -> /k8s-infra, cgroupDriver -> cgroupfs
        - Hieradata: cgroup_v2_enabled=false
        """
        LOG.info("CgroupBootParamsHook: Rollback - reverting to v1")
        self._set_v1_boot_params()
        self._revert_kubelet_cgroup_config_from_2610()
        self._update_hieradata(cgroup_v2=False)
        LOG.info("CgroupBootParamsHook: COMPLETED (rollback)")

    def run(self):
        LOG.info("CgroupBootParamsHook: STARTED")
        LOG.info(f"CgroupBootParamsHook: action={self._action}")

        # Note: remove when 26.10 is no longer supported
        if self._action == HookManager.MAJOR_RELEASE_ROLLBACK and \
           self._from_release == "26.10":

            self._rollback_cgroup_config_from_2610()
            return

        # Note: remove when 26.10 is no longer supported
        if self._action == HookManager.MAJOR_RELEASE_UPGRADE and \
           self._to_release == "26.10":

            # Upgrade path — always fix cgroupRoot rename
            value = self._get_cgroup_v2_enabled()
            LOG.info(f"CgroupBootParamsHook: DB value={repr(value)}")

            # Determine cgroup version intent
            cgroup_v2 = (value is not None and value.lower() == 'true')

            # Set boot params based on intent
            if cgroup_v2:
                LOG.info("CgroupBootParamsHook: setting v2 boot params")
                self._set_v2_boot_params()
            else:
                LOG.info("CgroupBootParamsHook: setting v1 boot params")
                self._set_v1_boot_params()

            self._update_hieradata(cgroup_v2=cgroup_v2)

        LOG.info("CgroupBootParamsHook: COMPLETED")


class PuppetHieradataUpdate(BaseHook):
    """
    Replace puppet hieradata files with the to-release versions.
    """

    HIERADATA_DIR = "etc/puppet/hieradata"
    USR_HIERADATA_DIR = os.path.join("usr", HIERADATA_DIR)

    # Exception: region keys in controller.yaml need to carry on
    # the deployment-specific value.
    def replace_region_in_controller_yaml(self):
        current_file = os.path.join("/", self.HIERADATA_DIR, "controller.yaml")
        destination_file = self.get_new_deploy_path(current_file)
        try:
            LOG.info(f"Updating region in {destination_file}")
            with open(current_file) as f:
                data = yaml.load(f)
                current_region = data.get("platform::mtce::params::auth_region")

            with open(destination_file, "r") as f:
                data = yaml.load(f)
                data["platform::mtce::params::auth_region"] = current_region
                data["keystone::endpoint::region"] = current_region

            with open(destination_file, "w") as f:
                yaml.dump(data, f)

        except Exception:
            LOG.exception(f"Failed to replace region in {destination_file}")
            raise

    def copy_hieradata_files(self):
        src_dir = os.path.join(self.TO_RELEASE_OSTREE_DIR, self.USR_HIERADATA_DIR)
        dst_dir = os.path.join(self.TO_RELEASE_OSTREE_DIR, self.HIERADATA_DIR)
        for filename in glob.glob(os.path.join(src_dir, "*.yaml")):
            dst = os.path.join(dst_dir, os.path.basename(filename))
            try:
                LOG.info(f"Replacing {dst} with {filename}")
                shutil.copyfile(filename, dst)
            except Exception:
                LOG.exception(f"Failed to copy {filename} to {dst}")
                raise

    def run(self):
        LOG.info("Running PuppetHieradataUpdate hook")
        self.copy_hieradata_files()
        self.replace_region_in_controller_yaml()


class LdapConfigHook(BaseHook):
    """
    Update LDAP configurations during upgrade and rollback.
    LDAP server files are replaced, and it is reconfigured from scratch by puppet.
    """
    LDAP_DIR = "etc/ldap"
    LDAP_PASSWD_FILE = "/etc/ldapscripts/ldapscripts.passwd"
    POLICY_DN = "cn=default,ou=policies,dc=cgcs,dc=local"

    def _get_ldap_admin_pw(self):
        with open(self.LDAP_PASSWD_FILE, "r") as f:
            return f.read().strip()

    def _policy_has_attr(self, attr):
        try:
            admin_pw = self._get_ldap_admin_pw()
            result = subprocess.run(
                ["ldapsearch", "-x", "-H", "ldap:///",
                 "-D", "cn=ldapadmin,dc=cgcs,dc=local",
                 "-w", admin_pw, "-b", self.POLICY_DN,
                 "-s", "base", attr],
                capture_output=True, text=True, check=True)
            return "%s:" % attr in result.stdout
        except Exception:
            LOG.exception("Failed to check attribute %s", attr)
            return False

    def _rollback_ppm_policy_trixie(self):
        """TODO: Remove after stx 13 upgrade.
        On rollback, remove pwdUseCheckModule and pwdCheckModuleArg and
        restore old password policy module 'check_password.so' on rollback.
        """
        config_dir = "/%s/schema" % self.LDAP_DIR
        needs_inject = False
        try:
            admin_pw = self._get_ldap_admin_pw()

            del_ops = []
            for attr in ("pwdUseCheckModule", "pwdCheckModuleArg"):
                if self._policy_has_attr(attr):
                    del_ops.append("delete: %s\n" % attr)
            if del_ops:
                ldif = (
                    "dn: %s\n"
                    "changetype: modify\n" % self.POLICY_DN
                    + "-\n".join(del_ops) + "\n"
                )
                subprocess.run(
                    ["ldapmodify", "-x", "-H", "ldap:///",
                     "-D", "cn=ldapadmin,dc=cgcs,dc=local",
                     "-w", admin_pw],
                    input=ldif, check=True,
                    capture_output=True, text=True)
                LOG.info("Deleted new ppm attributes online")

            # The Trixie schema does not define pwdCheckModule, so it cannot
            # be added via ldapmodify, instead we need to inject it with slapmodify
            needs_inject = not self._policy_has_attr("pwdCheckModule")
            if needs_inject:
                subprocess.run(["systemctl", "stop", "slapd"],
                               check=True, capture_output=True, text=True)
                LOG.info("Stopped slapd for offline ppm injection")

                inject_ldif = (
                    "dn: %s\n"
                    "changetype: modify\n"
                    "add: pwdCheckModule\n"
                    "pwdCheckModule: check_password.so\n" % self.POLICY_DN
                )

                # Don't need to delete this, rollback requires rebooting
                with tempfile.NamedTemporaryFile(
                        mode="w", suffix=".ldif", delete=False) as f:
                    f.write(inject_ldif)
                    ldif_path = f.name

                subprocess.run(["slapmodify", "-F", config_dir,
                               "-b", "dc=cgcs,dc=local", "-l", ldif_path],
                               check=True, capture_output=True, text=True)
                LOG.info("Injected pwdCheckModule via slapmodify")

                subprocess.run(["systemctl", "start", "slapd"],
                               check=True, capture_output=True, text=True)

            LOG.info("Rolled back ppm policy to use check_password.so")
        except Exception:
            LOG.exception("Failed to rollback ppm policy")
        finally:
            if needs_inject:
                # start slapd in case of exception
                subprocess.run(["systemctl", "start", "slapd"],
                               check=False, capture_output=True, text=True)

    def run(self):
        # No need to reconfigure if both sides are running the same debian release
        if self.get_from_release_debian_codename() == self.get_to_release_debian_codename():
            LOG.info("Same Debian release, skipping LdapConfigHook")
            return

        LOG.info("Running LdapConfigHook")

        # Rollback ppm policy before replacing LDAP config files
        if self._action == HookManager.MAJOR_RELEASE_ROLLBACK:
            if self.get_from_release_debian_codename() == "trixie":
                self._rollback_ppm_policy_trixie()

        src = os.path.join(self.TO_RELEASE_OSTREE_DIR, "usr", self.LDAP_DIR)
        dst = os.path.join(self.TO_RELEASE_OSTREE_DIR, self.LDAP_DIR)
        if os.path.isdir(src):
            shutil.rmtree(dst, ignore_errors=True)
            shutil.copytree(src, dst, symlinks=True)
            LOG.info("Replaced %s with contents from %s", dst, src)
        else:
            LOG.warning("Source not found: %s", src)


class OpenstackConfHook(BaseHook):
    """
    Generate and install updated openstack conf files into the
    to-release deployment during deploy-host.

    Updates OpenStack conf files to use the RELEASE_N template content
    while preserving existing configuration values, except for
    filtered/deprecated configurations.

    Conf files handled:
    - /etc/keystone/keystone.conf
    - /etc/barbican/barbican.conf
    """
    TEMPLATE_BASE = (
        "usr/share/ansible/stx-ansible/playbooks/roles/bootstrap/"
        "apply-manifest/templates"
    )

    # Release versions for exclusion mapping
    RELEASE_N = "26.10"
    RELEASE_N1 = "26.03"
    RELEASE_N2 = "25.09"

    # Staging area for generated conf files and backups.
    BACKUP_SUFFIX = ".pre-upgrade"

    # Conf files handled, keyed by filename.
    # Each value: (live_path, template_relative_path)
    # template_relative_path is relative to TEMPLATE_BASE.
    CONF_FILE_MAP = {
        "keystone.conf": (
            "/etc/keystone/keystone.conf",
            "keystone/keystone.conf-trixie.j2",
        ),
        "barbican.conf": (
            "/etc/barbican/barbican.conf",
            "barbican.conf-trixie.j2",
        ),
    }

    # Values to exclude when carrying forward old config into new
    # template.  Keyed by (from_release, to_release), each mapping conf
    # filename to a list of (section, option, reason) tuples.
    EXCLUSIONS = {
        (RELEASE_N1, RELEASE_N): {
            "keystone.conf": [
                # ldap pool options default to True in RELEASE_N and are not
                # recommended to be set False (per upstream conf comments).
                ("ldap", "use_pool",
                 "defaults to True; setting False not recommended"),
                ("ldap", "use_auth_pool",
                 "defaults to True; setting False not recommended"),
                # policy_file not set on bootstrap in RELEASE_N; The n-1
                # upgrade uses its absolute path. Remove for consistency.
                ("oslo_policy", "policy_file",
                 "not set on trixie bootstrap; template default applies"),
            ],
            "barbican.conf": [
                # sql_connection removed; replaced by [database]/connection
                # via oslo.db migration.
                ("DEFAULT", "sql_connection",
                 "removed; replaced by [database]/connection"),
            ],
        },
        (RELEASE_N2, RELEASE_N): {
            "keystone.conf": [
                # ldap pool options default True in RELEASE_N and are not
                # recommended to be set False (per upstream conf comments).
                ("ldap", "use_pool",
                 "defaults to True; setting False not recommended"),
                ("ldap", "use_auth_pool",
                 "defaults to True; setting False not recommended"),
                # policy_file not set on bootstrap in RELEASE_N; old .json
                # should not carry forward. Template default is policy.yaml.
                ("oslo_policy", "policy_file",
                 "not set on trixie bootstrap; template default applies"),
            ],
            "barbican.conf": [
                # sql_connection removed; replaced by [database]/connection
                # via oslo.db migration.
                ("DEFAULT", "sql_connection",
                 "removed; replaced by [database]/connection"),
            ],
        },
    }

    def _get_exclusions(self, from_release, to_release, conf_name):
        """Get the exclusion list for a given upgrade path and conf file.

        Combines exclusions from intermediate releases for N-2 upgrades.
        Returns a list of (section, option, reason) tuples.
        """
        result = []
        key = (from_release, to_release)
        if key in self.EXCLUSIONS:
            result.extend(self.EXCLUSIONS[key].get(conf_name, []))
        return result

    def _apply_exclusions(self, values, exclusions, conf_name):
        """Remove excluded values and log warnings.

        Logs a warning for each exclusion that was not found in the values
        (filter not activated).
        """
        for section, option, reason in exclusions:
            if section in values and option in values[section]:
                del values[section][option]
                if not values[section]:
                    del values[section]
                LOG.info("Excluded [%s]/%s from %s: %s",
                         section, option, conf_name, reason)
            else:
                LOG.warning("Exclusion not activated for [%s]/%s in %s: "
                            "value not present", section, option, conf_name)

    def _read_config_values(self, conf_path):
        """Read all non-default config values from an INI file.

        Returns a dict of {section: {option: value}} containing only
        values explicitly set in each section (not inherited from DEFAULT).
        DEFAULT section values are returned under the key 'DEFAULT'.
        """
        parser = configparser.RawConfigParser()
        parser.read(conf_path)

        values = {}

        # Capture DEFAULT section values
        defaults = dict(parser.defaults())
        if defaults:
            values['DEFAULT'] = defaults

        # Capture section-specific values (excluding inherited defaults)
        for section in parser.sections():
            own_items = {
                k: v for k, v in parser.items(section)
                if k not in defaults or defaults[k] != v
            }
            if own_items:
                values[section] = own_items

        return values

    def _write_config(self, values, dest_path, template_path):
        """Write a conf file using the new template as the base.

        Uses the new template file (preserving comments and structure),
        then replaces matching option lines with the preserved config
        values from the old release.
        """
        with open(template_path, 'r') as f:
            template_lines = f.readlines()

        output_lines = []
        current_section = None
        values_written = set()

        for line in template_lines:
            stripped = line.strip()

            # Track current section
            section_match = re.match(r'^\[(.+)\]$', stripped)
            if section_match:
                # Before leaving current section, append values that
                # belong to this section but not matched to a template line
                if current_section is not None:
                    section_values = values.get(current_section, {})
                    for opt in sorted(section_values):
                        key = (current_section, opt)
                        if key not in values_written:
                            output_lines.append('%s = %s\n' % (
                                opt, section_values[opt]))
                            values_written.add(key)

                current_section = section_match.group(1)
                output_lines.append(line)
                continue

            # Before the first section header, treat as DEFAULT
            if current_section is None:
                output_lines.append(line)
                continue

            # Check if this line sets a config option (commented or uncommented)
            # Also handles Jinja2 template lines like: connection = {{ var }}
            opt_match = re.match(
                r'^(#?)\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=', stripped
            )

            if opt_match:
                is_commented = opt_match.group(1) == '#'
                option_name = opt_match.group(2).lower()
                key = (current_section, option_name)
                section_values = values.get(current_section, {})
                if option_name in section_values and key not in values_written:
                    if is_commented:
                        # Keep the commented default
                        output_lines.append(line)
                    # Insert the active value
                    output_lines.append('%s = %s\n' % (
                        option_name, section_values[option_name]))
                    values_written.add(key)
                    continue

            output_lines.append(line)

        # Append any remaining values for the last section
        section_values = values.get(current_section, {})
        for opt in sorted(section_values):
            key = (current_section, opt)
            if key not in values_written:
                output_lines.append('%s = %s\n' % (opt, section_values[opt]))
                values_written.add(key)

        # Append values for sections not present in the template
        for section in sorted(values):
            section_values = values[section]
            has_unwritten = any(
                (section, opt) not in values_written for opt in section_values
            )
            if not has_unwritten:
                continue
            if section != 'DEFAULT':
                output_lines.append('\n[%s]\n' % section)
            for opt in sorted(section_values):
                key = (section, opt)
                if key not in values_written:
                    output_lines.append('%s = %s\n' %
                                        (opt, section_values[opt]))
                    values_written.add(key)

        fd = os.open(dest_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
        with os.fdopen(fd, 'w') as f:
            f.writelines(output_lines)

    def _generate_conf(self, live_path, template_path, dest_path,
                       from_release, to_release):
        """Generate an updated conf file from live conf + new template.

        Reads values from live_path, applies exclusions, writes the result
        to dest_path using template_path as the base.
        """
        conf_name = os.path.basename(live_path)

        values = self._read_config_values(live_path)
        if not values:
            LOG.error("No config values read from %s", live_path)
            raise RuntimeError("No config values read from %s" % live_path)

        # Apply exclusions
        if from_release and to_release:
            exclusions = self._get_exclusions(from_release,
                                              to_release,
                                              conf_name)
            if exclusions:
                self._apply_exclusions(values, exclusions, conf_name)

        # Write the new config
        self._write_config(values, dest_path, template_path)

        # Warn if any Jinja2 placeholders survived
        with open(dest_path, 'r') as f:
            if '{{' in f.read():
                LOG.warning("Jinja2 placeholders remain in %s", dest_path)

        LOG.info("%s generated successfully", conf_name)

    def _deploy_host_install(self, ostree_dir, from_release, to_release):
        """Called by OpenstackConfHook during deploy-host upgrade.

        For each conf file: reads live conf, generates updated conf,
        backs up and installs to ostree deployment.
        """
        # to_release barrier
        if to_release != self.RELEASE_N:
            LOG.info("Release is not affected (%s), skipping", to_release)
            return

        for conf_name, (live_path, tmpl_rel) in self.CONF_FILE_MAP.items():
            template_path = os.path.join(ostree_dir,
                                         self.TEMPLATE_BASE,
                                         tmpl_rel)
            dst = os.path.join(ostree_dir,
                               os.path.dirname(live_path).lstrip('/'),
                               conf_name)

            if not os.path.exists(live_path):
                LOG.warning("Live conf not found: %s", live_path)
                continue
            if not os.path.exists(template_path):
                LOG.warning("Template not found: %s", template_path)
                continue

            # Backup ostree destination
            backup_path = dst + self.BACKUP_SUFFIX
            dst_stat = os.stat(dst)
            shutil.copy2(dst, backup_path)
            os.chown(backup_path, dst_stat.st_uid, dst_stat.st_gid)
            LOG.info("Backed up %s to %s", dst, backup_path)

            # Generate and install
            self._generate_conf(live_path, template_path, dst,
                                from_release, to_release)

            # Preserve original permissions and ownership
            os.chmod(dst, dst_stat.st_mode & 0o7777)
            os.chown(dst, dst_stat.st_uid, dst_stat.st_gid)
            LOG.info("Installed updated %s", conf_name)

    def _deploy_host_restore(self, ostree_dir):
        """Called by OpenstackConfHook during deploy-host rollback.

        Restores backed-up conf files into the ostree deployment.
        """
        for conf_name, (live_path, _) in self.CONF_FILE_MAP.items():
            dst = os.path.join(ostree_dir,
                               os.path.dirname(live_path).lstrip('/'),
                               conf_name)
            backup = dst + self.BACKUP_SUFFIX
            if os.path.exists(backup):
                st = os.stat(backup)
                shutil.copy2(backup, dst)
                os.chown(dst, st.st_uid, st.st_gid)
                LOG.info("Restored %s from %s", dst, backup)
            else:
                LOG.warning("Backup not found: %s", backup)

    def run(self):
        if self._action == HookManager.MAJOR_RELEASE_UPGRADE:
            self._install()
        elif self._action == HookManager.MAJOR_RELEASE_ROLLBACK:
            self._restore()

    def _install(self):
        LOG.info("Running OpenstackConfHook install")
        if self.get_platform_conf("nodetype") != self.CONTROLLER:
            LOG.info("OpenstackConfHook: not a controller, skipping")
            return
        codename = self.get_to_release_debian_codename()
        if "trixie" != codename:
            # barrier for RELEASE_N bullseye versus trixie
            # The current N release is in transition
            LOG.info("OpenstackConfHook: not trixie (codename=%s), "
                     "skipping", codename)
            return

        self._deploy_host_install(self.TO_RELEASE_OSTREE_DIR,
                                  self._from_release,
                                  self._to_release)

    def _restore(self):
        LOG.info("Running OpenstackConfHook restore")
        if self.get_platform_conf("nodetype") != self.CONTROLLER:
            LOG.info("OpenstackConfHook: not a controller, skipping")
            return
        codename = self.get_from_release_debian_codename()
        if "trixie" != codename:
            # barrier for RELEASE_N bullseye versus trixie
            # The current N release is in transition
            LOG.info("OpenstackConfHook: not trixie (codename=%s), "
                     "skipping", codename)
            return

        self._deploy_host_restore(self.TO_RELEASE_OSTREE_DIR)


class EtcdUpgradeRollbackHook(BaseHook):
    """Manage etcd version symlink and data during upgrade/rollback.

    On upgrade:
      - Ensures /var/lib/etcd/stage0 symlink exists pointing to the
        correct etcd binary version, using hieradata as source of truth.
      - Creates the symlink if missing (legacy upgrade path where K8s
        control-plane upgrade has not yet run).

    On rollback:
      - Determines the correct etcd version for the old release
        (max installed etcd binary on old side, or fallback to 3.4.37).
      - Updates /var/lib/etcd/stage0 symlink to point to old binary.
      - Updates static hieradata with the old etcd version.
      - Wipes etcd member data to avoid version incompatibility on
        restart (etcd cannot downgrade cluster version).
    """

    ETCD_PATH = "/var/lib/etcd"
    ETCD_STAGE0_LINK = "/var/lib/etcd/stage0"
    ETCD_MEMBER_DIR = "/opt/etcd/db/controller.etcd/member"
    ETCD_VERSIONED_BINARIES_ROOT = "/usr/local/etcd/"
    # Fallback etcd versions for releases that don't have the versioned
    # etcd infrastructure (/usr/local/etcd/, stage0 symlink, hieradata).
    # Only 25.09 requires this; 26.03 and onwards have the infrastructure
    # so primary detection methods (hieradata, symlink, binaries) work.
    ETCD_FALLBACK_VERSIONS = {
        "25.09": "3.4.37",
    }

    HIERADATA_KEY = "platform::etcd::params::etcd_version"

    def _get_hieradata_path(self):
        sw_version = self.get_platform_conf("sw_version")
        return (f"/opt/platform/puppet/{sw_version}"
                f"/hieradata/static.yaml")

    def _get_etcd_version_from_hieradata(self):
        """Read etcd version from puppet hieradata."""
        hieradata_path = self._get_hieradata_path()
        try:
            with open(hieradata_path, "r") as f:
                data = yaml.load(f)
                return data.get(self.HIERADATA_KEY)
        except Exception as e:
            LOG.warning("Failed to read etcd version from "
                        "hieradata %s: %s" % (hieradata_path, e))
        return None

    def _get_max_installed_etcd_version(self, root_dir="/"):
        """Find the highest installed etcd binary version.

        Etcd binaries are installed under /usr/local/etcd/<version>/
        """
        return self._get_installed_etcd_version(root_dir, use_max=True)

    def _get_min_installed_etcd_version(self, root_dir="/"):
        """Find the lowest installed etcd binary version.

        Etcd binaries are installed under /usr/local/etcd/<version>/
        """
        return self._get_installed_etcd_version(root_dir, use_max=False)

    def _get_installed_etcd_version(self, root_dir="/", use_max=True):
        """Find installed etcd binary version (max or min)."""
        etcd_dir = os.path.join(root_dir,
                                self.ETCD_VERSIONED_BINARIES_ROOT.lstrip('/'))
        versions = []
        try:
            if os.path.isdir(etcd_dir):
                for entry in os.listdir(etcd_dir):
                    full_path = os.path.join(etcd_dir, entry)
                    if os.path.isdir(full_path):
                        versions.append(entry)
        except Exception as e:
            LOG.warning("Failed to list etcd versions in %s: %s"
                        % (etcd_dir, e))
        if versions:
            versions.sort(key=version.parse)
            return versions[-1] if use_max else versions[0]
        return None

    def _update_stage0_symlink(self, etcd_version, check_root="/"):
        """Create or update /var/lib/etcd/stage0 symlink.

        The symlink format is:
        /var/lib/etcd/stage0 -> /usr/local/etcd/<version>/stage0

        The check_root parameter is used only to verify the target
        exists before creating the symlink (e.g., /ostree/2 for old
        release during rollback).
        """
        symlink_target = os.path.join(
            self.ETCD_VERSIONED_BINARIES_ROOT, etcd_version, "stage0")
        check_path = os.path.join(check_root, symlink_target.lstrip('/'))
        if not os.path.exists(check_path):
            LOG.warning("etcd stage0 target not found at %s" % check_path)
            return False

        os.makedirs(self.ETCD_PATH, exist_ok=True)
        if os.path.islink(self.ETCD_STAGE0_LINK):
            os.unlink(self.ETCD_STAGE0_LINK)
        elif os.path.exists(self.ETCD_STAGE0_LINK):
            os.remove(self.ETCD_STAGE0_LINK)

        os.symlink(symlink_target, self.ETCD_STAGE0_LINK)
        LOG.info("Updated etcd stage0 symlink: %s -> %s"
                 % (self.ETCD_STAGE0_LINK, symlink_target))
        return True

    def _update_hieradata(self, etcd_version, sw_version=None):
        """Update static hieradata with etcd version."""
        if not sw_version:
            sw_version = self.get_platform_conf("sw_version")
        hieradata_path = (f"/opt/platform/puppet/{sw_version}"
                          f"/hieradata/static.yaml")
        try:
            with open(hieradata_path, "r") as f:
                data = yaml.load(f)
            data[self.HIERADATA_KEY] = etcd_version
            with open(hieradata_path, "w") as f:
                yaml.dump(data, f)
            LOG.info("Updated hieradata %s: %s = %s"
                     % (hieradata_path, self.HIERADATA_KEY, etcd_version))
        except Exception as e:
            LOG.error("Failed to update hieradata: %s" % e)

    def _wipe_etcd_member_data(self):
        """Remove etcd member data to force fresh bootstrap.

        etcd does not support downgrade of cluster version. When rolling
        back to an older etcd binary, the existing member data (written
        at a higher cluster version) is incompatible. Removing the member
        directory forces etcd to bootstrap fresh on the rolled-back release.

        Mask etcd.service before wiping to prevent pmon or any other
        mechanism from restarting it. Using --runtime --now so the mask
        does not persist after reboot.
        """
        try:
            subprocess.run(["systemctl", "mask", "etcd.service",
                            "--runtime", "--now"],
                           check=True, capture_output=True, text=True)
            LOG.info("Masked and stopped etcd.service")
        except subprocess.CalledProcessError as e:
            LOG.warning("Failed to mask etcd.service: %s" % e.stderr)
        if os.path.exists(self.ETCD_MEMBER_DIR):
            shutil.rmtree(self.ETCD_MEMBER_DIR)
            LOG.info("Removed etcd member data: %s"
                     % self.ETCD_MEMBER_DIR)
        else:
            LOG.info("etcd member data not found: %s"
                     % self.ETCD_MEMBER_DIR)

    def _upgrade(self):
        """Ensure etcd symlink exists for upgrade path."""
        LOG.info("Starting EtcdUpgradeRollbackHook upgrade.")
        if os.path.exists(self.ETCD_STAGE0_LINK):
            LOG.info("etcd stage0 symlink already exists: %s"
                     % os.readlink(self.ETCD_STAGE0_LINK))
            return

        etcd_version = self._get_etcd_version_from_hieradata()
        if not etcd_version:
            etcd_version = self._get_min_installed_etcd_version()
        if not etcd_version:
            # On 25.09 without enabler patch, /usr/local/etcd/ does not
            # exist and hieradata may not have the key. Use fallback.
            fallback = self.ETCD_FALLBACK_VERSIONS.get(self._from_release)
            if fallback:
                etcd_version = fallback
                LOG.info("Using fallback etcd version for from_release "
                         "%s: %s" % (self._from_release, etcd_version))
            else:
                LOG.warning("Cannot determine etcd version for upgrade, "
                            "skipping symlink creation")
                return

        self._update_stage0_symlink(etcd_version,
                                    check_root=self.TO_RELEASE_OSTREE_DIR)
        self._update_hieradata(etcd_version, sw_version=self._to_release)
        LOG.info("EtcdUpgradeRollbackHook upgrade finished.")

    def _get_etcd_version_from_old_hieradata(self):
        """Read etcd version from the rollback target release hieradata."""
        hieradata_path = (f"/opt/platform/puppet/{self._to_release}"
                          f"/hieradata/static.yaml")
        try:
            with open(hieradata_path, "r") as f:
                data = yaml.load(f)
                return data.get(self.HIERADATA_KEY)
        except Exception as e:
            LOG.warning("Failed to read etcd version from old "
                        "hieradata %s: %s" % (hieradata_path, e))
        return None

    def _rollback(self):
        """Handle etcd version rollback.

        The stage0 symlink is on persistent storage (/var/lib/etcd/)
        and may have been created/modified during upgrade. It needs
        to be corrected or removed for the old release.

        For releases that don't have versioned etcd infrastructure
        (e.g., 25.09), remove the symlink. For releases with versioned
        etcd (26.03+), update the symlink to the correct old version.

        Hieradata update is not needed during rollback because the
        upgrade hook only modifies the to_release hieradata, never
        the from_release hieradata.
        """
        LOG.info("Starting EtcdUpgradeRollbackHook rollback.")

        # In rollback context:
        #   self._from_release = current (new) release
        #   self._to_release = target (old) release we roll back to
        #   TO_RELEASE_OSTREE_DIR (/ostree/1) = old release filesystem
        #   FROM_RELEASE_OSTREE_DIR (/ostree/2) = new release filesystem

        # Determine etcd version for the old (rollback target) release
        # Priority: old hieradata > old ostree binaries > fallback
        # NOTE: symlink is not used here because it is on persistent
        # storage and may have been overwritten during upgrade.
        etcd_version = self._get_etcd_version_from_old_hieradata()
        if not etcd_version:
            etcd_version = self._get_max_installed_etcd_version(
                self.TO_RELEASE_OSTREE_DIR)
        if not etcd_version:
            fallback = self.ETCD_FALLBACK_VERSIONS.get(self._to_release)
            if fallback:
                etcd_version = fallback
                LOG.warning("Could not determine etcd version from "
                            "hieradata or binaries, using fallback "
                            "for %s: %s" % (self._to_release, etcd_version))
            else:
                LOG.error(
                    "Cannot determine etcd version for rollback "
                    "to release %s. No hieradata, no installed "
                    "binaries found, and no fallback defined."
                    % self._to_release)
                return

        # Handle symlink based on whether old release has versioned
        # etcd infrastructure. Check the actual ostree rather than
        # release version, because enabler patch may have installed
        # versioned etcd binaries on older releases (e.g., 25.09
        # with combo P&K upgrade).
        old_etcd_dir = os.path.join(
            self.TO_RELEASE_OSTREE_DIR,
            self.ETCD_VERSIONED_BINARIES_ROOT.lstrip('/'))
        if os.path.isdir(old_etcd_dir):
            # Old release has versioned etcd — update symlink
            self._update_stage0_symlink(etcd_version,
                                        check_root=self.TO_RELEASE_OSTREE_DIR)
        else:
            # No versioned etcd on old release — remove symlink
            # (it points to a path that won't exist after reboot)
            if os.path.islink(self.ETCD_STAGE0_LINK):
                os.unlink(self.ETCD_STAGE0_LINK)
                LOG.info("Removed stage0 symlink (not used by %s)"
                         % self._to_release)

        # Only wipe etcd member data if the version is changing.
        # If etcd version is the same (K8s upgrade didn't run), the
        # database is compatible and wipe is not needed.
        current_etcd_version = self._get_etcd_version_from_hieradata()
        LOG.info("Rollback etcd version: target=%s, current=%s"
                 % (etcd_version, current_etcd_version))
        if current_etcd_version and current_etcd_version != etcd_version:
            self._wipe_etcd_member_data()
        else:
            LOG.info("etcd version unchanged, skipping member data wipe")

        LOG.info("EtcdUpgradeRollbackHook rollback finished.")

    def run(self):
        if self._action == HookManager.MAJOR_RELEASE_UPGRADE:
            self._upgrade()
        elif self._action == HookManager.MAJOR_RELEASE_ROLLBACK:
            self._rollback()


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
            EtcMerger,
            NtpToNtpsecMigrationHook,
            CopyPxeFilesHook,
            UpdateKernelParametersHook,
            ReconfigureKernelHook,
            OOTDriverHook,
            UpdateGrubConfigHook,
            EnableNewServicesHook,
            DeleteControllerFeedRemoteHook,
            FixedEtcMergeHook,
            KubeletUpgradeHook,
            EtcdUpgradeRollbackHook,
            LdapConfigHook,
            OpenstackConfHook,
            PuppetHieradataUpdate,
            CgroupBootParamsHook,
            # enable usm-initialize service for next
            # reboot only if everything else is done
            UsmInitHook,
        ],
        MAJOR_RELEASE_ROLLBACK: [
            ReconfigureKernelHook,
            UpdateKernelParametersHook,
            UpdateGrubConfigHook,
            DeleteControllerFeedRemoteHook,
            FixedEtcMergeRollBackHook,
            CreateKubeApiserverPortUpdatedFlag,
            NtpToNtpsecMigrationHook,
            EtcdUpgradeRollbackHook,
            LdapConfigHook,
            OpenstackConfHook,
            PuppetHieradataUpdate,
            CgroupBootParamsHook,
            SSSDCacheCleanupRollBackHook,
            RestorePlatformConfPermissionHook,
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


def parse_config(args=None):
    """Parse the parameters passed to the script"""
    parser = argparse.ArgumentParser(description="Run agent hooks.")
    parser.add_argument("--software-version",
                        help="Software version",
                        required=True)
    parser.add_argument("--additional-data",
                        help="Additional data (JSON format)",
                        required=False,
                        action='append')

    # if args was not passed will use sys.argv by default
    parsed_args = parser.parse_args(args)
    return vars(parsed_args)


def main(argv=None):
    config = parse_config(argv)
    software_version = config.get('software_version')
    additional_data_raw = config.get('additional_data')
    if additional_data_raw:
        additional_data = json.loads(additional_data_raw)
    else:
        additional_data = None

    # determine if it is a rollback and set the source directory
    # of the agent hook file accordingly
    if version.Version(software_version) > version.Version(SW_VERSION):
        ostree_path = BaseHook.TO_RELEASE_OSTREE_DIR
    else:
        ostree_path = BaseHook.FROM_RELEASE_OSTREE_DIR

    # load the agent hooks module dynamically
    agent_hooks_path = os.path.normpath(ostree_path + BaseHook.INSTALLATION_PATH)
    agent_hooks = load_module(agent_hooks_path, "agent_hooks")
    hook_manager = agent_hooks.HookManager.create_hook_manager(software_version,
                                                               additional_data=additional_data)
    # execute the agent hooks
    try:
        hook_manager.run_hooks()
        LOG.info("Agent hooks executed successfully.")
    except Exception as e:
        LOG.exception("Error running agent hooks: %s" % str(e))
        raise


if __name__ == '__main__':
    sys.exit(main())
