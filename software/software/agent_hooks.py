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
import filecmp
import fileinput
import glob
import logging as LOG
import os
from packaging import version
import re
import shutil
import subprocess
from ipaddress import ip_address
from ipaddress import IPv6Address
import psycopg2

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

    def run(self):
        """Execute the hook"""
        kernel_params = self.read_kernel_parameters()

        isolcpus = self.read_isolcpus(kernel_params)
        self.update_isolcpus(isolcpus)

        kthread_prio = self.read_kthread_prio(kernel_params)
        self.add_kthread_prio_if_not_set(kthread_prio)


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


class RestartKubeApiServer(BaseHook):
    """
    Restart the kube-apiserver after the host rollback/upgrade to
    resolve issues with the pods that are pending or show errors
    with kubectl exec following a host-swact on controller-1.
    This action ensures all pods run correctly and enables
    successful exec operations.
    """
    def run(self):
        nodetype = self.get_platform_conf("nodetype")
        if nodetype == self.CONTROLLER:
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


# TODO(heitormatsui): remove after stx-10 -> stx-11 upgrade
class FixedEtcMergeHook(BaseHook):
    """
    This hook ensures some specified files from to-release are
    kept in the deployed host instead of the 3-way merge version
    of the file
    """
    FILES = [
        "passwd",
        "group",
        "syslog-ng/syslog-ng.conf",
    ]

    def run(self):
        for file in self.FILES:
            src = os.path.normpath(self.TO_RELEASE_OSTREE_DIR + "/usr/etc/" + file)
            dst = os.path.normpath(self.TO_RELEASE_OSTREE_DIR + "/etc/" + file)
            shutil.copy2(src, dst)
            LOG.info("Copied %s to %s" % (src, dst))


# TODO(heitormatsui): remove after stx-10 -> stx-11 upgrade
class FixPSQLPermissionHook(BaseHook):
    """
    This hook fix postgres related files/directories permissions
     due to differences in uids and gids between releases
    """
    SSL_DIR = "/etc/ssl/private"

    def fix_cert_dir(self):
        try:
            cmd = ["grep", "ssl-cert", f"{self.TO_RELEASE_OSTREE_DIR}/usr/etc/group"]
            output = subprocess.run(cmd, text=True, check=True, stdout=subprocess.PIPE)
            gid = int(output.stdout.strip().split(":")[2])
            os.chown(f"{self.TO_RELEASE_OSTREE_DIR}/{self.SSL_DIR}", uid=0, gid=gid)
            LOG.info("Fixed %s directory ownership to 0:%s" % (self.SSL_DIR, gid))
        except subprocess.CalledProcessError as e:
            LOG.exception("Error fixing %s directory ownership: %s" % (self.SSL_DIR, str(e)))
            raise

    def run(self):
        self.fix_cert_dir()


class UpdateSyslogConfig(BaseHook):
    """
    This class updates the syslog configuration by:
    1. Removing all lines containing `d_sm` from `/etc/syslog-ng/syslog-ng.conf`.
    2. Replacing lines containing `f_local3` with `# Facility code local3 is assigned to Service Management`.
    """

    def __init__(self, attrs):
        super().__init__(attrs)
        self._config_path = self.TO_RELEASE_OSTREE_DIR + "/etc/syslog-ng/syslog-ng.conf"
        self._backup_path = f"{self._config_path}.bak"

    def _backup_syslog_config(self):
        """Create a backup of the syslog configuration file."""
        try:
            subprocess.check_call(['cp', self._config_path, self._backup_path])
            LOG.info("Backup created at %s", self._backup_path)
        except subprocess.CalledProcessError as e:
            LOG.exception("Failed to create backup: %s", str(e))
            raise

    def _remove_and_replace_lines(self):
        """Use `sed` to remove lines containing `d_sm` and replace lines containing `f_local3`."""
        try:
            # Use sed to remove lines containing 'd_sm' and replace 'f_local3' with a comment
            cmd = [
                "sed", "-i",
                "-e", "/d_sm/d",  # Remove lines containing 'd_sm'
                "-e", "s|.*f_local3.*|# Facility code local3 is assigned to Service Management|g",  # Replace lines with 'f_local3'
                self._config_path
            ]
            subprocess.check_call(cmd)
            LOG.info("Updated %s by removing lines with `d_sm` and replacing `f_local3` lines", self._config_path)
        except subprocess.CalledProcessError as e:
            LOG.exception("Failed to update %s using sed: %s", self._config_path, str(e))
            raise

    def _reload_syslog_service(self):
        """Reload the syslog-ng service to apply changes."""
        try:
            subprocess.check_call(['systemctl', 'reload', 'syslog-ng'])
            LOG.info("Syslog-ng service reloaded successfully.")
        except subprocess.CalledProcessError as e:
            LOG.exception("Failed to reload syslog-ng service: %s", str(e))
            raise

    def run(self):
        """Execute the update process."""
        try:
            LOG.info("Starting syslog configuration update.")
            self._backup_syslog_config()
            self._remove_and_replace_lines()
            self._reload_syslog_service()
            LOG.info("Syslog configuration update completed.")
        except Exception as e:
            LOG.error("Syslog configuration update failed: %s", str(e))


class RevertSyslogConfig(UpdateSyslogConfig):
    """
    This class reverts changes made to the syslog configuration by:
    1. Restoring the backup of `/etc/syslog-ng/syslog-ng.conf` created by UpdateSyslogConfig.
    2. Reloading the syslog-ng service to apply the restored configuration.
    """

    def _restore_backup(self):
        """Restore the syslog configuration from the backup."""
        try:
            if os.path.exists(self._backup_path):
                subprocess.check_call(['cp', self._backup_path, self._config_path])
                LOG.info("Restored %s from backup at %s", self._config_path, self._backup_path)
            else:
                raise FileNotFoundError(f"Backup file {self._backup_path} not found.")
        except subprocess.CalledProcessError as e:
            LOG.exception("Failed to restore the backup: %s", str(e))
            raise
        except FileNotFoundError as e:
            LOG.error(str(e))
            raise

    def _reload_syslog_service(self):
        """Reload the syslog-ng service to apply changes."""
        try:
            subprocess.check_call(['systemctl', 'reload', 'syslog-ng'])
            LOG.info("Syslog-ng service reloaded successfully.")
        except subprocess.CalledProcessError as e:
            LOG.exception("Failed to reload syslog-ng service: %s", str(e))
            raise

    def run(self):
        """Execute the revert process."""
        try:
            LOG.info("Starting syslog configuration revert.")
            self._restore_backup()
            self._reload_syslog_service()
            LOG.info("Syslog configuration revert completed.")
        except Exception as e:
            LOG.error("Syslog configuration revert failed: %s", str(e))


class RevertUmaskHook(BaseHook):
    """
    Reverts the umask setting during a MAJOR_RELEASE_ROLLBACK event by
    removing 'umask 027' from /root/.bashrc and /root/.bash_profile.
    """
    def run(self):
        try:
            self._remove_umask_setting("/root/.bashrc")
            self._remove_umask_setting("/root/.bash_profile")
            LOG.info("Successfully reverted umask settings during rollback.")
        except Exception as e:
            LOG.exception("Failed to revert umask settings: %s", str(e))

    def _remove_umask_setting(self, filepath):
        if not os.path.exists(filepath):
            LOG.warning("File not found: %s", filepath)
            return
        try:
            cmd = f"/bin/sed -i '/^\\s*umask\\s\\+027\\s*$/d' {filepath}"
            subprocess.run(cmd, shell=True, check=True, capture_output=True)
            LOG.info("Removed 'umask 027' from %s", filepath)
        except subprocess.CalledProcessError as e:
            LOG.exception("Error updating %s: %s", filepath, e.stderr.decode("utf-8"))


class FixShadowPasswordlessChar(BaseHook):
    """
    This hook modifies the shadow file by replacing the 'x' placeholder
    with '*' for specific users.
    """
    USERS_TO_UPDATE = [
        "nova", "neutron", "ceilometer", "sysinv", "snmpd",
        "fm", "libvirt", "ironic", "www", "keystone"
    ]

    def run(self):
        shadow = os.path.normpath(self.TO_RELEASE_OSTREE_DIR + "/etc/shadow")
        try:
            with open(shadow, "r") as file:
                lines = file.readlines()

                updated_lines = []
                for line in lines:
                    parts = line.split(":")
                    if len(parts) > 1 and parts[0] in self.USERS_TO_UPDATE and parts[1] == "x":
                        parts[1] = "*"
                    updated_lines.append(":".join(parts))

            with open(shadow, "w") as file:
                file.writelines(updated_lines)

            LOG.info("Replaced 'x' entries in the password field with '*' in %s", shadow)
        except Exception as e:
            LOG.exception("Error processing shadow file: %s", str(e))
            raise


class RevertCrtPermissionsHook(BaseHook):
    """
    This hook resets the permissions of .crt files in /etc/kubernetes/pki
    to 0644
    """

    PKI_DIR = "/etc/kubernetes/pki"

    def revert_crt_permissions(self):
        target_dir = os.path.join(
            self.TO_RELEASE_OSTREE_DIR, self.PKI_DIR.lstrip("/")
        )

        if not os.path.isdir(target_dir):
            LOG.warning("Directory does not exist: %s" % target_dir)
            return

        for root, _, files in os.walk(target_dir):
            for f in files:
                if f.endswith(".crt"):
                    filepath = os.path.join(root, f)
                    try:
                        os.chmod(filepath, 0o644)
                        LOG.info("Set permission 0644 on %s", filepath)
                    except Exception as e:
                        LOG.exception(
                            "Failed to set permission on %s: %s",
                            filepath,
                            str(e)
                        )
                        raise

    def run(self):
        self.revert_crt_permissions()


class LogPermissionRestorerHook(BaseHook):
    """
    This hook restores file permissions under /var/log
    from a backup file, and resets /etc/cron* configs using TO_RELEASE_OSTREE_DIR.
    """

    BACKUP_FILE_RELATIVE_PATH = "/var/log/.permission.txt"

    def restore_log_permissions(self):
        """Restore file permissions from the backup file."""
        backup_file = self.BACKUP_FILE_RELATIVE_PATH

        if not os.path.isfile(backup_file):
            LOG.info("Backup file '%s' not found. Exiting...", backup_file)
            return False

        success = True
        with open(backup_file, "r") as file:
            for line in file:
                parts = line.strip().split(" ", 1)
                if len(parts) != 2:
                    continue
                perm, file_path = parts
                if os.path.isfile(file_path):
                    try:
                        os.chmod(file_path, int(perm, 8))
                        LOG.info("Restored permissions %s for %s", perm, file_path)
                    except OSError as e:
                        LOG.exception(
                            "Failed to restore permissions for %s: %s", file_path, e
                        )
                        success = False
                else:
                    LOG.info("File %s not found, skipping...", file_path)

        if success:
            LOG.info("Permissions restored successfully. Proceeding to delete backup.")
            self.delete_backup()

        return success

    def delete_backup(self):
        """Delete the backup file if restoration was successful."""
        try:
            os.remove(self.BACKUP_FILE_RELATIVE_PATH)
            LOG.info(
                "Backup file '%s' deleted successfully.", self.BACKUP_FILE_RELATIVE_PATH
            )
        except OSError as e:
            LOG.exception("Failed to delete backup file: %s", e)

    def restore_cron_permissions(self):
        """
        Restore /etc/cron* permissions and delete cron.allow/at.allow files
        in the TO_RELEASE_OSTREE_DIR (next boot image).
        """
        cron_files = {
            "/etc/crontab": 0o644,
            "/etc/cron.d": 0o755,
            "/etc/cron.hourly": 0o755,
            "/etc/cron.daily": 0o755,
            "/etc/cron.weekly": 0o755,
            "/etc/cron.monthly": 0o755,
        }

        for path, perm in cron_files.items():
            full_path = os.path.join(self.TO_RELEASE_OSTREE_DIR, path.lstrip("/"))
            if os.path.exists(full_path):
                try:
                    os.chmod(full_path, perm)
                    LOG.info("Restored permissions %o for %s", perm, full_path)
                except OSError as e:
                    LOG.exception("Failed to set permissions for %s: %s", full_path, e)
            else:
                LOG.warning("%s not found, skipping permission restore", full_path)

        for path in ["/etc/cron.allow", "/etc/at.allow"]:
            full_path = os.path.join(self.TO_RELEASE_OSTREE_DIR, path.lstrip("/"))
            try:
                if os.path.exists(full_path):
                    os.remove(full_path)
                    LOG.info("Deleted file: %s", full_path)
                else:
                    LOG.info("File %s not found, skipping delete", full_path)
            except OSError as e:
                LOG.exception("Failed to delete file %s: %s", full_path, e)

    def run(self):
        self.restore_log_permissions()
        self.restore_cron_permissions()


class FixSimplexAddressesHook(BaseHook):
    """
    Reconfigure ceph-mon with the mgmt floating address
    """
    def connect_postgres_db(self):
        DEFAULT_POSTGRES_PORT = 5432
        username, password = self.get_db_credentials()
        conn = psycopg2.connect("dbname=sysinv user=%s password=%s \
                                host=localhost port=%s"
                                % (username, password, DEFAULT_POSTGRES_PORT))
        return conn

    def get_db_credentials(self):
        cp = configparser.ConfigParser()
        cp.read('/etc/sysinv/sysinv.conf')
        conn_string = cp['database']['connection']
        match = re.match(r'postgresql\+psycopg2://([^:]+):([^@]+)@', conn_string)
        if match:
            username = match.group(1)
            password = match.group(2)
            return username, password
        else:
            raise Exception("Failed to get database credentials from sysinv.conf")

    def db_query_one(self, query):
        try:
            conn = self.connect_postgres_db()
            with conn.cursor() as cursor:
                cursor.execute(query)
                result = cursor.fetchone()
                return result[0] if result else None
        except Exception as e:
            LOG.exception("Error executing query: %s" % e)
            raise
        finally:
            conn.close()

    def is_ceph_configured(self):
        query = (
            "SELECT storage_backend.state "
            "FROM storage_backend "
            "JOIN storage_ceph "
            "ON storage_ceph.id = storage_backend.id "
            "WHERE storage_backend.backend = 'ceph' "
            "AND storage_ceph.network = 'mgmt';"
        )
        res = self.db_query_one(query)
        return res and res == 'configured'

    def get_fsid(self):
        cp = configparser.ConfigParser()
        cp.read("/etc/ceph/ceph.conf")
        return cp["global"]["fsid"]

    def get_mon_ip(self):
        hosts_path = ""
        host = ""
        if self._to_release == "25.09":
            hosts_path = "/etc/hosts"
            host = "controller"
        elif self._to_release == "24.09":
            hosts_path = "/opt/platform/config/24.09/hosts"
            host = "controller-0"
        with open(hosts_path) as f:
            lines = f.readlines()
            for line in lines:
                fields = line.split()
                if fields[1] == host:
                    ip = fields[0]
                    mon_ip = f"[{ip}]" if isinstance(ip_address(ip), IPv6Address) else ip
                    return mon_ip, ip
        return None

    def run(self):
        # Handle both upgrade to 25.09 and rollback to 24.09
        if self._to_release == "24.09" or self._to_release == "25.09":
            system_mode = self.get_platform_conf("system_mode")
            if (system_mode == self.SIMPLEX):
                mon_ip, ip = self.get_mon_ip()

                # fix dnsmasq.addn_hosts until sysinv conductor fixes it definitely
                if self._to_release == "25.09":
                    LOG.info("fix-sx-addr: fixing dnsmasq.addn_hosts")
                    addn_hosts = "/opt/platform/config/25.09/dnsmasq.addn_hosts"
                    for line in fileinput.input(files=addn_hosts, inplace=True):
                        cols = line.split()
                        if "controller-0.internal" in cols[1]:
                            line = line.replace(cols[0], ip)
                        elif "controller-1.internal" in cols[1]:
                            continue
                        print(line, end="")

                if not self.is_ceph_configured():
                    LOG.info("fix-sx-addr: skipping ceph mon reconfig, bare metal ceph not configured for mgmt")
                    return

                fsid = self.get_fsid()
                mon_name = "controller-0"
                if not fsid or not mon_ip:
                    LOG.exception("Invalid fsid or mon_ip")
                    raise ValueError("Invalid params")
                LOG.info("fix-sx-addr: ceph mon: using fsid=%s, mon_name=%s, mon_ip=%s" % (fsid, mon_name, mon_ip))

                cmds = [
                    ["rm", "-f", "/etc/pmon.d/ceph.conf"],
                    ["/etc/init.d/ceph", "stop", "mon"],
                    ["ceph-mon", "--name", f"mon.{mon_name}", "--extract-monmap", f"/tmp/mon-{mon_name}.map"],
                    ["monmaptool", "--rm", f"{mon_name}", f"/tmp/mon-{mon_name}.map"],
                    ["monmaptool", "--add", f"{mon_name}", f"{mon_ip}:6789", f"/tmp/mon-{mon_name}.map"],
                    ["monmaptool", "--fsid", f"{fsid}", f"/tmp/mon-{mon_name}.map"],
                    ["ceph-mon", "--name", f"mon.{mon_name}", "--inject-monmap", f"/tmp/mon-{mon_name}.map"],
                    ["/etc/init.d/ceph", "start", "mon"],
                    ["ln", "-s", "/etc/ceph/ceph.conf.pmon", "/etc/pmon.d/ceph.conf"],
                ]
                if self._to_release == "24.09":
                    # For /etc/init.d/ceph start mon to work during rollback, need to add mon_ip temporarily
                    # to the loopback. This will corrected permanently after host unlock and reboot.
                    cmds.insert(0, ["ip", "address", "replace", f"{ip}", "dev", "lo"])

                try:
                    for cmd in cmds:
                        LOG.info("fix-sx-addr: exec: '%s'" % ' '.join(cmd))
                        subprocess.check_call(cmd, timeout=60)
                    LOG.info("fix-sx-addr: reconfiguration finished")
                except subprocess.CalledProcessError as e:
                    LOG.exception("fix-sx-addr: failed executing the command '%s': %s" % (' '.join(cmd), str(e)))
                    raise
            else:
                LOG.info("fix-sx-addr: skipping reconfiguration, system_mode is not simplex")


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

            LOG.info(f"Applying sysctl changes from {config_file}...")
            result = subprocess.run(['sudo', 'sysctl', '-p', config_file],
                                    capture_output=True, text=True, check=True)
            if result.stderr:
                LOG.error("sysctl -p errors:")
                LOG.error(result.stderr)
            LOG.info("sysctl changes applied successfully.")

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
            CopyPxeFilesHook,
            ReconfigureKernelHook,
            UpdateKernelParametersHook,
            UpdateGrubConfigHook,
            EnableNewServicesHook,
            UpdateSyslogConfig,
            FixedEtcMergeHook,
            FixShadowPasswordlessChar,
            FixPSQLPermissionHook,
            DeleteControllerFeedRemoteHook,
            RestartKubeApiServer,
            FixSimplexAddressesHook,
            CISSysctlFlagHookUpgrade,
            # enable usm-initialize service for next
            # reboot only if everything else is done
            UsmInitHook,
        ],
        MAJOR_RELEASE_ROLLBACK: [
            ReconfigureKernelHook,
            UpdateGrubConfigHook,
            RestartKubeApiServer,
            RevertSyslogConfig,
            FixedEtcMergeHook,
            FixPSQLPermissionHook,
            DeleteControllerFeedRemoteHook,
            RevertUmaskHook,
            RevertCrtPermissionsHook,
            LogPermissionRestorerHook,
            FixSimplexAddressesHook,
            CISSysctlFlagHookRollback,
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
            LOG.info("Upgrading from %s to %s, additional_data %s" % (
                     sw_version, software_version, additional_data))
            return HookManager(HookManager.MAJOR_RELEASE_UPGRADE, attrs=hook_attrs)

        # otherwise the operation is a rollback
        LOG.info("Rolling back from %s to %s, additional_data %s" % (
                 sw_version, software_version, additional_data))
        return HookManager(HookManager.MAJOR_RELEASE_ROLLBACK, attrs=hook_attrs)
