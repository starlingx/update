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
import configparser
import filecmp
import glob
import logging as LOG
import os
from packaging import version
import re
import shutil
import subprocess

log_format = ('%(asctime)s: ' + '[%(process)s]: '
              '%(filename)s(%(lineno)s): %(levelname)s: %(message)s')
LOG.basicConfig(filename="/var/log/software.log",
                format=log_format, level=LOG.INFO, datefmt="%FT%T")


class BaseHook(object):
    """Base Hook object"""
    TO_RELEASE_OSTREE_DIR = "/ostree/1"
    FROM_RELEASE_OSTREE_DIR = "/ostree/2"
    SYSTEMD_LIB_DIR = "/lib/systemd/system"
    SYSTEMD_ETC_DIR = "%s/etc/systemd/system/multi-user.target.wants" % TO_RELEASE_OSTREE_DIR
    CONTROLLER = "controller"
    PLATFORM_CONF_PATH = "/etc/platform/"
    PLATFORM_CONF_FILE = os.path.join(PLATFORM_CONF_PATH, "platform.conf")

    def __init__(self, attrs=None):
        pass

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
    def __init__(self, attrs):
        super().__init__()
        self._to_release = None
        if "to_release" in attrs:
            self._to_release = attrs.get("to_release")

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
    USM_UPGRADE_IN_PROGRESS_FLAG = os.path.join(BaseHook.PLATFORM_CONF_PATH,
                                                ".usm_upgrade_in_progress")

    def __init__(self, attrs):
        super().__init__(attrs)

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
    def __init__(self, attrs):
        super().__init__()

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
class EtcMergeHook(BaseHook):
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
        super().__init__()
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
    def __init__(self, attrs):
        super().__init__()

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
            CopyPxeFilesHook,
            ReconfigureKernelHook,
            UpdateKernelParametersHook,
            EnableNewServicesHook,
            UpdateSyslogConfig,
            EtcMergeHook,
            FixShadowPasswordlessChar,
            FixPSQLPermissionHook,
            DeleteControllerFeedRemoteHook,
            RestartKubeApiServer,
            # enable usm-initialize service for next
            # reboot only if everything else is done
            UsmInitHook,
        ],
        MAJOR_RELEASE_ROLLBACK: [
            ReconfigureKernelHook,
            RestartKubeApiServer,
            RevertSyslogConfig,
            EtcMergeHook,
            FixPSQLPermissionHook,
            DeleteControllerFeedRemoteHook,
            RevertUmaskHook,
            RevertCrtPermissionsHook,
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
