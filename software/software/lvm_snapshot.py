#!/usr/bin/python3
"""
Copyright (c) 2025 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import argparse
import configparser
import contextlib
import json
import logging
import shutil
import subprocess
import sys
import time
import tempfile

from datetime import datetime
from ipaddress import ip_address
from ipaddress import IPv6Address

from packaging import version
from pathlib import Path

LOG = logging.getLogger("main_logger")


class LVMSnapshot:
    ATTRIBUTES = ["lv_time", "lv_snapshot_invalid"]
    SEPARATOR = ","
    CREATE_DATE_MASK = "%Y-%m-%d %H:%M:%S %z"
    SOFTWARE_JSON_SNAPSHOT = "rootdirs/opt/software/software.json"
    SOFTWARE_JSON_CURRENT = "/opt/software/software.json"
    VIM_CONFIG = "/etc/nfv/vim/config.ini"

    def __init__(self, vg_name, lv_name, lv_size=None):
        self._vg_name = vg_name
        self._lv_name = lv_name
        self._lv_size = lv_size
        self._name = f"{lv_name}_snapshot"

    @property
    def lv_name(self):
        return self._lv_name

    @property
    def name(self):
        return self._name

    @staticmethod
    def get_command_abs_path(command):
        return Path("/usr/sbin") / command

    @staticmethod
    def run_command(command, shell=False, check=True):
        """
        Helper function to run shell commands and capture output
        :param command: command to be executed (can be list or string)
        :param shell: if command must run in a shell (command should be string)
        :param check: if subprocess.CalledProcessError must be raised when rc != 0
        """
        try:
            result = subprocess.run(command, shell=shell, check=check,
                                    text=True, capture_output=True)
            return result
        except subprocess.CalledProcessError as e:
            LOG.error("Error executing command: %s\n%s" % (command, e.stderr))
            raise
        except Exception as e:
            LOG.error("Error executing command: %s", str(e))
            raise

    def to_json(self):
        """
        Return snapshot object in a json serializable format
        """
        return {
            "name": self._name,
            "vg_name": self._vg_name,
            "lv_name": self._lv_name,
        }

    def get_dev_path(self):
        """
        Return snapshot path under /dev
        """
        return Path("/dev") / self._vg_name / self._name

    @contextlib.contextmanager
    def mount(self):
        """
        Mount the snapshot in a temporary directory, so that it's
        content can be manipulated to cover specific scenarios
        """
        mount_dir = tempfile.mkdtemp(prefix=f"{self._lv_name}-", dir="/tmp")
        try:
            self.run_command(["/usr/bin/mount", "-t", "ext4", self.get_dev_path(), mount_dir])
            LOG.info("Mounted %s under %s", self._name, mount_dir)
            yield mount_dir
        except Exception as e:
            LOG.error("Error mounting snapshot: %s", str(e))
            raise
        finally:
            self.run_command(["/usr/bin/umount", "-l", mount_dir])
            shutil.rmtree(mount_dir, ignore_errors=True)
            LOG.info("Directory %s unmounted and removed", mount_dir)

    def exists(self):
        """
        Check if a snapshot volume exists in the local filesystem
        """
        command = f"lvs --noheadings -o lv_name {self._vg_name} | grep -w {self._name}"
        result = self.run_command(command, shell=True, check=False)
        return result.returncode == 0

    def create(self):
        """
        Run the command to create a snapshot
        """
        command = [self.get_command_abs_path("lvcreate"), "-y", "-L", self._lv_size, "-s", "-n",
                   self._name, Path("/dev") / self._vg_name / self._lv_name]
        self.run_command(command)

    def restore(self):
        """
        Run the command to restore a snapshot
        """
        command = [self.get_command_abs_path("lvconvert"), "-y", "--merge",
                   Path("/dev") / self._vg_name / self._name]
        self.run_command(command)

    def delete(self):
        """
        Run the command to delete a snapshot
        """
        command = [self.get_command_abs_path("lvremove"), "-f",
                   Path("/dev") / self._vg_name / self._name]
        self.run_command(command)

    def get_attributes(self):
        """
        Get the creation date and status for a snapshot
        """
        command = [self.get_command_abs_path("lvdisplay"), self._vg_name, "--select",
                   f"lv_name={self._name}", "--noheadings",
                   f"--separator={self.SEPARATOR}",
                   "-C", "-o", ",".join(self.ATTRIBUTES)]
        process = self.run_command(command)
        output = process.stdout.strip()
        attributes = output.split(self.SEPARATOR)
        create_date = attributes[0]
        valid_state = "invalid" not in attributes[1].lower()
        return datetime.strptime(create_date, self.CREATE_DATE_MASK), valid_state

    # TODO(sshathee) Delete this function and use the one in utils file.
    # Currently lvm snapshot is executed from feed repo where utils file
    # is not copied.
    @staticmethod
    def get_major_release_version(sw_release_version):
        """
        Get the major release for a given software version
        """
        if not sw_release_version:
            return None
        else:
            try:
                separator = '.'
                separated_string = sw_release_version.split(separator)
                major_version = separated_string[0] + separator + separated_string[1]
                return major_version
            except Exception:
                return None

    @staticmethod
    def read_file(file_path):
        """
        Read a json file and return its parsed content
        """
        with open(file_path, "r") as fp:
            content = json.loads(fp.read())
        return content


class VarSnapshot(LVMSnapshot):
    def _update_deployment_data(self):
        try:
            with self.mount() as mount_dir:
                software_json = Path(mount_dir) / self.SOFTWARE_JSON_SNAPSHOT
                shutil.copy2(self.SOFTWARE_JSON_CURRENT, software_json)
                LOG.info("Copied current deployment to %s", software_json)
                content = self.read_file(software_json)
                deploy_host = content.get("deploy_host")
                for host in deploy_host:
                    host["state"] = "rollback-deployed"
                deploy = content.get("deploy")
                for d in deploy:
                    d["state"] = "host-rollback-done"
                    from_release = d["from_release"]
                    to_release = d["to_release"]
                    if version.Version(to_release) > version.Version(from_release):
                        d["from_release"] = to_release
                        d["to_release"] = from_release
                with open(software_json, "w") as fp:
                    fp.write(json.dumps(content))
                LOG.info("Deployment data updated")
        except Exception as e:
            LOG.error("Failure updating %s: %s", software_json, str(e))
            raise

    def restore(self):
        """
        Override default restore behavior for var-lv; which has
        the following specific scenarios to treat on restore:
        - software.json needs to be updated to the current status, otherwise
          will be restored with the pre-deploy start content incorrectly
        """
        self._update_deployment_data()
        super().restore()


class PlatformSnapshot(LVMSnapshot):
    @staticmethod
    def _wait_for_vim_ready(timeout=20):
        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                subprocess.run(
                    ["bash", "-c",
                     "source /etc/platform/openrc; sw-manager sw-deploy-strategy show"],
                    capture_output=True, timeout=10, check=True
                )
                return True
            except Exception:
                pass
            time.sleep(1)
        return False

    def _replace_vim_db(self):
        try:
            content = self.read_file(self.SOFTWARE_JSON_CURRENT)
            deploy = content.get("deploy")
            d = deploy[0]
            from_release = self.get_major_release_version(d["from_release"])
            to_release = self.get_major_release_version(d["to_release"])

            vim_db = "/opt/platform/nfv/vim/%s" % from_release
            vim_db_snapshot = "nfv/vim/%s" % to_release
            db_dump = tempfile.NamedTemporaryFile(dir="/tmp", prefix="dump")
            config = configparser.ConfigParser()

            self.run_command(["nfv-vim-manage",
                              "db-dump-data",
                              "-d",
                              vim_db,
                              "-f",
                              db_dump.name])
            with open(db_dump.name, "r") as fp:
                content = json.loads(fp.read())
                # Check if no strategy present, it indicates snapshot
                # restore done through USM, no need to restore VIM DB
                if not content["tables"]["sw_updates"]:
                    LOG.info("Empty sw_updates table, snapshot restored with USM")
                    return

            mount_dir = tempfile.mkdtemp(prefix=f"{self._lv_name}-", dir="/tmp")
            self.run_command(["/usr/bin/mount",
                              "-t",
                              "ext4",
                              self.get_dev_path(),
                              mount_dir])
            LOG.info("Mounted %s under %s", self._name, mount_dir)

            vim_db_snap = Path(mount_dir) / vim_db_snapshot
            # Empty contents of snapshot vim db directory
            shutil.rmtree(vim_db_snap, ignore_errors=True)
            vim_db_snap.mkdir()

            self.run_command(["nfv-vim-manage",
                              "db-load-data",
                              "-d",
                              vim_db_snap,
                              "-f",
                              db_dump.name])
            db_dump.close()

            # Update config file with new vim db
            config.read(self.VIM_CONFIG)
            config.set("database", "database_dir", str(vim_db_snap))
            with open(self.VIM_CONFIG, "w") as fp:
                config.write(fp)

            # Restart vim to take new db file
            self.run_command(["sm-restart-safe", "service", "vim"])
            LOG.info("VIM restarted successfully")

            if not self._wait_for_vim_ready(timeout=20):
                LOG.error("VIM failed to come up within timeout")

        except Exception as e:
            LOG.error("Failure updating VIM snapshot db: %s", str(e))
            raise

    def get_ceph_config(self):
        with open("/etc/platform/platform.conf", "r") as f:
            content = f.read()
        ceph_network = None
        for line in content.splitlines():
            if line.startswith("ceph_network="):
                ceph_network = line.split("=", 1)[1].strip()
                break
        return ceph_network

    # TODO(heitormatsui): remove this function and its call after stx10 -> stx-11 upgrade
    def _restore_ceph_mon_configuration(self):
        content = self.read_file(self.SOFTWARE_JSON_CURRENT)
        deploy = content.get("deploy")[0]
        from_release = self.get_major_release_version(deploy["from_release"])
        state = deploy["state"]

        if from_release == "24.09":
            if state == "activate-rollback":
                LOG.info("Not in auto-recovery mode, skipping ceph-mon reconfiguration")
                return

            ceph_net = self.get_ceph_config()
            if not ceph_net:
                LOG.info("Ceph mon configuration: skipping, bare metal ceph not configured")
                return

            ceph_configured_flags = ["/etc/platform/.node_ceph_configured"]
            if all(not Path(flag).exists() for flag in ceph_configured_flags):
                LOG.info("No ceph backend configured, skipping ceph-mon reconfiguration")
                return

            try:
                # get from-release controller-0 IP
                mon_name = "controller-0"
                mon_ip = None

                mon_host_name = mon_name
                if ceph_net == 'cluster_host':
                    mon_host_name = "controller-0-cluster-host"

                with self.mount() as mount_dir:
                    with open(Path(mount_dir) / "config" / from_release / "hosts", "r") as hosts_file:
                        for line in hosts_file.readlines():
                            content = line.strip().split()
                            if content[1] == mon_host_name:
                                mon_ip = f"[{content[0]}]" if isinstance(ip_address(content[0]), IPv6Address) else content[0]
                                break

                # get fsid
                cp = configparser.ConfigParser()
                cp.read("/etc/ceph/ceph.conf")
                fsid = cp["global"]["fsid"]

                # restore ceph-mon parameters to the from-release values
                if any(not x for x in [mon_ip, fsid]):
                    LOG.error("Failure getting ceph-mon attributes")
                    raise ValueError("Invalid values: mon_ip=%s fsid=%s" % (mon_ip, fsid))
                LOG.info("Retrieved ceph-mon parameters: mon_ip=%s fsid=%s ceph_network=%s" % (mon_ip, fsid, ceph_net))

                cmds = [
                    ["rm", "-f", "/etc/pmon.d/ceph.conf"],
                    ["ceph-mon", "--name", f"mon.{mon_name}", "--extract-monmap", f"/tmp/mon-{mon_name}.map"],
                    ["monmaptool", "--rm", f"{mon_name}", f"/tmp/mon-{mon_name}.map"],
                    ["monmaptool", "--addv", f"{mon_name}",
                     f"[v2:{mon_ip}:3300/0,v1:{mon_ip}:6789/0]", f"/tmp/mon-{mon_name}.map"],
                    ["monmaptool", "--fsid", f"{fsid}", f"/tmp/mon-{mon_name}.map"],
                    ["ceph-mon", "--name", f"mon.{mon_name}", "--inject-monmap", f"/tmp/mon-{mon_name}.map"],
                    ["ln", "-s", "/etc/ceph/ceph.conf.pmon", "/etc/pmon.d/ceph.conf"],
                ]
                for cmd in cmds:
                    LOG.info("Restoring ceph mon config: exec: %s", cmd)
                    self.run_command(cmd)
                LOG.info("Restored ceph-mon parameters to %s values" % from_release)
            except Exception as e:
                LOG.error("Failure while reverting ceph-mon config: %s", str(e))
                raise

    def restore(self):
        """
        Override default restore behavior for platform-lv; which has
        the following specific scenarios to treat on restore:
        - VIM DB in snapshot needs to mounted and replaced with active
        DB otherwise during unlock it will be restored with the pre-deploy
        start content incorrectly
        - Restore ceph-mon configuration on stx-10 to stx-11 upgrade, due
        to the subnet range reduction that is applied on the upgrade path,
        but only on the auto-recovery scenario (on the standard rollback
        an agent hook will do the job)
        """
        self._replace_vim_db()
        self._restore_ceph_mon_configuration()
        super().restore()


class LVMSnapshotManager:
    """
    Manage all operations to be taken over LVM snapshots
    """
    # LVM snapshot default constants
    VOLUME_GROUP = "cgts-vg"
    # NOTE: snapshots store the changes between the state when they were taken and
    # the current state of the LV, so how much and how fast it fills up relates to
    # how much and how fast data is changing in each LV during the upgrade
    LOGICAL_VOLUMES = {  # lv_name: snapshot_size
        "docker-lv": "12G",
        "etcd-lv": "2G",
        "kubelet-lv": "2G",
        "platform-lv": "2G",
        "pgsql-lv": "2G",
        "rabbit-lv": "1G",
        "var-lv": "3G",
    }
    # TODO(heitormatsui) revisit this value soon to check
    #  if it matches the feature requirements and expectations
    SNAPSHOT_EXPIRE_TIME = 86400  # 24 hours

    def __init__(self, vg_name=None, lvs=None):
        self._vg_name = vg_name if vg_name is not None else self.VOLUME_GROUP
        self._lvs = lvs if lvs is not None else self.LOGICAL_VOLUMES

    @property
    def vg_name(self):
        return self._vg_name

    @property
    def lvs(self):
        return self._lvs

    def create_instance(self, lv_name):
        """
        Factory method to create snapshot instance; LVs that need to
        override the default snapshot behavior must inherit the base
        snapshot class and include a condition in this method
        """

        # TODO(sshathee) Define a constant variable for var-lv which
        # is used in multiple places. Currently lvm snapshot is executed
        # from feed repo where constants file is not copied.

        # specific snapshot instances
        if lv_name == "var-lv":
            return VarSnapshot(self.vg_name, lv_name)
        elif lv_name == "platform-lv":
            return PlatformSnapshot(self.vg_name, lv_name)
        # otherwise create a generic instance
        return LVMSnapshot(self.vg_name, lv_name)

    def _create_snapshots(self):
        """Create snapshots for the specified logical volumes"""
        LOG.info("Creating snapshots...")
        for lv_name, lv_size in self.lvs.items():
            snapshot = LVMSnapshot(self.vg_name, lv_name, lv_size)
            if snapshot.exists():
                LOG.info("Snapshot %s already exists, deleting snapshot...", snapshot.name)
                snapshot.delete()
            LOG.info("Creating snapshot for %s in volume group %s" % (lv_name, self.vg_name))
            snapshot.create()
        LOG.info("Snapshots created successfully")

    def create_snapshots(self):
        """
        Create snapshots and return success only if all expected snapshots are created,
        if any snapshot creation returns error, all snapshots are cleared
        """
        try:
            self._create_snapshots()
        except Exception:
            LOG.error("Error creating snapshots, existing snapshots will be deleted")
            self.delete_snapshots()
            return False
        return True

    def _restore_snapshots(self):
        """Activate LVM snapshots and prepare the system for rollback"""
        LOG.info("Restoring all active snapshots...")
        for lv_name in self.lvs.keys():
            snapshot = self.create_instance(lv_name)
            if not snapshot.exists():
                LOG.info("Snapshot %s for %s does not exist. Skipping", snapshot.name, lv_name)
                continue
            LOG.info("Restoring snapshot for %s: %s", lv_name, snapshot.name)
            snapshot.restore()
        LOG.info("Snapshots restored, reboot is needed to apply the changes")

    def restore_snapshots(self):
        """
        Restore snapshots, but only after doing sanity checks:
        - If all expected snapshots exists
        - If snapshots are valid (if a snapshot reaches it's maximum size it is invalidated)
        """
        # check for snapshot existence
        # TODO(heitormatsui) optimize by calling one single command and check all
        #  existing snapshots from its output instead of calling it for each LV
        snapshots = self.list_snapshots()
        snapshots_lv_name = [snapshot.lv_name for snapshot in snapshots]
        all_snapshots_found = all(lv_name in snapshots_lv_name
                                  for lv_name in self._lvs)
        if all_snapshots_found:
            LOG.info("All expected snapshots found")
        else:
            LOG.error("Cannot proceed with snapshot restore, missing snapshots for %s",
                      set(self._lvs) - set(snapshots_lv_name))
            return False

        # check for invalid or expired snapshots
        invalid_snapshots = []
        for snapshot in snapshots:
            _, valid_state = snapshot.get_attributes()
            if valid_state is False:
                LOG.error("Snapshot %s is invalid", snapshot.name)
                invalid_snapshots.append(snapshot.name)
            else:
                LOG.info("Snapshot %s can be used", snapshot.name)

        if invalid_snapshots:
            LOG.error("Cannot proceed with snapshot restore, "
                      "invalid snapshots: %s", invalid_snapshots)
            return False

        # restore snapshots
        LOG.info("All snapshots validated")
        try:
            self._restore_snapshots()
        except Exception:
            return False
        return True

    def delete_snapshots(self):
        """Delete any active snapshots"""
        LOG.info("Deleting all active snapshots...")
        for lv_name in self.lvs.keys():
            snapshot = LVMSnapshot(self.vg_name, lv_name)
            if snapshot.exists():
                LOG.info("Deleting snapshot for %s: %s" % (lv_name, snapshot.name))
                snapshot.delete()
            else:
                LOG.info("Snapshot %s does not exist or was already deleted", snapshot.name)
        LOG.info("Snapshots deleted successfully")

    def list_snapshots(self):
        """Check if any snapshots exist for the specified logical volumes."""
        LOG.info("Checking for existing LVM snapshots...")
        snapshots = []
        for lv_name in self.lvs.keys():
            snapshot = LVMSnapshot(self.vg_name, lv_name)
            if snapshot.exists():
                LOG.info("Snapshot exists for %s: %s", lv_name, snapshot.name)
                snapshots.append(snapshot)
            else:
                LOG.info("No snapshot found for %s", lv_name)
        return snapshots


def main():
    """Main function to be executed when called as an executable"""
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--create",
                        action="store_true",
                        help="Create LVM snapshots")
    parser.add_argument("-r", "--restore",
                        action="store_true",
                        help="Restore LVM snapshots")
    parser.add_argument("-d", "--delete",
                        action="store_true",
                        help="Delete LVM snapshots")
    parser.add_argument("-l", "--list",
                        action="store_true",
                        help="List existing snapshots")

    args = parser.parse_args()
    try:
        manager = LVMSnapshotManager()
        success = True
        if args.create:
            success = manager.create_snapshots()
        elif args.restore:
            success = manager.restore_snapshots()
        elif args.delete:
            manager.delete_snapshots()
        elif args.list:
            snapshots = [snapshot.to_json() for snapshot in manager.list_snapshots()]
            success = bool(snapshots)  # True is snapshots exists, False otherwise
            print(json.dumps(snapshots, indent=4))
        else:
            parser.print_usage()
    except Exception as e:
        LOG.exception("Error: %s", str(e))
        success = False
    return 0 if success else 1


if __name__ == "__main__":
    import upgrade_utils  # pylint: disable=E0401
    upgrade_utils.configure_logging('/var/log/software.log', log_level=logging.INFO)
    sys.exit(main())
