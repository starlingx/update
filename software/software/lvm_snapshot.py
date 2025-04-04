"""
Copyright (c) 2025 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

from pathlib import Path
import subprocess

from software.software_functions import LOG


class LVMSnapshotManager:
    """
    Manage all operations to be taken over LVM snapshots
    """
    # LVM snapshot default constants
    VOLUME_GROUP = "cgts-vg"
    LOGICAL_VOLUMES = {  # lv_name: snapshot_size
        "docker-lv": "12G",
        "etcd-lv": "2G",
        "kubelet-lv": "2G",
        "platform-lv": "2G",
        "pgsql-lv": "2G",
        "rabbit-lv": "1G",
        "var-lv": "3G",
    }

    def __init__(self, vg_name=None, lvs=None):
        self._vg_name = vg_name if vg_name is not None else self.VOLUME_GROUP
        self._lvs = lvs if lvs is not None else self.LOGICAL_VOLUMES

    @property
    def vg_name(self):
        return self._vg_name

    @property
    def lvs(self):
        return self._lvs

    @staticmethod
    def run_command(command, shell=False, check=True):
        """Helper function to run shell commands and capture output."""
        try:
            result = subprocess.run(command, shell=shell, check=check,
                                    text=True, capture_output=True)
            return result
        except subprocess.CalledProcessError as e:
            LOG.error("Error executing command: %s\n%s" % (command, e.stderr))
            raise

    def snapshot_exists(self, snapshot_name):
        """Check if a snapshot volume exists."""
        command = f"lvs --noheadings -o lv_name {self.vg_name} | grep -w {snapshot_name}"
        result = self.run_command(command, shell=True, check=False)
        return result.returncode == 0

    def create_snapshots(self):
        """Create snapshots for the specified logical volumes."""
        LOG.info("Creating snapshots...")
        for lv_name, lv_size in self.lvs.items():
            snapshot_name = f"{lv_name}_snapshot"
            if self.snapshot_exists(snapshot_name):
                LOG.info("Snapshot already exists for %s. Skipping" % lv_name)
                continue
            LOG.info("Creating snapshot for %s in volume group %s" % (lv_name, self.vg_name))
            command = ["lvcreate", "-y", "-L", lv_size, "-s", "-n",
                       snapshot_name, Path("/dev") / self.vg_name / lv_name]
            self.run_command(command)
        LOG.info("Snapshots created successfully")

    def restore_snapshots(self):
        """Activate LVM snapshots and prepare the system for rollback."""
        LOG.info("Restoring all active snapshots...")
        for lv_name in self.lvs.keys():
            snapshot_name = f"{lv_name}_snapshot"
            if not self.snapshot_exists(snapshot_name):
                LOG.info("Snapshot %s for %s does not exist. Skipping" % (snapshot_name, lv_name))
                continue
            LOG.info("Restoring snapshot for %s: %s" % (lv_name, snapshot_name))
            command = ["lvconvert", "-y", "--merge", Path("/dev") / self.vg_name / snapshot_name]
            self.run_command(command)
        LOG.info("Snapshots restored, please reboot to apply changes")

    def delete_snapshots(self):
        """Deactivate and delete any active snapshots and remove the rollback marker."""
        LOG.info("Deleting all active snapshots...")
        for lv_name in self.lvs.keys():
            snapshot_name = f"{lv_name}_snapshot"
            if self.snapshot_exists(snapshot_name):
                LOG.info("Deleting snapshot for %s: %s" % (lv_name, snapshot_name))
                command = ["lvremove", "-f", Path("/dev") / self.vg_name / snapshot_name]
                self.run_command(command)
            else:
                LOG.info("Snapshot %s does not exist or is already deleted" % snapshot_name)
        LOG.info("Snapshots deleted successfully")

    def check_snapshots(self):
        """Check if any snapshots exist for the specified logical volumes."""
        LOG.info("Checking for existing LVM snapshots...")
        snapshots_found = []
        for lv_name in self.lvs.keys():
            snapshot_name = f"{lv_name}_snapshot"
            if self.snapshot_exists(snapshot_name):
                LOG.info("Snapshot exists for %s: %s" % (lv_name, snapshot_name))
                snapshots_found.append(snapshot_name)
            else:
                LOG.info("No snapshot found for %s: %s" % (lv_name, snapshot_name))
        return snapshots_found
