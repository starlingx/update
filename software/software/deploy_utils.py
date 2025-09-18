"""
Copyright (c) 2025 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import fcntl
import glob
import os
import shutil
import time

from software.software_functions import LOG
from software import constants

_lock_file_handle = None


def get_etc_backup_path(commit_id=None):
    ETC_BACKUP_PATH = '/sysroot/upgrade/deploy-%s.bak'
    if commit_id is None:
        commit_id = '*'
    return ETC_BACKUP_PATH % commit_id


def backup_etc(commit_id):
    # backup current runtime etc directory to
    # /sysroot/upgrade/deploy-<current-commit-id>/etc
    # a full copy is created
    # the backup is deleted when the release deploy is deleted

    dst_path = get_etc_backup_path(commit_id)

    src_path = "/etc"
    delete_etc_backup()

    if not os.path.exists(dst_path):
        os.makedirs(dst_path)

    os.makedirs(dst_path, exist_ok=True)
    try:
        shutil.copytree(src_path, os.path.join(dst_path, "etc"), symlinks=True)
        LOG.info(f"/etc contents for {commit_id} is backup to {dst_path} successfully")
    except Exception as e:
        LOG.error(f"Copying /etc to {dst_path} failed. {e}")
        raise


def delete_etc_backup():
    # when deploy completes, delete the backup of the etc directory
    # /sysroot/upgrade/deploy-* (any previous backup)

    def log_delete_error(__, path, _):
        LOG.warning(f"Deleting backup {path} failed")

    backup_path = get_etc_backup_path()
    for backup_dir in glob.glob(backup_path):
        LOG.info(f"Deleting backup {backup_dir}")
        try:
            shutil.rmtree(backup_dir, onerror=log_delete_error)
        except Exception:
            LOG.error(f"Delete backup {backup_dir} failed.")


def acquire_etc_lock(lockfile=constants.LOCKFILE, timeout=constants.LOCK_TIMEOUT):
    """
    Acquire an exclusive lock on the given lockfile, retrying until successful.
    """
    global _lock_file_handle
    _lock_file_handle = open(lockfile, "w")

    start_time = time.time()
    while True:
        try:
            fcntl.flock(_lock_file_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            LOG.info("/etc lock acquired on %s" % lockfile)
            break
        except BlockingIOError:
            elapsed = time.time() - start_time
            if elapsed >= timeout:
                LOG.warning("Failed to get /etc lock after %s seconds. Retrying..." % timeout)
                start_time = time.time()
            time.sleep(1)


def release_etc_lock():
    """
    Release the previously acquired lock.
    """
    global _lock_file_handle
    if _lock_file_handle:
        fcntl.flock(_lock_file_handle, fcntl.LOCK_UN)
        _lock_file_handle.close()
        _lock_file_handle = None
        LOG.info("/etc lock released")
