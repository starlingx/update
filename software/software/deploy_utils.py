"""
Copyright (c) 2025 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import glob
import os
import shutil

from software.software_functions import LOG


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
