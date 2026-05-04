#!/usr/bin/env python
# Copyright (c) 2022-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script is used to resize the platform (and backup, consequently) filesystems
# on System Controller DC, so that to allow an increased parallelism on subclouds
# deployment (100+ deployments in parallel). This script will:
# - Check if deployment is System Controller DC from distributed_cloud_role variable
#   sourced from /etc/platform/platform.conf
# - Check if platform filesystem needs to be resized (i.e. if less than 20GB in size)
#   and skip the execution if not
# - Check if there is enough space on cgts-vg to resize on both controllers
# - Resize backup filesystem on each controller and check if resized successfully
# - Resize platform controllerfs and check if resized successfully
# - NOTE: this script has to be idempotent and reentrant, since upgrade-activate can
#   be called multiple times during the upgrade
# - NOTE: this script must not fail the upgrade if there is not enough disk space to
#   resize, and only have to warn the user about the limitation
#

import logging
import subprocess
import sys
import time

from software.utilities.utils import configure_logging


LOG = logging.getLogger('main_logger')

EXPANDED_PLATFORM_SIZE = 20
NODE_LIST = ["controller-0", "controller-1"]
RESIZE_SLEEP_TIME = 90
RESIZE_CHECK_MAX_RETRIES = 5


def get_platform_conf_value(key):
    """Read a value from /etc/platform/platform.conf."""
    try:
        with open("/etc/platform/platform.conf", "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith(key + "="):
                    return line.split("=", 1)[1].strip()
    except Exception as e:
        LOG.error("Error reading platform.conf: %s", e)
    return None


def run_command(cmd):
    """Run a command and return stdout."""
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, check=True)
    return result.stdout


def verify_fs_need_resizing():
    """Check if platform filesystem needs resizing.
    Returns (needs_resize, current_size).
    """
    output = run_command(["system", "controllerfs-list",
                         "--column", "name", "--column", "size", "--column", "state"])
    for line in output.splitlines():
        if "platform" in line:
            fields = line.split()
            # size is typically the 4th field in the table output
            for field in fields:
                try:
                    size = int(field)
                    if size >= EXPANDED_PLATFORM_SIZE:
                        return False, size
                    return True, size
                except ValueError:
                    continue
    raise RuntimeError("Could not determine platform filesystem size")


def verify_space_to_resize(platform_size, hostname):
    """Check if there is enough space on cgts-vg to resize.
    Returns (has_space, increase_size).
    """
    output = run_command(["system", "host-lvg-list", hostname])
    available_disk_size = None
    for line in output.splitlines():
        if "cgts-vg" in line:
            fields = line.split()
            # available size is typically the 12th field
            try:
                available_disk_size = float(fields[11])
            except (IndexError, ValueError):
                # Try to find a float value in the line
                for field in fields:
                    try:
                        available_disk_size = float(field)
                    except ValueError:
                        continue
            break

    if available_disk_size is None:
        raise RuntimeError("Could not determine available disk size for %s" % hostname)

    increase_disk_size = EXPANDED_PLATFORM_SIZE - platform_size
    total_increase_disk_size = 2 * increase_disk_size  # need to resize platform and backup
    LOG.info("[%s] Available cgts-vg space: %sG, need %sG to resize.",
             hostname, available_disk_size, total_increase_disk_size)

    has_space = available_disk_size >= total_increase_disk_size
    return has_space, increase_disk_size


def resize_backup_filesystem(increase_disk_size, hostname):
    """Resize the backup filesystem on a given host."""
    output = run_command(["system", "host-fs-list", hostname])
    backup_size = None
    for line in output.splitlines():
        if "backup" in line:
            fields = line.split()
            # size is typically the 6th field
            try:
                backup_size = int(fields[5])
            except (IndexError, ValueError):
                for field in fields:
                    try:
                        backup_size = int(field)
                    except ValueError:
                        continue
            break

    if backup_size is None:
        raise RuntimeError("Could not determine backup filesystem size for %s" % hostname)

    expanded_backup_size = backup_size + increase_disk_size
    LOG.info("[%s] Current backup size is %sG, new size will be %sG.",
             hostname, backup_size, expanded_backup_size)
    run_command(["system", "host-fs-modify", hostname,
                 "backup=%s" % expanded_backup_size])
    time.sleep(5)

    # Verify resize
    output = run_command(["system", "host-fs-list", hostname])
    for line in output.splitlines():
        if "backup" in line:
            fields = line.split()
            try:
                new_backup_size = int(fields[5])
                if new_backup_size == expanded_backup_size:
                    return True
            except (IndexError, ValueError):
                pass
            break
    return False


def resize_platform_controllerfs(platform_size):
    """Resize the platform controllerfs."""
    LOG.info("Current platform size is %sG, new size will be %sG.",
             platform_size, EXPANDED_PLATFORM_SIZE)
    run_command(["system", "controllerfs-modify",
                 "platform=%s" % EXPANDED_PLATFORM_SIZE])

    for retry in range(1, RESIZE_CHECK_MAX_RETRIES + 1):
        LOG.info("Retry %s of %s, checking if platform filesystem is resized...",
                 retry, RESIZE_CHECK_MAX_RETRIES)
        output = run_command(["system", "controllerfs-list",
                             "--column", "name", "--column", "size", "--column", "state"])
        for line in output.splitlines():
            if "platform" in line:
                fields = line.split()
                current_size = None
                for field in fields:
                    try:
                        current_size = int(field)
                        break
                    except ValueError:
                        continue
                LOG.info("Current platform fs size: %s", current_size)
                if current_size == EXPANDED_PLATFORM_SIZE:
                    return True
                if current_size is not None and current_size < EXPANDED_PLATFORM_SIZE:
                    LOG.info("Current platform size is less than %sG, retrying resize command...",
                             EXPANDED_PLATFORM_SIZE)
                    run_command(["system", "controllerfs-modify",
                                 "platform=%s" % EXPANDED_PLATFORM_SIZE])
                break
        time.sleep(RESIZE_SLEEP_TIME)

    # Final check
    output = run_command(["system", "controllerfs-list",
                         "--column", "name", "--column", "size", "--column", "state"])
    for line in output.splitlines():
        if "platform" in line:
            fields = line.split()
            for field in fields:
                try:
                    if int(field) == EXPANDED_PLATFORM_SIZE:
                        LOG.warning("platform fs is resized but not yet in available state.")
                        return True
                except ValueError:
                    continue
    return False


def main():
    action = None
    from_release = None
    to_release = None
    arg = 1
    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]
        elif arg == 3:
            action = sys.argv[arg]
        elif arg == 4:
            # postgres_port = sys.argv[arg]
            pass
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    configure_logging()
    LOG.info(
        "%s invoked from_release = %s to_release = %s action = %s"
        % (sys.argv[0], from_release, to_release, action)
    )

    distributed_cloud_role = get_platform_conf_value("distributed_cloud_role")

    LOG.info("Starting filesystems resize on DC System Controller for increased "
             "parallel subcloud deployment, from release %s to %s with action %s",
             from_release, to_release, action)

    if action == "activate":
        if distributed_cloud_role == "systemcontroller":
            LOG.info("Verifying if filesystems need resizing...")
            try:
                needs_resize, platform_size = verify_fs_need_resizing()
            except Exception as e:
                LOG.exception("Error verifying filesystem size: %s", e)
                return 0

            if not needs_resize:
                LOG.info("No need to resize, platform filesystem has been resized already.")
                return 0

            LOG.info("Platform filesystem needs resizing, current size is %sG, "
                     "ideal size is %sG.", platform_size, EXPANDED_PLATFORM_SIZE)

            LOG.info("Verifying if there is enough available space to resize...")
            increase_disk_size = None
            for node in NODE_LIST:
                try:
                    has_space, increase_disk_size = verify_space_to_resize(platform_size, node)
                except Exception as e:
                    LOG.exception("Error checking space on %s: %s", node, e)
                    return 0
                if not has_space:
                    LOG.info("Not enough space in cgts-vg on %s to resize, parallel "
                             "subcloud deployment will be limited. Resize operations "
                             "will be skipped.", node)
                    return 0

            LOG.info("LVG cgts-vg has enough space for resizing, continuing with resize operations...")

            LOG.info("Trying to resize host-fs backup for both controllers...")
            for node in NODE_LIST:
                try:
                    if not resize_backup_filesystem(increase_disk_size, node):
                        LOG.info("Failed while resizing backup fs on %s, resize operation aborted.", node)
                        return 0
                except Exception as e:
                    LOG.exception("Failed while resizing backup fs on %s: %s", node, e)
                    return 0
                LOG.info("Successfully resized backup filesystem on %s.", node)

            LOG.info("Trying to resize controllerfs platform filesystem...")
            try:
                if not resize_platform_controllerfs(platform_size):
                    LOG.info("Failed while resizing controllerfs platform filesystem, "
                             "resize operation aborted.")
                    return 0
            except Exception as e:
                LOG.exception("Failed while resizing controllerfs platform: %s", e)
                return 0
            LOG.info("Successfully resized controllerfs platform filesystem.")
        else:
            LOG.info("Not a DC System Controller deployment. No filesystem resize needed.")

        LOG.info("Filesystems resizing for DC System Controller finished successfully, "
                 "from release %s to %s with action %s", from_release, to_release, action)

    elif action == "activate-rollback":
        LOG.info("The %s action is not reversible for this script.", action)
    else:
        LOG.info("No actions required for from release %s to %s with action %s",
                 from_release, to_release, action)

    return 0


if __name__ == "__main__":
    sys.exit(main())
