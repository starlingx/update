#!/usr/bin/env python
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script checks if there is a software-controller restart flag,
# if it exists:
# - Create a flag detected by software-controller on startup
#   and set its state to activate-done
# - Restarts the software-controller-daemon
#

import logging
import os
import re
import shutil
import subprocess
import sys

from software.states import DEPLOY_STATES
from software.utilities.update_deploy_state import update_deploy_state
from software.utilities.utils import configure_logging

LOG = logging.getLogger('main_logger')

RESTART_SERVICES_FLAG = "/run/software/.activate.restart-services.flag"
ACTIVATE_DONE_FLAG = "/run/software/.activate-done.flag"


def apply_fix_to_set_activate_done_state():
    """
    This is a live patch-back of a function to report the activate-done state after
    the software-controller service is restarted. Only applies when it is removing
    the patch 24.09.400, when applying, it will stop and log 'Already patched".
    """
    LOG.info("Applying activate done fix in software_controller.py")

    FILE = "/ostree/1/usr/lib/python3/dist-packages/software/software_controller.py"
    LINE_REGEX = r'^\s*self\.register_deploy_state_change_listeners\(\)\s*$'
    TO_ADD_LINE = "_detect_flag_and_set_to_activate_done"

    try:
        with open(FILE, "r", encoding="utf-8") as f:
            original_content = f.read()
    except FileNotFoundError:
        LOG.error(f"Error: File not found: {FILE}")
        return

    # Idempotency check: if function reference already present, assume patched
    if TO_ADD_LINE in original_content:
        LOG.info("Already patched")
        return

    # Ensure target line exists
    line_re = re.compile(LINE_REGEX)
    lines = original_content.splitlines()
    match_index = None
    for i, line in enumerate(lines):
        if line_re.match(line):
            match_index = i
            break

    if match_index is None:
        LOG.error("Error: Could not find line to replace")
        return

    # Build replacement block (mirrors the sed-replaced text and indentation)
    replacement_block = (
        "        self.register_deploy_state_change_listeners()\n"
        "\n"
        "        self._detect_flag_and_set_to_activate_done()\n"
        "\n"
        "    def _detect_flag_and_set_to_activate_done(self):\n"
        "        ACTIVATE_DONE_FLAG = \"/run/software/.activate-done.flag\"\n"
        "\n"
        "        if os.path.isfile(ACTIVATE_DONE_FLAG):\n"
        "            os.remove(ACTIVATE_DONE_FLAG)\n"
        "            deploy_state = DeployState.get_instance()\n"
        "            deploy_state.activate_done()"
    )

    # Prepare new content, replacing only the first match
    new_lines = lines[:match_index] + [replacement_block] + lines[match_index + 1:]
    new_content = "\n".join(new_lines)

    # Backup before writing
    backup_path = f"{FILE}.bak"
    try:
        shutil.copy2(FILE, backup_path)
    except Exception as e:
        LOG.error(f"Error: Unable to create backup at {backup_path}: {e}")
        return

    # Write patched content
    try:
        with open(FILE, "w", encoding="utf-8", newline="\n") as f:
            f.write(new_content)
    except Exception as e:
        LOG.error(f"Error: Failed to write patched file: {e}")
        # Attempt restore if write failed after backup
        try:
            shutil.move(backup_path, FILE)
        except Exception as e2:
            LOG.error(f"Error: Failed to restore backup: {e2}")
        return

    # Post-check: confirm the function reference now exists
    try:
        with open(FILE, "r", encoding="utf-8") as f:
            after = f.read()
    except Exception as e:
        LOG.error(f"Error: Failed to read back file for verification: {e}")
        # Attempt restore
        try:
            shutil.move(backup_path, FILE)
        except Exception as e2:
            LOG.error(f"Error: Failed to restore backup: {e2}")
        return

    if TO_ADD_LINE not in after:
        LOG.error("Error: Patch did not apply correctly. Restoring backup.")
        try:
            shutil.move(backup_path, FILE)
        except Exception as e2:
            LOG.error(f"Error: Failed to restore backup: {e2}")
        return

    # Remove backup on success
    os.remove(backup_path)


def restart_vim_services():
    services = ["vim", "vim-api", "vim-webserver"]
    for service in services:
        command = ["sudo", "sm-restart-safe", "service", service]
        try:
            result = subprocess.run(command,
                                    check=True,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    text=True)
            print(f"Successfully restarted {service}:\n{result.stdout}")
        except subprocess.CalledProcessError as e:
            print(f"Error restarting {service}:\n{e.stderr}")


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
            # Optional port
            # port = sys.argv[arg]
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

    try:
        if os.path.isfile(RESTART_SERVICES_FLAG):
            restart_vim_services()
            apply_fix_to_set_activate_done_state()

            open(ACTIVATE_DONE_FLAG, 'a').close()
            os.remove(RESTART_SERVICES_FLAG)

            # Restart software-controller service
            subprocess.run(["pmon-restart", "software-controller-daemon"], check=True)
    except Exception as e:
        LOG.error(f"Activate script to restart services failed: {e}")
        try:
            os.remove(ACTIVATE_DONE_FLAG)
            open(RESTART_SERVICES_FLAG, 'a').close()
            update_deploy_state("deploy-activate", deploy_state=DEPLOY_STATES.ACTIVATE_FAILED.value)
        except Exception as e:
            LOG.error(f"Activate script to restart services failed twice: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
