#!/usr/bin/env python
# Copyright (c) 2025 Wind River Systems
#
# SPDX-License-Identifier: Apache-2.0
#
# Set Keystone "ignore_lockout_failure_attempts"
# for user "sysinv" during upgrade-activate.

import logging
import subprocess
import sys

from software.utilities.utils import configure_logging

LOG = logging.getLogger("main_logger")

USER = "sysinv"
FLAG = "ignore_lockout_failure_attempts"
FLAG_PARAM = "--ignore-lockout-failure-attempts"
COMMAND_TIMEOUT = 20


def set_flag():
    LOG.info(f"Setting up Keystone flag {FLAG}")

    subprocess.run(
        ["openstack", "user", "set", USER, FLAG_PARAM],
        capture_output=True,
        text=True,
        check=True,
        timeout=COMMAND_TIMEOUT
    )

    LOG.info(f"User option {FLAG} is set.")


def main():
    argv = sys.argv

    if len(argv) > 5:
        print(f"Invalid option {argv[5]}.")
        return 1

    from_release = argv[1] if len(argv) > 1 else None
    to_release = argv[2] if len(argv) > 2 else None
    action = argv[3] if len(argv) > 3 else None
    # Not used by this script.
    # postgres_port = argv[4] if len(argv) > 4 else None

    configure_logging()

    if action != "activate":
        LOG.info(f"Nothing to do for action '{action}'.")
        return 0

    LOG.info("%s invoked with from_release %s to_release %s and action %s",
             sys.argv[0], from_release, to_release, action)

    try:
        set_flag()
    except subprocess.CalledProcessError as e:
        LOG.error("Fail to set Keystone flag %s: %s",
                  FLAG, e.stderr.strip())
        return 1
    except Exception as e:
        LOG.error("Unexpected error: %s", e)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
