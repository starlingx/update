#!/usr/bin/env python
# Copyright (c) 2022-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Sometimes docker will be in a bad state.
# Check for this and use some recovery logic to get it back to normal.
#

import logging
import os
import subprocess
import sys
import time

from software.utilities.utils import configure_logging


LOG = logging.getLogger('main_logger')

MAX_ATTEMPTS = 5
TIME_STEP = 6


def is_docker_healthy():
    """Docker is healthy if service is active and /var/lib/docker/tmp exists."""
    try:
        result = subprocess.run(["systemctl", "is-active", "docker"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.stdout.strip() != "active":
            return False
    except Exception:
        return False
    return os.path.isdir("/var/lib/docker/tmp")


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

    if action != "activate":
        return 0

    LOG.info("Starting docker health check script from release %s to %s with action %s",
             from_release, to_release, action)

    attempts = 0
    while not is_docker_healthy():
        attempts += 1
        if attempts > MAX_ATTEMPTS:
            LOG.info("Could not fix docker service.")
            return 0
        LOG.info("Docker in bad state. Restarting docker service. Attempt: %s/%s",
                 attempts, MAX_ATTEMPTS)
        subprocess.run(["systemctl", "restart", "docker"],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(TIME_STEP)

    LOG.info("Docker service is active and healthy")
    return 0


if __name__ == "__main__":
    sys.exit(main())
