#!/usr/bin/env python
# Copyright (c) 2025-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Set Keystone service user options (ignore_lockout_failure_attempts and
# ignore_password_expiry) for all platform service users during
# upgrade-activate.
#
# This ensures service users are exempt from password expiry and lockout
# policies after upgrade, regardless of when they were created relative
# to the password_expires_days policy being active.
#
# NOTE: When adding a new platform service user, add it to SERVICE_USERS
# below AND to the appropriate list in openstack_config_endpoints.py.
#
# TODO(amantri): In 27.09, the existing users in SERVICE_USERS can be removed
# (both N-1=27.03 and N-2=26.09 will already have the options set).
# However, if a new service user is introduced in 27.03 or 27.09,
# add it here so it gets the options during upgrade from older releases
# that don't have it. Only remove this script entirely when ALL supported
# upgrade source releases already set these options for all service users.

import logging
import subprocess
import sys

from software.utilities.plugin_runner import CPlugin
from software.utilities.utils import configure_logging

LOG = logging.getLogger("main_logger")

# All platform service users that should have options set.
# Excludes 'admin' which is a human-facing account.
# Keep in sync with BASE_USERS + ADDITIONAL_*_USERS in
# sysinv/common/openstack_config_endpoints.py
SERVICE_USERS = [
    "sysinv",
    "fm",
    "usm",
    "vim",
    "smapi",
    "barbican",
    "mtce",
    "dcorch",
    "dcmanager",
    "dcdbsync",
    "dcagent",
]

OPTIONS_TO_SET = [
    "--ignore-lockout-failure-attempts",
    "--ignore-password-expiry",
]

COMMAND_TIMEOUT = 20


def set_service_user_options():
    """Set ignore_password_expiry and ignore_lockout_failure_attempts
    on all platform service users.
    """

    for user in SERVICE_USERS:
        for option in OPTIONS_TO_SET:
            try:
                result = subprocess.run(
                    ["openstack", "user", "set", user, option],
                    capture_output=True, text=True, timeout=COMMAND_TIMEOUT,
                )
                if result.returncode != 0:
                    # User might not exist on this system type
                    # (e.g., dcagent only on subclouds, dcorch only on SC)
                    if "No user with" in result.stderr or \
                       "not found" in result.stderr.lower():
                        LOG.info(f"User {user} not found on this system, skipping.")
                        break
                    else:
                        LOG.warning(f"Failed to set {option} for {user}: "
                                    f"{result.stderr.strip()}")
                else:
                    LOG.info(f"Set {option} for user {user}")
            except subprocess.TimeoutExpired:
                LOG.warning(f"Timeout setting {option} for {user}, skipping.")
            except Exception as e:
                LOG.warning(f"Error setting {option} for {user}: {e}")


class SetServiceUserOptions(CPlugin):
    def __init__(self):
        super().__init__(
            matching_action='activate',
            required_state=None,
            plugin_name='set-service-user-options',
            completed_state='set-service-user-options-completed'
        )

    def _run(self, from_release, to_release, action, port):
        configure_logging()
        LOG.info("%s invoked from_release = %s to_release = %s action = %s"
                 % (self.name, from_release, to_release, action))
        set_service_user_options()
        LOG.info("Service user options set successfully.")


if __name__ == "__main__":
    from_release = None
    to_release = None
    action = None
    port = None
    arg = 1

    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]
        elif arg == 3:
            action = sys.argv[arg]
        elif arg == 4:
            port = sys.argv[arg]
        else:
            print("Invalid option %s." % sys.argv[arg])
            sys.exit(1)
        arg += 1

    plugin = SetServiceUserOptions()
    result = plugin.run(from_release, to_release, action, port)
    if result and 'failed' in result:
        sys.exit(1)
