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
# Uses the Keystone Python API directly (single authenticated session)
# instead of shelling out to the openstack CLI for each user, reducing
# total execution time from ~5 minutes to under 10 seconds.
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
import os
import sys

from keystoneauth1.identity import v3 as v3_auth
from keystoneauth1 import session as ks_session
from keystoneclient.v3 import client as ks_client
from software.utilities.plugin_runner import CPlugin
from software.utilities.utils import configure_logging

LOG = logging.getLogger("main_logger")

# Service users present on ALL system types (standalone, DX, standard, DC)
BASE_SERVICE_USERS = [
    "sysinv",
    "fm",
    "usm",
    "vim",
    "smapi",
    "barbican",
    "mtce",
    "patching",
]

# Additional service users only present on Distributed Cloud systems
DC_SERVICE_USERS = [
    "dcorch",
    "dcmanager",
    "dcdbsync",
    "dcagent",
]

# Keystone user option IDs
# From keystone/models/user_option.py:
#   1001 = ignore_password_expiry
#   1002 = ignore_lockout_failure_attempts
OPTIONS_TO_SET = {
    "ignore_password_expiry": True,
    "ignore_lockout_failure_attempts": True,
}


def is_distributed_cloud():
    """Check if this system is a Distributed Cloud deployment."""
    try:
        with open("/etc/platform/platform.conf", "r") as f:
            for line in f:
                if line.strip().startswith("distributed_cloud_role"):
                    return True
    except FileNotFoundError:
        pass
    return False


def get_keystone_client():
    """Create a Keystone client using environment variables provided
    by the upgrade framework.
    """
    auth = v3_auth.Password(
        auth_url=os.environ.get("OS_AUTH_URL"),
        username=os.environ.get("OS_USERNAME"),
        password=os.environ.get("OS_PASSWORD"),
        project_name=os.environ.get("OS_PROJECT_NAME"),
        user_domain_name=os.environ.get("OS_USER_DOMAIN_NAME"),
        project_domain_name=os.environ.get("OS_PROJECT_DOMAIN_NAME"),
    )
    session = ks_session.Session(auth=auth)
    return ks_client.Client(
        session=session,
        interface="internal",
        region_name=os.environ.get("OS_REGION_NAME"),
    )


def set_service_user_options():
    """Set ignore_password_expiry and ignore_lockout_failure_attempts
    on all platform service users using the Keystone API directly.
    """
    keystone = get_keystone_client()

    # Determine which users to process
    users_to_process = list(BASE_SERVICE_USERS)
    if is_distributed_cloud():
        users_to_process.extend(DC_SERVICE_USERS)
        LOG.info("Distributed Cloud system detected, including DC users.")
    else:
        LOG.info("Non-DC system, skipping DC-only users "
                 "(dcorch, dcmanager, dcdbsync, dcagent).")

    # Get all users in one API call
    all_users = keystone.users.list()
    user_map = {u.name: u for u in all_users}

    updated_count = 0
    skipped_count = 0

    for username in users_to_process:
        user = user_map.get(username)
        if not user:
            LOG.info("User %s not found on this system, skipping.", username)
            skipped_count += 1
            continue

        # Check current options
        current_options = getattr(user, "options", {}) or {}
        needs_update = False
        for option, value in OPTIONS_TO_SET.items():
            if current_options.get(option) != value:
                needs_update = True
                break

        if not needs_update:
            LOG.info("User %s already has correct options, skipping.", username)
            skipped_count += 1
            continue

        # Set options
        try:
            keystone.users.update(user.id, options=OPTIONS_TO_SET)
            LOG.info("Set service user options for %s: %s", username, OPTIONS_TO_SET)
            updated_count += 1
        except Exception as e:
            LOG.warning("Failed to set options for %s: %s", username, e)

    LOG.info("Service user options complete: %d updated, %d skipped.",
             updated_count, skipped_count)


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
