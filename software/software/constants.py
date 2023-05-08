"""
Copyright (c) 2023 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import os
try:
    # The tsconfig module is only available at runtime
    import tsconfig.tsconfig as tsc

    INITIAL_CONFIG_COMPLETE_FLAG = os.path.join(
        tsc.PLATFORM_CONF_PATH, ".initial_config_complete")
except Exception:
    pass

CLI_OPT_ALL = '--all'
CLI_OPT_DRY_RUN = '--dry-run'
CLI_OPT_RECURSIVE = '--recursive'
CLI_OPT_RELEASE = '--release'

ADDRESS_VERSION_IPV4 = 4
ADDRESS_VERSION_IPV6 = 6
CONTROLLER_FLOATING_HOSTNAME = "controller"

AVAILABLE = 'Available'
APPLIED = 'Applied'
PARTIAL_APPLY = 'Partial-Apply'
PARTIAL_REMOVE = 'Partial-Remove'
COMMITTED = 'Committed'
UNKNOWN = 'n/a'

STATUS_OBSOLETE = 'OBS'
STATUS_RELEASED = 'REL'
STATUS_DEVELOPEMENT = 'DEV'

PATCH_AGENT_STATE_IDLE = "idle"
PATCH_AGENT_STATE_INSTALLING = "installing"
PATCH_AGENT_STATE_INSTALL_FAILED = "install-failed"
PATCH_AGENT_STATE_INSTALL_REJECTED = "install-rejected"

SOFTWARE_STORAGE_DIR = "/opt/software"

OSTREE_REF = "starlingx"
OSTREE_REMOTE = "debian"
FEED_OSTREE_BASE_DIR = "/var/www/pages/feed"
SYSROOT_OSTREE = "/sysroot/ostree/repo"
OSTREE_BASE_DEPLOYMENT_DIR = "/ostree/deploy/debian/deploy/"
PATCH_SCRIPTS_STAGING_DIR = "/var/www/pages/updates/software-scripts"

LOOPBACK_INTERFACE_NAME = "lo"

SEMANTIC_PREAPPLY = 'pre-apply'
SEMANTIC_PREREMOVE = 'pre-remove'
SEMANTIC_ACTIONS = [SEMANTIC_PREAPPLY, SEMANTIC_PREREMOVE]

CHECKOUT_FOLDER = "checked_out_commit"

DEPLOYMENT_STATE_INACTIVE = "Inactive"
DEPLOYMENT_STATE_ACTIVE = "Active"
DEPLOYMENT_STATE_PRESTAGING = "Prestaging"
DEPLOYMENT_STATE_PRESTAGED = "Prestaged"
