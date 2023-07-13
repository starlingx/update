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

SOFTWARE_STORAGE_DIR = "/opt/software"

AVAILABLE_DIR = "%s/metadata/available" % SOFTWARE_STORAGE_DIR
UNAVAILABLE_DIR = "%s/metadata/unavailable" % SOFTWARE_STORAGE_DIR
DEPLOYING_START_DIR = "%s/metadata/deploying_start" % SOFTWARE_STORAGE_DIR
DEPLOYING_HOST_DIR = "%s/metadata/deploying_host" % SOFTWARE_STORAGE_DIR
DEPLOYING_ACTIVATE_DIR = "%s/metadata/deploying_activate" % SOFTWARE_STORAGE_DIR
DEPLOYING_COMPLETE_DIR = "%s/metadata/deploying_complete" % SOFTWARE_STORAGE_DIR
DEPLOYED_DIR = "%s/metadata/deployed" % SOFTWARE_STORAGE_DIR
REMOVING_DIR = "%s/metadata/removing" % SOFTWARE_STORAGE_DIR
ABORTING_DIR = "%s/metadata/aborting" % SOFTWARE_STORAGE_DIR
COMMITTED_DIR = "%s/metadata/committed" % SOFTWARE_STORAGE_DIR
SEMANTICS_DIR = "%s/semantics" % SOFTWARE_STORAGE_DIR

DEPLOY_STATE_METADATA_DIR = \
    [
        AVAILABLE_DIR,
        UNAVAILABLE_DIR,
        DEPLOYING_START_DIR,
        DEPLOYING_HOST_DIR,
        DEPLOYING_ACTIVATE_DIR,
        DEPLOYING_COMPLETE_DIR,
        DEPLOYED_DIR,
        REMOVING_DIR,
        ABORTING_DIR,
        COMMITTED_DIR,
    ]

ABORTING = 'aborting'
AVAILABLE = 'available'
COMMITTED = 'committed'
DEPLOYED = 'deployed'
DEPLOYING_ACTIVATE = 'deploying-activate'
DEPLOYING_COMPLETE = 'deploying-complete'
DEPLOYING_HOST = 'deploying-host'
DEPLOYING_START = 'deploying-start'
REMOVING = 'removing'
UNAVAILABLE = 'unavailable'
UNKNOWN = 'n/a'


STATUS_DEVELOPEMENT = 'DEV'
STATUS_OBSOLETE = 'OBS'
STATUS_RELEASED = 'REL'

PATCH_AGENT_STATE_IDLE = "idle"
PATCH_AGENT_STATE_INSTALLING = "installing"
PATCH_AGENT_STATE_INSTALL_FAILED = "install-failed"
PATCH_AGENT_STATE_INSTALL_REJECTED = "install-rejected"


FEED_OSTREE_BASE_DIR = "/var/www/pages/feed"
OSTREE_BASE_DEPLOYMENT_DIR = "/ostree/deploy/debian/deploy/"
OSTREE_REF = "starlingx"
OSTREE_REMOTE = "debian"
PATCH_SCRIPTS_STAGING_DIR = "/var/www/pages/updates/software-scripts"
SYSROOT_OSTREE = "/sysroot/ostree/repo"

LOOPBACK_INTERFACE_NAME = "lo"

SEMANTIC_PREAPPLY = 'pre-apply'
SEMANTIC_PREREMOVE = 'pre-remove'
SEMANTIC_ACTIONS = [SEMANTIC_PREAPPLY, SEMANTIC_PREREMOVE]

CHECKOUT_FOLDER = "checked_out_commit"

DEPLOYMENT_STATE_ACTIVE = "Active"
DEPLOYMENT_STATE_INACTIVE = "Inactive"
DEPLOYMENT_STATE_PRESTAGING = "Prestaging"
DEPLOYMENT_STATE_PRESTAGED = "Prestaged"

UPGRADE_FEED_DIR = "/var/www/pages/feed/"
TMP_DIR = "/tmp"
OSTREE_REPO = 'ostree_repo'

ISO_EXTENSION = ".iso"
SIG_EXTENSION = ".sig"
PATCH_EXTENSION = ".patch"
SUPPORTED_UPLOAD_FILE_EXT = [ISO_EXTENSION, SIG_EXTENSION, PATCH_EXTENSION]
SCRATCH_DIR = "/scratch"
