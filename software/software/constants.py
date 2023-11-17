"""
Copyright (c) 2023 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
from enum import Enum
import os
try:
    # The tsconfig module is only available at runtime
    import tsconfig.tsconfig as tsc

    INITIAL_CONFIG_COMPLETE_FLAG = os.path.join(
        tsc.PLATFORM_CONF_PATH, ".initial_config_complete")
except Exception:
    pass

from tsconfig.tsconfig import SW_VERSION

ADDRESS_VERSION_IPV4 = 4
ADDRESS_VERSION_IPV6 = 6
CONTROLLER_FLOATING_HOSTNAME = "controller"

SOFTWARE_STORAGE_DIR = "/opt/software"
SOFTWARE_CONFIG_FILE_LOCAL = "/etc/software/software.conf"

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
PACKAGE_FEED_DIR = "/var/www/pages/updates/debian"
OSTREE_REF = "starlingx"
OSTREE_REMOTE = "debian"
DEBIAN_RELEASE = "bullseye"
STARLINGX_RELEASE = SW_VERSION
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

FEED_DIR = "/var/www/pages/feed/"
UPGRADE_FEED_DIR = FEED_DIR
TMP_DIR = "/tmp"
OSTREE_REPO = 'ostree_repo'

ISO_EXTENSION = ".iso"
SIG_EXTENSION = ".sig"
PATCH_EXTENSION = ".patch"
SUPPORTED_UPLOAD_FILE_EXT = [ISO_EXTENSION, SIG_EXTENSION, PATCH_EXTENSION]
SCRATCH_DIR = "/scratch"
RELEASE_GA_NAME = "starlingx-%s.0"
LOCAL_LOAD_IMPORT_FILE = "/etc/software/usm_load_import"

# Precheck constants
LICENSE_FILE = "/etc/platform/.license"
VERIFY_LICENSE_BINARY = "/usr/bin/verify-license"

SOFTWARE_JSON_FILE = "/opt/software/software.json"

# The value "software-deploy" is also used in rule file
SOFTWARE_DEPLOY_FOLDER = "software-deploy"

WORKER_SUMMARY_DIR = "%s/summary" % SOFTWARE_STORAGE_DIR
WORKER_DATETIME_FORMAT = "%Y%m%dT%H%M%S%f"
UNKNOWN_SOFTWARE_VERSION = "0.0.0"


class DEPLOY_STATES(Enum):
    ACTIVATING = 'activating'
    ACTIVATED = 'activated'
    ACTIVATION_FAILED = 'activation-failed'
    DATA_MIGRATION_FAILED = 'data-migration-failed'
    DATA_MIGRATION = 'data-migration'
    DEPLOYING = 'deploying'
    DEPLOYED = 'deployed'
    PRESTAGING = 'prestaging'
    PRESTAGED = 'prestaged'
    PRESTAGING_FAILED = 'prestaging-failed'
    UPGRADE_CONTROLLERS = 'upgrade-controllers'
    UPGRADE_CONTROLLER_FAILED = 'upgrade-controller-failed'
    UPGRADE_HOSTS = 'upgrade-hosts'
    UNKNOWN = 'unknown'
