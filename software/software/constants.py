"""
Copyright (c) 2023-2024 Wind River Systems, Inc.

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

from tsconfig.tsconfig import SW_VERSION

ADDRESS_VERSION_IPV4 = 4
ADDRESS_VERSION_IPV6 = 6
CONTROLLER_FLOATING_HOSTNAME = "controller"
CONTROLLER_0_HOSTNAME = '%s-0' % CONTROLLER_FLOATING_HOSTNAME
CONTROLLER_1_HOSTNAME = '%s-1' % CONTROLLER_FLOATING_HOSTNAME

DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER = 'systemcontroller'
SYSTEM_CONTROLLER_REGION = 'SystemController'

SOFTWARE_STORAGE_DIR = "/opt/software"
SOFTWARE_CONFIG_FILE_LOCAL = "/etc/software/software.conf"

# Deploy precheck return codes
RC_SUCCESS = 0
RC_UNHEALTHY = 3

DEPLOY_PRECHECK_SCRIPT = "deploy-precheck"
DEPLOY_START_SCRIPT = "software-deploy-start"

SEMANTICS_DIR = "%s/semantics" % SOFTWARE_STORAGE_DIR

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

FEED_DIR = "/var/www/pages/feed/"
UPGRADE_FEED_DIR = FEED_DIR
TMP_DIR = "/tmp"
OSTREE_REPO = 'ostree_repo'

ISO_EXTENSION = ".iso"
SIG_EXTENSION = ".sig"
PATCH_EXTENSION = ".patch"
SUPPORTED_UPLOAD_FILE_EXT = [ISO_EXTENSION, SIG_EXTENSION, PATCH_EXTENSION]
SCRATCH_DIR = "/scratch"
RELEASE_GA_NAME = "starlingx-%s"
MAJOR_RELEASE = "%s.0"

# Precheck constants
LICENSE_FILE = "/etc/platform/.license"
VERIFY_LICENSE_BINARY = "/usr/bin/verify-license"
VERSIONED_SCRIPTS_DIR = "%s/rel-%%s/bin/" % SOFTWARE_STORAGE_DIR

SOFTWARE_JSON_FILE = "%s/software.json" % SOFTWARE_STORAGE_DIR
SYNCED_SOFTWARE_JSON_FILE = "%s/synced/software.json" % SOFTWARE_STORAGE_DIR

# The value "software-deploy" is also used in rule file
SOFTWARE_DEPLOY_FOLDER = "software-deploy"

WORKER_SUMMARY_DIR = "%s/summary" % SOFTWARE_STORAGE_DIR
WORKER_DATETIME_FORMAT = "%Y%m%dT%H%M%S%f"
UNKNOWN_SOFTWARE_VERSION = "0.0.0"

LAST_IN_SYNC = "last_in_sync"

SYSTEM_MODE_SIMPLEX = "simplex"
SYSTEM_MODE_DUPLEX = "duplex"

# Personalities
CONTROLLER = 'controller'
STORAGE = 'storage'
WORKER = 'worker'

AVAILABILITY_ONLINE = 'online'
ADMIN_LOCKED = 'locked'
