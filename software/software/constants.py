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

from fm_api import constants as fm_constants
from tsconfig.tsconfig import SW_VERSION

ADDRESS_VERSION_IPV4 = 4
ADDRESS_VERSION_IPV6 = 6
CONTROLLER_FLOATING_HOSTNAME = "controller"
CONTROLLER_0_HOSTNAME = '%s-0' % CONTROLLER_FLOATING_HOSTNAME
CONTROLLER_1_HOSTNAME = '%s-1' % CONTROLLER_FLOATING_HOSTNAME
PREBOOTSTRAP_HOSTNAME = 'localhost'

DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER = 'systemcontroller'
SYSTEM_CONTROLLER_REGION = 'SystemController'

SOFTWARE_STORAGE_DIR = "/opt/software"
SOFTWARE_CONFIG_FILE_LOCAL = "/etc/software/software.conf"

# Deploy precheck return codes
RC_SUCCESS = 0
RC_UNHEALTHY = 3

DEPLOY_PRECHECK_SCRIPT = "deploy-precheck"
UPGRADE_UTILS_SCRIPT = "upgrade_utils.py"
DEPLOY_START_SCRIPT = "software-deploy-start"
DEPLOY_CLEANUP_SCRIPT = "deploy-cleanup"

SEMANTICS_DIR = "%s/semantics" % SOFTWARE_STORAGE_DIR

STATUS_DEVELOPEMENT = 'DEV'
STATUS_OBSOLETE = 'OBS'
STATUS_RELEASED = 'REL'

PATCH_AGENT_STATE_IDLE = "idle"
PATCH_AGENT_STATE_INSTALLING = "installing"
PATCH_AGENT_STATE_INSTALL_FAILED = "install-failed"
PATCH_AGENT_STATE_INSTALL_REJECTED = "install-rejected"

REBOOT_REQUIRED = "reboot_required"

FEED_OSTREE_BASE_DIR = "/var/www/pages/feed"
FEED_OSTREE_URL = "http://controller:8080/feed"
OSTREE_BASE_DEPLOYMENT_DIR = "/ostree/deploy/debian/deploy/"
PACKAGE_FEED_DIR = "/var/www/pages/updates/debian"
OSTREE_REF = "starlingx"
OSTREE_REMOTE = "debian"
OSTREE_AUX_REMOTE = "constroller-feed"
OSTREE_AUX_REMOTE_PATH = "/ostree/repo"
DEBIAN_RELEASE = "bullseye"
STARLINGX_RELEASE = SW_VERSION
PATCH_SCRIPTS_STAGING_DIR = "/var/www/pages/updates/software-scripts"
SYSROOT_OSTREE = "/sysroot/ostree/repo"
STAGING_DIR = "/sysroot/upgrade"
ROOT_DIR = "%s/sysroot" % STAGING_DIR
POSTGRES_PATH = "/var/lib/postgresql"
PLATFORM_PATH = "/opt/platform"
RABBIT_PATH = '/var/lib/rabbitmq'
ETCD_PATH = "/opt/etcd"
ARMADA = "armada"
CONFIG = "config"
DEPLOY = "deploy"
FLUXCD = "fluxcd"
HELM = "helm"
KEYRING = ".keyring"
PUPPET = "puppet"
SYSINV = "sysinv"
UPGRADE = "upgrade"
VIM = "nfv/vim"
RELEASE_PREFIX = "rel"

DEPLOY_CLEANUP_FOLDERS_NAME = [ARMADA, CONFIG, DEPLOY, FLUXCD, HELM, KEYRING, PUPPET, SYSINV, VIM]

LOOPBACK_INTERFACE_NAME = "lo"

SEMANTIC_PREAPPLY = 'pre-apply'
SEMANTIC_PREREMOVE = 'pre-remove'
SEMANTIC_ACTIONS = [SEMANTIC_PREAPPLY, SEMANTIC_PREREMOVE]

CHECKOUT_FOLDER = "checked_out_commit"

COMMIT_DEFAULT_VALUE = "xxxBASECOMMITxxx"

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
ALARM_INSTANCE_ID_OUT_OF_SYNC = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_HOST,
                                           CONTROLLER_FLOATING_HOSTNAME)

SYSTEM_TYPE_ALL_IN_ONE = "All-in-one"
SYSTEM_MODE_SIMPLEX = "simplex"
SYSTEM_MODE_DUPLEX = "duplex"

# Personalities
CONTROLLER = 'controller'
STORAGE = 'storage'
WORKER = 'worker'

AVAILABILITY_ONLINE = 'online'
AVAILABILITY_AVAILABLE = 'available'
ADMIN_LOCKED = 'locked'
ADMIN_UNLOCKED = 'unlocked'

SOFTWARE_ALARMS = {
    fm_constants.FM_ALARM_ID_SW_UPGRADE_DEPLOY_STATE_OUT_OF_SYNC: {
        "entity_type_id": fm_constants.FM_ENTITY_TYPE_HOST,
        "severity": fm_constants.FM_ALARM_SEVERITY_MAJOR,
        "reason_text": "Software deployment data is out of sync",
        "alarm_type": fm_constants.FM_ALARM_TYPE_11,
        "probable_cause": fm_constants.ALARM_PROBABLE_CAUSE_65,
        "proposed_repair_action": "Wait for deployment to complete",
        "service_affecting": False,
    },
    fm_constants.FM_ALARM_ID_USM_DEPLOY_HOST_SUCCESS_RR: {
        "entity_type_id": fm_constants.FM_ENTITY_TYPE_HOST,
        "severity": fm_constants.FM_ALARM_SEVERITY_WARNING,
        "reason_text": ("Deploy host completed, unlock the host to apply "
                        "the new software release"),
        "alarm_type": fm_constants.FM_ALARM_TYPE_11,
        "probable_cause": fm_constants.ALARM_PROBABLE_CAUSE_65,
        "proposed_repair_action": "Unlock host",
        "service_affecting": True,
    },
    fm_constants.FM_ALARM_ID_USM_DEPLOY_HOST_FAILURE: {
        "entity_type_id": fm_constants.FM_ENTITY_TYPE_HOST,
        "severity": fm_constants.FM_ALARM_SEVERITY_MAJOR,
        "reason_text": "Deploy host failed, check logs for errors",
        "alarm_type": fm_constants.FM_ALARM_TYPE_11,
        "probable_cause": fm_constants.ALARM_PROBABLE_CAUSE_65,
        "proposed_repair_action": ("Check the logs for errors, fix the issues manually "
                                   "and retry"),
        "service_affecting": True,
    },
    fm_constants.FM_ALARM_ID_USM_CLEANUP_DEPLOYMENT_DATA: {
        "entity_type_id": fm_constants.FM_ENTITY_TYPE_HOST,
        "severity": fm_constants.FM_ALARM_SEVERITY_WARNING,
        "reason_text": "Deploy in %s state, delete deployment to clean up the remaining %s deployment data",
        "alarm_type": fm_constants.FM_ALARM_TYPE_11,
        "probable_cause": fm_constants.ALARM_PROBABLE_CAUSE_65,
        "proposed_repair_action": "Delete deployment",
        "service_affecting": False
    }
}

# metadata tags
CONTENTS_TAG = "contents"
OSTREE_TAG = "ostree"
NUMBER_OF_COMMITS_TAG = "number_of_commits"
BASE_TAG = "base"
COMMIT_TAG = "commit"
CHECKSUM_TAG = "checksum"
COMMIT1_TAG = "commit1"

# flags
INSTALL_LOCAL_FLAG = "/opt/software/.install_local"
USM_UPGRADE_IN_PROGRESS_FLAG = os.path.join(tsc.PLATFORM_CONF_PATH, ".usm_upgrade_in_progress")
UPGRADE_DO_NOT_USE_FQDN_FLAG = os.path.join(tsc.PLATFORM_CONF_PATH, ".upgrade_do_not_use_fqdn")
