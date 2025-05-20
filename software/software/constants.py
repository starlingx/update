"""
Copyright (c) 2023-2025 Wind River Systems, Inc.

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

# Network
ADDRESS_VERSION_IPV4 = 4
ADDRESS_VERSION_IPV6 = 6
LOOPBACK_INTERFACE_NAME = "lo"

# Availability and administrative
AVAILABILITY_ONLINE = 'online'
AVAILABILITY_AVAILABLE = 'available'
AVAILABILITY_DEGRADED = 'degraded'
ADMIN_LOCKED = 'locked'
ADMIN_UNLOCKED = 'unlocked'

# Hostnames
CONTROLLER_FLOATING_HOSTNAME = "controller"
CONTROLLER_0_HOSTNAME = '%s-0' % CONTROLLER_FLOATING_HOSTNAME
CONTROLLER_1_HOSTNAME = '%s-1' % CONTROLLER_FLOATING_HOSTNAME
PREBOOTSTRAP_HOSTNAME = 'localhost'

# Personalities
CONTROLLER = 'controller'
STORAGE = 'storage'
WORKER = 'worker'

# Region names
DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER = 'systemcontroller'
SYSTEM_CONTROLLER_REGION = 'SystemController'

# DC
DC_VAULT_DIR = "/opt/dc-vault"
DC_VAULT_PLAYBOOK_DIR = "%s/playbooks" % DC_VAULT_DIR
DC_VAULT_LOADS_DIR = "%s/loads" % DC_VAULT_DIR

# Certificate
ENABLE_DEV_CERTIFICATE_PATCH_IDENTIFIER = 'ENABLE_DEV_CERTIFICATE'

# Software path's
SOFTWARE_STORAGE_DIR = "/opt/software"
SOFTWARE_CONFIG_FILE_LOCAL = "/etc/software/software.conf"
SOFTWARE_DEPLOY_FOLDER = "software-deploy"
SOFTWARE_JSON_FILE = "%s/software.json" % SOFTWARE_STORAGE_DIR
SYNCED_SOFTWARE_JSON_FILE = "%s/synced/software.json" % SOFTWARE_STORAGE_DIR

# Deploy precheck return codes
RC_SUCCESS = 0
RC_UNHEALTHY = 3

# Script names
DEPLOY_PRECHECK_SCRIPT = "deploy-precheck"
UPGRADE_UTILS_SCRIPT = "upgrade_utils.py"
DEPLOY_START_SCRIPT = "deploy-start"
REMOVE_TEMPORARY_DATA_SCRIPT = "remove-temporary-data"
MAJOR_RELEASE_UPLOAD_SCRIPT = "major-release-upload"
PATCH_SCRIPTS_STAGING_DIR = "/var/www/pages/updates/software-scripts"

# Status
STATUS_DEVELOPEMENT = 'DEV'
STATUS_OBSOLETE = 'OBS'
STATUS_RELEASED = 'REL'

# Patch status
PATCH_AGENT_STATE_IDLE = "idle"
PATCH_AGENT_STATE_INSTALLING = "installing"
PATCH_AGENT_STATE_INSTALL_FAILED = "install-failed"
PATCH_AGENT_STATE_INSTALL_REJECTED = "install-rejected"

# Patch
CHECKOUT_FOLDER = "checked_out_commit"

# Feed
DEBIAN_RELEASE = "bullseye"
FEED_DIR = "/var/www/pages/feed/"
FEED_OSTREE_BASE_DIR = "/var/www/pages/feed"
FEED_OSTREE_URL = "http://controller:8080/feed"
PACKAGE_FEED_DIR = "/var/www/pages/updates/debian"
UPGRADE_FEED_DIR = FEED_DIR

# Ostree
OSTREE_BASE_DEPLOYMENT_DIR = "/ostree/deploy/debian/deploy/"
OSTREE_REF = "starlingx"
OSTREE_REMOTE = "debian"
OSTREE_AUX_REMOTE = "controller-feed"
OSTREE_AUX_REMOTE_PATH = "/ostree/repo"
OSTREE_HISTORY_NOT_FETCHED = "<< History beyond this commit not fetched >>"
OSTREE_REPO = 'ostree_repo'
SYSROOT_OSTREE_REF = "debian:starlingx"

# Sysroot
SYSROOT_OSTREE = "/sysroot/ostree/repo"
STAGING_DIR = "/sysroot/upgrade"
ROOT_DIR = "%s/sysroot" % STAGING_DIR

ETCD_PATH = "/opt/etcd"
PLATFORM_PATH = "/opt/platform"
PLAYBOOKS_PATH = "/usr/share/ansible/stx-ansible/playbooks"
POSTGRES_PATH = "/var/lib/postgresql"
RABBIT_PATH = '/var/lib/rabbitmq'
TMP_DIR = "/tmp"

# Upgrade dirs
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
DEPLOY_CLEANUP_FOLDERS_NAME = [ARMADA, CONFIG, DEPLOY, FLUXCD, HELM, KEYRING, PUPPET, SYSINV, VIM]

# Semantic
SEMANTIC_PREAPPLY = 'pre-apply'
SEMANTIC_PREREMOVE = 'pre-remove'
SEMANTIC_ACTIONS = [SEMANTIC_PREAPPLY, SEMANTIC_PREREMOVE]
SEMANTICS_DIR = "%s/semantics" % SOFTWARE_STORAGE_DIR

# Upload
ISO_EXTENSION = ".iso"
SIG_EXTENSION = ".sig"
PATCH_EXTENSION = ".patch"
SUPPORTED_UPLOAD_FILE_EXT = [ISO_EXTENSION, SIG_EXTENSION, PATCH_EXTENSION]
SCRATCH_DIR = "/scratch"

# Release
LOWEST_MAJOR_RELEASE_FOR_PATCH_SUPPORT = "24.09"
MAJOR_RELEASE = "%s.0"
RELEASE_GA_NAME = "starlingx-%s"
RELEASE_PREFIX = "rel"
STARLINGX_RELEASE = SW_VERSION
UNKNOWN_SOFTWARE_VERSION = "0.0.0"

# Precheck constants
LICENSE_FILE = "/etc/platform/.license"
VERIFY_LICENSE_BINARY = "/usr/bin/verify-license"
VERSIONED_SCRIPTS_DIR = "%s/rel-%%s/bin/" % SOFTWARE_STORAGE_DIR

WORKER_SUMMARY_DIR = "%s/summary" % SOFTWARE_STORAGE_DIR
WORKER_DATETIME_FORMAT = "%Y%m%dT%H%M%S%f"

# Sync
ALARM_INSTANCE_ID_OUT_OF_SYNC = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_HOST,
                                           CONTROLLER_FLOATING_HOSTNAME)
LAST_IN_SYNC = "last_in_sync"
TIMEOUT_SYNC_API_CALL = 120

# System type/mode
SYSTEM_TYPE_ALL_IN_ONE = "All-in-one"
SYSTEM_MODE_SIMPLEX = "simplex"
SYSTEM_MODE_DUPLEX = "duplex"

# Software alarms
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

# Metadata
BASE_TAG = "base"
CHECKSUM_TAG = "checksum"
CONTENTS_TAG = "contents"
COMMIT_DEFAULT_VALUE = "xxxBASECOMMITxxx"
COMMIT_TAG = "commit"
COMMIT1_TAG = "commit1"
NUMBER_OF_COMMITS_TAG = "number_of_commits"
OSTREE_TAG = "ostree"

# Flags
INSTALL_LOCAL_FLAG = "/opt/software/.install_local"
REBOOT_REQUIRED = "reboot_required"
USM_UPGRADE_IN_PROGRESS_FLAG = os.path.join(tsc.PLATFORM_CONF_PATH, ".usm_upgrade_in_progress")
UPGRADE_DO_NOT_USE_FQDN_FLAG = os.path.join(tsc.PLATFORM_CONF_PATH, ".upgrade_do_not_use_fqdn")

# Host software agent
MAX_OSTREE_DEPLOY_RETRIES = 5

# Precheck timeout
PRECHECK_RESULT_VALID_PERIOD = 300

# Logging
LOG_DEFAULT_FORMAT = ('%(asctime)s.%(msecs)03d USM - %(exec)s [%(process)s:%(thread)d]: '
                      '%(filename)s(%(lineno)s): %(levelname)s: %(message)s')
SOFTWARE_API_SUPPRESS_PATTERNS = [
    r"GET /v1/deploy/software_upgrade",
]
