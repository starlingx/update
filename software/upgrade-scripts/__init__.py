#!/usr/bin/env python
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import sys
import logging
import importlib.util
import os

from software.utilities.plugin_runner import ScriptPlugin


LOG = logging.getLogger('main_logger')
SOFTWARE_LOG_FILE = "/var/log/software.log"

DEPLOY_SCRIPTS_FAILURES_LOG = logging.getLogger('deploy_scripts_failures')
DEPLOY_SCRIPTS_FAILURES_LOG_FILE = "/var/log/deploy_scripts_failures.log"

# 26.09 release supports migrate, activate, activate-rollback and delete
# plugin actions
ACTION_MIGRATE = "migrate"
ACTION_ACTIVATE = "activate"
ACTION_ACTIVATE_ROLLBACK = "activate-rollback"
ACTION_DELETE = "delete"
PLUGIN_ACTIONS = [ACTION_MIGRATE, ACTION_ACTIVATE, ACTION_ACTIVATE_ROLLBACK, ACTION_DELETE]
FRAMEWORK_INIT = "framework_init"
FEATURE_PRE_APPS = "feature_pre_apps"
K8S_APP_UPDATE = "k8s_apps_update"
FEATURE_POST_APPS = "feature_post_apps"
FRAMEWORK_FINALIZE = "framework_finalize"
PLUGIN_STAGES = [FRAMEWORK_INIT, FEATURE_PRE_APPS, K8S_APP_UPDATE,
                 FEATURE_POST_APPS, FRAMEWORK_FINALIZE]

# Import all plugin classes
from importlib import import_module as _import_module

PopulateIHostSWVersion = getattr(
    _import_module(".07-populate-ihost-sw-version-field", __name__),
    "PopulateIHostSWVersion")
ActivateKeystone = getattr(
    _import_module(".08-activate-keystone", __name__),
    "ActivateKeystone")
UpdateStaticHieradata = getattr(
    _import_module(".11-update-static-hieradata", __name__),
    "UpdateStaticHieradata")
DisablePortierisWebhook = getattr(
    _import_module(".18-disable-portieris-webhook", __name__),
    "DisablePortierisWebhook")
EnableFluxcdControllers = getattr(
    _import_module(".20-enable-fluxcd-controllers", __name__),
    "EnableFluxcdControllers")
K8sAppUpgrade = getattr(
    _import_module(".21-k8s-app-upgrade", __name__),
    "K8sAppUpgrade")
RollbackFluxcdControllers = getattr(
    _import_module(".22-rollback-fluxcd-controllers", __name__),
    "RollbackFluxcdControllers")
CleanUpDeploymentData = getattr(
    _import_module(".26-clean-up-deployment-data", __name__),
    "CleanUpDeploymentData")
SetServiceUserOptions = getattr(
    _import_module(".31-set-service-user-options", __name__),
    "SetServiceUserOptions")
ResetConfigTarget = getattr(
    _import_module(".197-reset-config-target", __name__),
    "ResetConfigTarget")
UpdateISystemData = getattr(
    _import_module(".198-update-isystem-data", __name__),
    "UpdateISystemData")
RemoveLvmSnapshots = getattr(
    _import_module(".202-remove-lvm-snapshots", __name__),
    "RemoveLvmSnapshots")
AddPlatformTlsParameters = getattr(
    _import_module(".42-add-platform-tls-parameters", __name__),
    "AddPlatformTlsParameters")

# Shell scripts are wrapped as ScriptPlugin instances
_SCRIPT_DIR = os.path.dirname(__file__)


def _shell_script_plugin(script, action, required_state=None, completed_state=None):
    path = os.path.join(_SCRIPT_DIR, script)
    if completed_state is None:
        completed_state = script.rsplit('.', 1)[0] + '-completed'
    return ScriptPlugin(action, required_state, path, completed_state)


# Plugins for each action are organized as 3 parts,
# framework initialize, feature, and framework finalize
# however in activate and activate-rollback, feature plugins are divided
# into 2 groups, pre k8s apps update and post k8s apps update, therefore
# feature plugins are grouped into 2 groups
# in total, all plugins are grouped as:
# frame_init, feature_pre_apps, k8s_apps_update, feature_post_apps, framework_finalize
PLUGINS = {
    ACTION_MIGRATE: {
        FRAMEWORK_INIT: [
            PopulateIHostSWVersion(),
        ],
        FEATURE_PRE_APPS: [
            UpdateStaticHieradata(),
        ],
        K8S_APP_UPDATE: [],
        FEATURE_POST_APPS: [],
        FRAMEWORK_FINALIZE: [
            ResetConfigTarget(),
        ],
    },
    ACTION_ACTIVATE: {
        FRAMEWORK_INIT: [
            SetServiceUserOptions(),
            ActivateKeystone(),
            _shell_script_plugin("23-resize-systemcontroller-filesystems.py",
                                 ACTION_ACTIVATE),
        ],
        FEATURE_PRE_APPS: [
            AddPlatformTlsParameters(),
            DisablePortierisWebhook(),
        ],
        K8S_APP_UPDATE: [
            _shell_script_plugin("19-assert-docker-health.py", ACTION_ACTIVATE),
            EnableFluxcdControllers(),
            K8sAppUpgrade(),
        ],
        FEATURE_POST_APPS: [],
        FRAMEWORK_FINALIZE: [
            UpdateISystemData(),
        ],
    },
    ACTION_ACTIVATE_ROLLBACK: {
        FRAMEWORK_INIT: [
            UpdateISystemData(),
        ],
        FEATURE_PRE_APPS: [],
        K8S_APP_UPDATE: [
            RollbackFluxcdControllers(),
            K8sAppUpgrade(),
            DisablePortierisWebhook(),
        ],
        FEATURE_POST_APPS: [],
        FRAMEWORK_FINALIZE: [],
    },
    ACTION_DELETE: {
        FRAMEWORK_INIT: [
            CleanUpDeploymentData(),
        ],
        FEATURE_PRE_APPS: [],
        K8S_APP_UPDATE: [],
        FEATURE_POST_APPS: [],
        FRAMEWORK_FINALIZE: [
            RemoveLvmSnapshots(),
        ],
    },
}


MIGRATE_PLUGINS = PLUGINS[ACTION_MIGRATE]
ACTIVATE_PLUGINS = PLUGINS[ACTION_ACTIVATE]
ACTIVATE_ROLLBACK_PLUGINS = PLUGINS[ACTION_ACTIVATE_ROLLBACK]
DELETE_PLUGINS = PLUGINS[ACTION_DELETE]

# supported n-2 from release version. None if unsupported.
PREV_RELEASE = "25.09"


def get_plugin_mgr():
    module_path = os.path.dirname(__file__)
    sys.path.append(module_path)
    try:
        plugin_mgr = importlib.import_module("n-1")
    finally:
        sys.path.remove(module_path)

    return plugin_mgr


def join_plugins(prev_release_plugins, plugins):
    result = {
        FRAMEWORK_INIT: plugins[FRAMEWORK_INIT],
        FEATURE_PRE_APPS: prev_release_plugins[FEATURE_PRE_APPS] + plugins[FEATURE_PRE_APPS],
        K8S_APP_UPDATE: plugins[K8S_APP_UPDATE],
        FEATURE_POST_APPS: prev_release_plugins[FEATURE_POST_APPS] + plugins[FEATURE_POST_APPS],
        FRAMEWORK_FINALIZE: plugins[FRAMEWORK_FINALIZE],
    }
    LOG.info(f"list of plugins {result}")
    return result


def get_migrate_plugins(from_release):
    prev_release_plugins = {stage: [] for stage in PLUGIN_STAGES}
    if from_release == PREV_RELEASE:
        plugin_mgr = get_plugin_mgr()
        prev_release_plugins = plugin_mgr.get_migrate_plugins(from_release)

    return join_plugins(prev_release_plugins, MIGRATE_PLUGINS)


def get_activate_plugins(from_release):
    prev_release_plugins = {stage: [] for stage in PLUGIN_STAGES}
    if from_release == PREV_RELEASE:
        plugin_mgr = get_plugin_mgr()
        prev_release_plugins = plugin_mgr.get_activate_plugins(from_release)

    return join_plugins(prev_release_plugins, ACTIVATE_PLUGINS)


def get_activate_rollback_plugins(from_release):
    prev_release_plugins = {stage: [] for stage in PLUGIN_STAGES}
    if from_release == PREV_RELEASE:
        plugin_mgr = get_plugin_mgr()
        prev_release_plugins = plugin_mgr.get_activate_rollback_plugins(from_release)

    return join_plugins(prev_release_plugins, ACTIVATE_ROLLBACK_PLUGINS)


def get_delete_plugins(from_release):
    prev_release_plugins = {stage: [] for stage in PLUGIN_STAGES}
    if from_release == PREV_RELEASE:
        plugin_mgr = get_plugin_mgr()
        prev_release_plugins = plugin_mgr.get_delete_plugins(from_release)

    return join_plugins(prev_release_plugins, DELETE_PLUGINS)


def get_plugins(from_release, action):
    LOG.info(f"get {action} plugins, upgrade from {from_release}")
    if action == ACTION_DELETE:
        result = get_delete_plugins(from_release)
    elif action == ACTION_MIGRATE:
        result = get_migrate_plugins(from_release)
    elif action == ACTION_ACTIVATE:
        result = get_activate_plugins(from_release)
    elif action == ACTION_ACTIVATE_ROLLBACK:
        result = get_activate_rollback_plugins(from_release)
    else:
        result = {stage: [] for stage in PLUGIN_STAGES}

    return (
        result[FRAMEWORK_INIT] +
        result[FEATURE_PRE_APPS] +
        result[K8S_APP_UPDATE] +
        result[FEATURE_POST_APPS] +
        result[FRAMEWORK_FINALIZE]
    )


__all__ = ["get_migrate_plugins", "get_activate_plugins",
           "get_activate_rollback_plugins", "get_delete_plugins", "get_plugins"]
