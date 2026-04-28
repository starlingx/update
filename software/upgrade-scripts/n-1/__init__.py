#!/usr/bin/env python
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import os
import sys
import logging
import importlib.util


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

# Plugins for each action are organized as 3 parts,
# framework initialize, feature, and framework finalize
# however in activate and activate-rollback, feature plugins are devided
# into 2 groups, pre k8s apps update and post k8s apps update, therefore
# feature plugins are grouped into 2 groups
# in total, all plugins are grouped as:
# frame_init, feature_pre_apps, k8s_apps_update, feature_post_apps, framework_finalize
PLUGINS = {
    ACTION_MIGRATE: {
        FRAMEWORK_INIT: [
            "07-populate-ihost-sw-version-field.py",
        ],
        FEATURE_PRE_APPS: [
            "11-update-static-hieradata.py",
            "04-remove-out-of-tree-service-parameter.py",
            "05-add-autoreapply-service-parameter.py",
            "13-registry-central-as-local-scope.py",
        ],
        K8S_APP_UPDATE: [],
        FEATURE_POST_APPS: [],
        FRAMEWORK_FINALIZE: [
            "197-reset-config-target.py"
        ],
    },
    ACTION_ACTIVATE: {
        FRAMEWORK_INIT: [
            "31-set-ignore-lockout-failure-attempts.py",
            "08-activate-keystone.py",
            "23-resize-systemcontroller-filesystems.sh",],
        FEATURE_PRE_APPS: [
            "10-add-cluster-host-ip-to-kube-apiserver-cert.py",
        ],
        K8S_APP_UPDATE: [
            "18-disable-portieris-webhook.py",
            "19-assert-docker-health.sh",
            "20-enable-fluxcd-controllers.py",
            "21-k8s-app-upgrade.py",
        ],
        FEATURE_POST_APPS: [
            "41-ensure-oidc-service-parameters.py",
        ],
        FRAMEWORK_FINALIZE: [
            "198-update-isystem-data.py",
        ],
    },
    ACTION_ACTIVATE_ROLLBACK: {
        FRAMEWORK_INIT: [
            "198-update-isystem-data.py", ],
        FEATURE_PRE_APPS: [],
        K8S_APP_UPDATE: [
            "22-rollback-fluxcd-controllers.py",
            "21-k8s-app-upgrade.py",
            "18-disable-portieris-webhook.py",
        ],
        FEATURE_POST_APPS: [],
        FRAMEWORK_FINALIZE: []
    },
    ACTION_DELETE: {
        FRAMEWORK_INIT: [
            "26-clean-up-deployment-data.py",
        ],
        FEATURE_PRE_APPS: [
            "40-clean-apiserver-certsan-parameter.py"
        ],
        K8S_APP_UPDATE: [],
        FEATURE_POST_APPS: [],
        FRAMEWORK_FINALIZE: [
            "202-remove-lvm-snapshots.py",
        ]
    }
}


MIGRATE_PLUGINS = PLUGINS[ACTION_MIGRATE]
ACTIVATE_PLUGINS = PLUGINS[ACTION_ACTIVATE]
ACTIVATE_ROLLBACK_PLUGINS = PLUGINS[ACTION_ACTIVATE_ROLLBACK]
DELETE_PLUGINS = PLUGINS[ACTION_DELETE]

# supported n-2 from release version. None if unsupported.
PREV_RELEASE = None


def get_plugin_mgr():
    module_path = os.path.dirname(__file__)
    sys.path.append(module_path)
    try:
        plugin_mgr = importlib.import_module("n-1")
    finally:
        sys.path.remove(module_path)

    return plugin_mgr


def format_path(plugins):
    relative_plugins = [os.path.join('n-1', p) for p in plugins]
    return relative_plugins


def join_plugins(prev_release_plugins, plugins):
    print(prev_release_plugins)
    print(plugins)
    result = {
        FRAMEWORK_INIT: plugins[FRAMEWORK_INIT],
        FEATURE_PRE_APPS: prev_release_plugins[FEATURE_PRE_APPS] + plugins[FEATURE_PRE_APPS],
        K8S_APP_UPDATE: plugins[K8S_APP_UPDATE],
        FEATURE_POST_APPS: prev_release_plugins[FEATURE_POST_APPS] + plugins[FEATURE_POST_APPS],
        FRAMEWORK_FINALIZE: plugins[FRAMEWORK_FINALIZE]
    }
    LOG.info(f"list of scripts {result}")
    return result


def get_migrate_plugins(from_release):
    prev_release_plugins = {stage: [] for stage in PLUGIN_STAGES}
    if from_release == PREV_RELEASE:
        plugin_mgr = get_plugin_mgr()
        prev_release_plugins = plugin_mgr.get_migrate_plugins(from_release)

    plugins = MIGRATE_PLUGINS
    return join_plugins(prev_release_plugins, plugins)


def get_activate_plugins(from_release):
    prev_release_plugins = {stage: [] for stage in PLUGIN_STAGES}
    if from_release == PREV_RELEASE:
        plugin_mgr = get_plugin_mgr()
        prev_release_plugins = plugin_mgr.get_activate_plugins(from_release)

    plugins = ACTIVATE_PLUGINS
    return join_plugins(prev_release_plugins, plugins)


def get_activate_rollback_plugins(from_release):
    prev_release_plugins = {stage: [] for stage in PLUGIN_STAGES}
    if from_release == PREV_RELEASE:
        plugin_mgr = get_plugin_mgr()
        prev_release_plugins = plugin_mgr.get_activate_rollback_plugins(from_release)

    plugins = ACTIVATE_ROLLBACK_PLUGINS
    return join_plugins(prev_release_plugins, plugins)


def get_delete_plugins(from_release):
    prev_release_plugins = {stage: [] for stage in PLUGIN_STAGES}
    if from_release == PREV_RELEASE:
        plugin_mgr = get_plugin_mgr()
        prev_release_plugins = plugin_mgr.get_delete_plugins(from_release)

    plugins = DELETE_PLUGINS
    return join_plugins(prev_release_plugins, plugins)


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
        result = {action: {stage: [] for stage in PLUGIN_STAGES} for action in PLUGIN_ACTIONS}

    return (
        result[FRAMEWORK_INIT] +
        result[FEATURE_PRE_APPS] +
        result[K8S_APP_UPDATE] +
        result[FEATURE_POST_APPS] +
        result[FRAMEWORK_FINALIZE]
    )


__all__ = ["get_migrate_plugins", "get_activate_plugins", "get_activate_rollback_plugins", "get_delete_plugins", "get_plugins"]
