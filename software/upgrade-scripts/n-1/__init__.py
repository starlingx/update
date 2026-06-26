#!/usr/bin/env python
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import logging
import os

from software.utilities.plugin_runner import ScriptPlugin


LOG = logging.getLogger('main_logger')

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

_SCRIPT_DIR = os.path.dirname(__file__)


def _sp(script, action):
    """Create a ScriptPlugin for a script in this directory."""
    path = os.path.join(_SCRIPT_DIR, script)
    completed_state = script.rsplit('.', 1)[0] + '-completed'
    return ScriptPlugin(action, None, path, completed_state)


PLUGINS = {
    ACTION_MIGRATE: {
        FRAMEWORK_INIT: [
            _sp("07-populate-ihost-sw-version-field.py", ACTION_MIGRATE),
        ],
        FEATURE_PRE_APPS: [
            _sp("11-update-static-hieradata.py", ACTION_MIGRATE),
            _sp("04-remove-out-of-tree-service-parameter.py", ACTION_MIGRATE),
            _sp("05-add-autoreapply-service-parameter.py", ACTION_MIGRATE),
            _sp("13-registry-central-as-local-scope.py", ACTION_MIGRATE),
        ],
        K8S_APP_UPDATE: [],
        FEATURE_POST_APPS: [],
        FRAMEWORK_FINALIZE: [
            _sp("197-reset-config-target.py", ACTION_MIGRATE),
        ],
    },
    ACTION_ACTIVATE: {
        FRAMEWORK_INIT: [
            _sp("31-set-ignore-lockout-failure-attempts.py", ACTION_ACTIVATE),
            _sp("08-activate-keystone.py", ACTION_ACTIVATE),
            _sp("23-resize-systemcontroller-filesystems.sh", ACTION_ACTIVATE),
        ],
        FEATURE_PRE_APPS: [
            _sp("10-add-cluster-host-ip-to-kube-apiserver-cert.py", ACTION_ACTIVATE),
            _sp("203-netapp-trident-migration.py", ACTION_ACTIVATE),
        ],
        K8S_APP_UPDATE: [
            _sp("18-disable-portieris-webhook.py", ACTION_ACTIVATE),
            _sp("19-assert-docker-health.sh", ACTION_ACTIVATE),
            _sp("20-enable-fluxcd-controllers.py", ACTION_ACTIVATE),
            _sp("21-k8s-app-upgrade.py", ACTION_ACTIVATE),
        ],
        FEATURE_POST_APPS: [
            _sp("41-ensure-oidc-service-parameters.py", ACTION_ACTIVATE),
        ],
        FRAMEWORK_FINALIZE: [
            _sp("198-update-isystem-data.py", ACTION_ACTIVATE),
        ],
    },
    ACTION_ACTIVATE_ROLLBACK: {
        FRAMEWORK_INIT: [
            _sp("198-update-isystem-data.py", ACTION_ACTIVATE_ROLLBACK),
        ],
        FEATURE_PRE_APPS: [],
        K8S_APP_UPDATE: [
            _sp("22-rollback-fluxcd-controllers.py", ACTION_ACTIVATE_ROLLBACK),
            _sp("21-k8s-app-upgrade.py", ACTION_ACTIVATE_ROLLBACK),
            _sp("18-disable-portieris-webhook.py", ACTION_ACTIVATE_ROLLBACK),
        ],
        FEATURE_POST_APPS: [
            _sp("203-netapp-trident-migration.py", ACTION_ACTIVATE_ROLLBACK),
        ],
        FRAMEWORK_FINALIZE: [],
    },
    ACTION_DELETE: {
        FRAMEWORK_INIT: [
            _sp("26-clean-up-deployment-data.py", ACTION_DELETE),
        ],
        FEATURE_PRE_APPS: [
            _sp("40-clean-apiserver-certsan-parameter.py", ACTION_DELETE),
        ],
        K8S_APP_UPDATE: [],
        FEATURE_POST_APPS: [],
        FRAMEWORK_FINALIZE: [
            _sp("202-remove-lvm-snapshots.py", ACTION_DELETE),
        ],
    },
}


MIGRATE_PLUGINS = PLUGINS[ACTION_MIGRATE]
ACTIVATE_PLUGINS = PLUGINS[ACTION_ACTIVATE]
ACTIVATE_ROLLBACK_PLUGINS = PLUGINS[ACTION_ACTIVATE_ROLLBACK]
DELETE_PLUGINS = PLUGINS[ACTION_DELETE]

# supported n-2 from release version. None if unsupported.
PREV_RELEASE = None


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
    return join_plugins(prev_release_plugins, MIGRATE_PLUGINS)


def get_activate_plugins(from_release):
    prev_release_plugins = {stage: [] for stage in PLUGIN_STAGES}
    return join_plugins(prev_release_plugins, ACTIVATE_PLUGINS)


def get_activate_rollback_plugins(from_release):
    prev_release_plugins = {stage: [] for stage in PLUGIN_STAGES}
    return join_plugins(prev_release_plugins, ACTIVATE_ROLLBACK_PLUGINS)


def get_delete_plugins(from_release):
    prev_release_plugins = {stage: [] for stage in PLUGIN_STAGES}
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
