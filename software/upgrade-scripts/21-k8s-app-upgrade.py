#!/usr/bin/python
# Copyright (c) 2022-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import logging
import os
import sys
import time

from cgtsclient import client as cgts_client
from software.utilities.plugin_runner import CPlugin
from software.utilities.utils import configure_logging

LOG = logging.getLogger('main_logger')
TIMEOUT_LIMIT_IN_MINUTES = 30
PROGRESS_CHECK_INTERVAL_IN_SECONDS = 20
IN_PROGRESS_STATUS = 'in_progress'
FAILED_STATUS = 'failed'
COMPLETED_STATUS = 'completed'
NO_INFO_STATUS = 'no_info'
ERROR_STATUS = 'error'
TIMEOUT_STATUS = 'timeout'
REVERT_ACTION = 'revert'
APP_UPLOAD_SUCCESS = 'uploaded'
APP_UPDATE_STARTING = 'update-starting'
APP_UPDATE_IN_PROGRESS = 'updating'
APP_APPLY_SUCCESS = 'applied'


def get_sysinv_client():
    return cgts_client.get_client(
        "1",
        os_auth_token=os.environ.get("OS_AUTH_TOKEN"),
        system_url=os.environ.get("SYSTEM_URL")
    )


def log_apps_progress_via_database(client_and_release_info, action='update', short_version=False):
    client = client_and_release_info['client']
    from_release = client_and_release_info['from_release']
    to_release = client_and_release_info['to_release']

    try:
        apps = client.kube_app.get_all_apps()
    except Exception as e:
        LOG.error(f"Failed to get apps from database: {e}")
        return

    updated = []
    not_updated = []
    update_in_progress = []

    for app in apps:
        name = app['name']
        status = app['status']
        app_version = app['app_version']

        if status in [APP_APPLY_SUCCESS, APP_UPLOAD_SUCCESS] and to_release in app_version:
            updated.append(name)
        elif status in [APP_APPLY_SUCCESS, APP_UPLOAD_SUCCESS] and from_release in app_version:
            not_updated.append(name)
        elif status in [APP_UPDATE_STARTING, APP_UPDATE_IN_PROGRESS]:
            update_in_progress.append(name)

    if updated:
        verb = 'Reverted' if action == REVERT_ACTION else 'Updated'
        LOG.info(f"{verb} apps up to now: {', '.join(updated)}")
    if not_updated and not short_version:
        verb = 'reverting' if action == REVERT_ACTION else 'updating'
        LOG.info(f"Applications that have not yet started the {verb} process: "
                 f"{', '.join(not_updated)}")
    if update_in_progress and not short_version:
        verb = 'reverting' if action == REVERT_ACTION else 'updating'
        LOG.info(f"Applications currently in the {verb} process: "
                 f"{', '.join(update_in_progress)}")


def log_progress(max_attempts, currently_attempt, status, client_and_release_info,
                 failed_apps=[], updated_apps=[], error_msg=None, action='update'):
    attempt_msg = f"{action.capitalize()} checking {currently_attempt + 1}/{max_attempts}"
    interval_msg = f"Checking again in {PROGRESS_CHECK_INTERVAL_IN_SECONDS} second(s)."

    status_to_msg = {
        IN_PROGRESS_STATUS: f'{attempt_msg}: Application {action} still in progress. {interval_msg}',
        FAILED_STATUS: f'{attempt_msg}: The application {action} process failed',
        COMPLETED_STATUS: f'{attempt_msg}: Application {action} successfully finished.',
        NO_INFO_STATUS: f'{attempt_msg}: No info from the Application Framework regarding '
                        f'application {action}. {interval_msg}',
        ERROR_STATUS: f'{attempt_msg} failed with error: {error_msg}',
        TIMEOUT_STATUS: f'{attempt_msg}: Application {action} failed due to a timeout. '
                        f'For more details, check the sysinv logs at /var/log/sysinv.log'
    }

    verb = 'Reverted' if action == REVERT_ACTION else 'Updated'
    apps_msg = ''

    if updated_apps and status == COMPLETED_STATUS:
        apps_msg += f"{verb} apps: {', '.join(updated_apps)}."
    if failed_apps:
        apps_msg += f"The following apps did not {action} correctly and require manual " \
                    f"intervention: {', '.join(failed_apps)}."

    progress_log = status_to_msg[status]

    if status in (FAILED_STATUS, ERROR_STATUS):
        LOG.error(progress_log)
        if apps_msg:
            LOG.info(apps_msg)
        return
    elif status == TIMEOUT_STATUS:
        log_apps_progress_via_database(client_and_release_info, action=action)
        LOG.warning(
            "The apps listed above may change as sysinv continues to update/revert apps. "
            "If the app that's taking longer than expected to update/revert is resolved, "
            "the update will continue for the remaining apps."
        )
        LOG.error(progress_log)
        return

    LOG.info(progress_log)
    if apps_msg:
        LOG.info(apps_msg)
    else:
        log_apps_progress_via_database(client_and_release_info, action=action, short_version=True)


def check_apps_update_progress(client_and_release_info, action='update'):
    max_attempts = int(TIMEOUT_LIMIT_IN_MINUTES * 60 / PROGRESS_CHECK_INTERVAL_IN_SECONDS)
    currently_attempt = 0
    client = client_and_release_info['client']
    while currently_attempt < max_attempts:
        try:
            response = client.kube_app.get_apps_update_status()
            status = NO_INFO_STATUS
            if response:
                status = response['status']
            log_progress(max_attempts, currently_attempt, status,
                         client_and_release_info, response['failed_apps'],
                         response['updated_apps'], action=action)
            if status == IN_PROGRESS_STATUS:
                time.sleep(PROGRESS_CHECK_INTERVAL_IN_SECONDS)
                currently_attempt += 1
            elif status == FAILED_STATUS:
                return False
            elif status == COMPLETED_STATUS:
                return True
            else:
                currently_attempt += 1
        except Exception as e:
            log_progress(max_attempts, currently_attempt, ERROR_STATUS,
                         client_and_release_info, error_msg=e, action=action)
            time.sleep(PROGRESS_CHECK_INTERVAL_IN_SECONDS)
            currently_attempt += 1
    log_progress(max_attempts, currently_attempt, TIMEOUT_STATUS,
                 client_and_release_info, action=action)
    return False


class K8sAppUpgrade(CPlugin):
    def __init__(self):
        super().__init__(
            matching_action=['activate', 'activate-rollback'],
            required_state=None,
            plugin_name='k8s-app-upgrade',
            completed_state='k8s-app-upgrade-completed'
        )

    def _run(self, from_release, to_release, action, port):
        configure_logging()
        LOG.info("%s invoked from_release = %s to_release = %s action = %s"
                 % (self.name, from_release, to_release, action))
        client = get_sysinv_client()
        client_and_release_info = {
            'client': client,
            'from_release': from_release,
            'to_release': to_release
        }
        if action == 'activate':
            client.kube_app.update_all()
            time.sleep(5)
            if not check_apps_update_progress(client_and_release_info):
                raise Exception("Application update failed")
        elif action == 'activate-rollback':
            if client.kube_app.get_all_apps_by_status('apply-failed'):
                raise Exception(
                    "One or more applications are in 'apply-failed' status. "
                    "Manual intervention is required.")
            client.kube_app.rollback_all_apps()
            time.sleep(5)
            if not check_apps_update_progress(client_and_release_info, REVERT_ACTION):
                raise Exception("Application rollback failed")


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

    plugin = K8sAppUpgrade()
    result = plugin.run(from_release, to_release, action, port)
    if result and 'failed' in result:
        sys.exit(1)
