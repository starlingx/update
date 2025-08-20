#!/usr/bin/python
# Copyright (c) 2022-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import logging
import os
import sys
from time import sleep

from cgtsclient import client as cgts_client

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


def get_sysinv_client():
    sysinv_client = cgts_client.get_client(
        "1",
        os_auth_token=os.environ.get("OS_AUTH_TOKEN"),
        system_url=os.environ.get("SYSTEM_URL")
    )
    return sysinv_client


def log_progress(
    max_attempts,
    currently_attempt,
    status,
    failed_apps=[],
    updated_apps=[],
    error_msg=None,
    action='update'
):

    attempt_msg = f"{action.capitalize()} checking {currently_attempt + 1}/{max_attempts}"
    interval_msg = f"Checking again in {PROGRESS_CHECK_INTERVAL_IN_SECONDS} second(s)."

    status_to_msg = {
        IN_PROGRESS_STATUS: f'{attempt_msg}: Application {action} still in progress. {interval_msg}',
        FAILED_STATUS: f'{attempt_msg}: The application {action} process failed',
        COMPLETED_STATUS: f'{attempt_msg}: Application {action} successfully finished.',
        NO_INFO_STATUS: f'{attempt_msg}: No info from the Application Framework regarding \
            application {action}. {interval_msg}',
        ERROR_STATUS: f'{attempt_msg} failed with error: {error_msg}',
        TIMEOUT_STATUS: f'{attempt_msg}: Application {action} failed due to a timeout. \
            For more details, check the sysinv logs at /var/log/sysinv.log'
    }

    apps_msg = ''

    if updated_apps and status == IN_PROGRESS_STATUS:
        apps_msg += f"{action.capitalize()}d apps up to now: {', '.join(updated_apps)}."
    elif updated_apps and status == COMPLETED_STATUS:
        apps_msg += f"{action.capitalize()}d apps: {', '.join(updated_apps)}."

    if failed_apps:
        apps_msg += f"The following apps did not {action} correctly and require manual \
            intervention: {', '.join(failed_apps)}."

    progress_log = status_to_msg[status]

    if status in (FAILED_STATUS, ERROR_STATUS, TIMEOUT_STATUS):
        LOG.error(progress_log)
        if apps_msg:
            LOG.info(apps_msg)
        return

    LOG.info(progress_log)
    if apps_msg:
        LOG.info(apps_msg)


def check_apps_update_progress(client, action='update'):
    max_attempts = int(TIMEOUT_LIMIT_IN_MINUTES*60 / PROGRESS_CHECK_INTERVAL_IN_SECONDS)
    currently_attempt = 0
    while currently_attempt < max_attempts:
        try:
            response = client.kube_app.get_apps_update_status()
            status = NO_INFO_STATUS
            if response:
                status = response['status']

            log_progress(
                max_attempts,
                currently_attempt,
                status,
                response['failed_apps'],
                response['updated_apps'],
                action=action
            )
            if status == IN_PROGRESS_STATUS:
                sleep(PROGRESS_CHECK_INTERVAL_IN_SECONDS)
                currently_attempt += 1
            elif status == FAILED_STATUS:
                return False
            elif status == COMPLETED_STATUS:
                return True
            else:
                currently_attempt += 1
        except Exception as e:
            log_progress(
                max_attempts,
                currently_attempt,
                ERROR_STATUS,
                error_msg=e,
                action=action
            )
            sleep(PROGRESS_CHECK_INTERVAL_IN_SECONDS)
            currently_attempt += 1
    log_progress(max_attempts, currently_attempt, TIMEOUT_STATUS)
    return False


def main():
    action = sys.argv[3]
    if action in ('activate', 'activate-rollback'):
        configure_logging()
        try:
            client = get_sysinv_client()
            update_operation_result = False
            if action == 'activate':
                client.kube_app.update_all()
                sleep(5)
                update_operation_result = check_apps_update_progress(client)
            elif action == 'activate-rollback':
                if client.kube_app.get_all_apps_by_status('apply-failed'):
                    LOG.error(
                        "One or more applications are in 'apply-failed' status."
                        "Manual intervention is required."
                    )
                    return 1
                client.kube_app.rollback_all_apps()
                sleep(5)
                update_operation_result = check_apps_update_progress(client, 'revert')
            if update_operation_result:
                return 0
            return 1
        except Exception as e:
            LOG.error(e)
            return 1


if __name__ == "__main__":
    sys.exit(main())
