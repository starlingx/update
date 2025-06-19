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


def start_update_of_all_apps(client):
    try:
        client.kube_app.update_all()
        return 0
    except Exception as e:
        LOG.error(f"ERROR: {e}")
        return 1


def log_progress(
    max_attempts,
    currently_attempt,
    status,
    failed_apps=[],
    updated_apps=[],
    error_msg=None
):
    attempt_msg = f"Update checking {currently_attempt + 1}/{max_attempts}:"
    interval_msg = f"Checking again in {PROGRESS_CHECK_INTERVAL_IN_SECONDS} second(s)."

    status_to_msg = {
        IN_PROGRESS_STATUS: f'{attempt_msg}: Application updates still in progress. {interval_msg}',
        FAILED_STATUS: f'{attempt_msg}: The application update process failed',
        COMPLETED_STATUS: f'{attempt_msg}: Application updates successfully finished.',
        NO_INFO_STATUS: f'{attempt_msg}: No info from the Application Framework regarding \
            application updates. {interval_msg}',
        ERROR_STATUS: f'{attempt_msg} failed with error: {error_msg}',
        TIMEOUT_STATUS: f'{attempt_msg}: Application updates failed due to a timeout. \
            For more details, check the sysinv logs at /var/log/sysinv.log'
    }

    apps_msg = ''

    if updated_apps and status == IN_PROGRESS_STATUS:
        apps_msg += f"Updated apps up to now: {', '.join(updated_apps)}."
    elif updated_apps and status == COMPLETED_STATUS:
        apps_msg += f"Updated apps: {', '.join(updated_apps)}."

    if failed_apps:
        apps_msg += f"The following apps did not update correctly and require manual \
            intervention: {', '.join(failed_apps)}."

    progress_log = status_to_msg[status]

    if status in ('failed', 'timeout', 'error'):
        LOG.error(progress_log)
        if apps_msg:
            LOG.info(apps_msg)
        return

    LOG.info(progress_log)
    if apps_msg:
        LOG.info(apps_msg)


def check_apps_update_progress(client):
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
                response['updated_apps']
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
                error_msg=e
            )
            sleep(PROGRESS_CHECK_INTERVAL_IN_SECONDS)
            currently_attempt += 1
    log_progress(max_attempts, currently_attempt, TIMEOUT_STATUS)
    return False


def main():
    action = sys.argv[3]
    if action == 'activate':
        configure_logging()
        client = get_sysinv_client()
        start_update_of_all_apps(client)
        sleep(5)
        update_operation_result = check_apps_update_progress(client)
        if update_operation_result:
            return 0
        return 1


if __name__ == "__main__":
    sys.exit(main())
