#!/bin/bash
#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#####################################################################
#
# This script sets the Maintenance Heartbeat period service parameter
# according to the release upgrade or rollback activate actions:
#
#   Upgrade  - To Release - 25.09 release - heartbeat_period=1000
#   Rollback - To Release - 24.09 release - heartbeat_period=100
#
# Performance Features to improve exeution time.
#
# 1. Only source openrc if its needed
# 2. If a service parameter apply change is required,
#    it is launched in the background asynchronously.
#    The script does not wait around.
#
# These features are seen to reduce execution time
# down to 4-5 seconds from 20-23 seconds.
#
# Assumptions: platform.conf and openrc are already part of the
#              environment passed to this script.
#
####################################################################
NAME=$(basename "$0")

# The script can be called with the start,
# migration, activation and delete actions
# with these parameters:
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

# List of supported actions
MY_SUPPORTED_ACTIONS=("activate" "activate-rollback")

# Safe valid action checker
is_valid_action=false
for action in "${MY_SUPPORTED_ACTIONS[@]}"; do
    if [[ "${ACTION}" == "${action}" ]]; then
        is_valid_action=true
        break
    fi
done

# Exit silently on unsupported actions
! ${is_valid_action} && exit 0

start_time=${SECONDS}

# The file to log to
SOFTWARE_LOG_PATH="/var/log/software.log"
PLATFORM_CONF_FILE="/etc/platform/platform.conf"
OPENRC_FILE="/etc/platform/openrc"

# Make this script's logging consistent
LOG_PREFIX="Maintenance Heartbeat Period"

# The desired heartbeat period in these releases
HEARTBEAT_PERIOD_24_09=100
HEARTBEAT_PERIOD_25_09=1000

function log {
    echo "$(date -Iseconds | cut -d'+' -f1): ${NAME}[$$]:  INFO: $*" >> "${SOFTWARE_LOG_PATH}" 2>&1
}

if [ $# -lt 3 ]; then
    error_str="Error: ${LOG_PREFIX} update script requires at least 3 arguments"
    echo "${error_str}"
    log  "${error_str}"
    usage_str="Usage: $0 'FROM_RELEASE' 'TO_RELEASE' 'ACTION'"
    echo "${usage_str}"
    log  "${usage_str}"
    exit 1
fi

function script_exit {
    delta=$((SECONDS-start_time))
    log "${LOG_PREFIX} service parameter update for ${ACTION} from ${FROM_RELEASE} to ${TO_RELEASE} - Completed in ${delta} secs"
    exit 0
}

# Backup plan if called without nodetype being set
if [ -z "${nodetype}" ]; then
    log "${LOG_PREFIX} need to source ${PLATFORM_CONF_FILE}"
    # shellcheck disable=SC1090
    source "${PLATFORM_CONF_FILE}"
fi

# Backup plan if called without required environment credentials
# Check to see if we need to source openrc
if [ -z "${OS_USERNAME+x}" ] || [ -z "${OS_PASSWORD+x}" ]; then
    if [ -e ${OPENRC_FILE} ]; then
        log "${LOG_PREFIX} need to source ${OPENRC_FILE}"
        # shellcheck disable=SC1090
        source "${OPENRC_FILE}" >/dev/null 2>&1
        rc=$?
        if [ "${rc}" -ne 0 ]; then
            log "No actions required for inactive controller"
            script_exit
        fi
    else
        log "${LOG_PREFIX} missing ${OPENRC_FILE} ... exiting"
        exit 1
    fi
fi

log "${LOG_PREFIX} ${ACTION} from ${FROM_RELEASE} to ${TO_RELEASE} - Start"

# shellcheck disable=SC2154
if [ "${nodetype}" = "controller" ]; then

    # Query the heartbeat period
    period=$(system service-parameter-list --service platform \
                                            --section maintenance \
                                            --name heartbeat_period \
                                            --format value | \
                                            awk '/heartbeat_period/ {print $5}')

    if ! [[ "${period}" =~ ^[0-9]+$ ]]; then
        log "Invalid heartbeat period: '${period}'"
        script_exit
    fi

    log "${LOG_PREFIX} current value is ${period}"

    if [ "${period}" -lt 100 ] || [ "${period}" -gt 1000 ]; then
        log "No actions required for invalid heartbeat period of '${period}'"
        script_exit
    fi

    # Case: Upgrade to 25.09
    if [[ "${ACTION}" == "activate" && "${TO_RELEASE}" == "25.09" ]]; then
        if [ "${period}" -ne "${HEARTBEAT_PERIOD_25_09}" ]; then
            system "service-parameter-modify" "platform" "maintenance" "heartbeat_period=${HEARTBEAT_PERIOD_25_09}" >/dev/null 2>&1
            rc=$?
            # shellcheck disable=SC2181
            if [ "${rc}" -eq 0 ]; then
                # Note: The service parameter apply operation is seen to take upwards
                #       of 10 seconds or more.
                #
                #       For this reason and that it is the last operation in the script
                #       a choice was made to post the apply in the background rather
                #       than wait around for inline completion before continuing.
                #
                #       The disown option was used in the background launch so that the
                #       apply continues even if this script exits (which it will).
                system service-parameter-apply platform >/dev/null 2>&1 & disown
                log "${LOG_PREFIX} service parameter apply change, from ${period} to ${HEARTBEAT_PERIOD_25_09}, posted to sysinv"
            fi
        else
            log "${LOG_PREFIX} no change required"
        fi
    elif [[ "${ACTION}" == "activate-rollback" && "${TO_RELEASE}" == "24.09" ]]; then

        if [ "${period}" -ne "${HEARTBEAT_PERIOD_24_09}" ]; then
            system "service-parameter-modify" "platform" "maintenance" "heartbeat_period=${HEARTBEAT_PERIOD_24_09}" >/dev/null 2>&1
            rc=$?
            # shellcheck disable=SC2181
            if [ "${rc}" -eq 0 ]; then
                # Posting ther apply operation. See Note above.
                system "service-parameter-apply" "platform" >/dev/null 2>&1 & disown
                log "${LOG_PREFIX} service parameter apply change, from ${period} to ${HEARTBEAT_PERIOD_24_09}, posted to sysinv"
            fi
        else
            log "${LOG_PREFIX} no change required"
        fi
    else
        log "No actions for ${ACTION} for ${FROM_RELEASE} to ${TO_RELEASE} transition"
    fi
else
    log "No actions required for ${nodetype}"
fi
script_exit
