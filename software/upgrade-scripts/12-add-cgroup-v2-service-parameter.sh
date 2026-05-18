#!/bin/bash
#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Adds cgroup_v2_enabled service parameter during upgrade activate.
# This runs after reboot when the system is fully up.
#

NAME=$(basename $0)
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

source /etc/platform/openrc 2>/dev/null

function log {
    echo "$(date -Iseconds | cut -d'+' -f1): ${NAME}[$$]: INFO: $*" >> "/var/log/software.log" 2>&1
}

log "Invoked from=$FROM_RELEASE to=$TO_RELEASE action=$ACTION"

if [[ "$ACTION" == "activate" ]]; then
    if system service-parameter-list --service platform --section config 2>/dev/null | grep -q cgroup_v2_enabled; then
        log "cgroup_v2_enabled already exists. Skipping."
    else
        system service-parameter-add platform config cgroup_v2_enabled=false
        if [ $? -eq 0 ]; then
            log "Added cgroup_v2_enabled=false service parameter."
        else
            log "ERROR: Failed to add cgroup_v2_enabled parameter."
        fi
    fi
fi

exit 0
