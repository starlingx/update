#!/bin/bash
#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# When the rook ceph backend is configured, this script archives any daemon
# crashes that may have occurred during the upgrade, and restores the value
# of the mgr/crash/warn_recent_interval key that was modified at the
# beginning of the upgrade, at deploy-start.
#

# The script receives these parameters:
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

SOFTWARE_LOG_PATH="/var/log/software.log"
ROOK_CEPH_CONFIGURED_FLAG="/etc/platform/.node_rook_configured"

# Default logging method extracted from script #02
function log {
    echo "$(date -Iseconds | cut -d'+' -f1): ${NAME}[$$]: INFO: $*" \
        >> "${SOFTWARE_LOG_PATH}" 2>&1
}

# Script start
if [[ "${ACTION}" != "delete" ]]; then
    log "No actions required from ${FROM_RELEASE} to ${TO_RELEASE} with action ${ACTION}."
    exit 0
fi

# Checks if rook ceph is configured
if [ -f "$ROOK_CEPH_CONFIGURED_FLAG" ]; then
    # Archive rook ceph daemon crashes
    log "Archiving rook ceph daemon crashes.."
    ceph crash archive-all
    # Restore warn_recent_interval value
    warn_recent_interval=$(ceph config-key get usm/mgr/crash/warn_recent_interval 2>/dev/null)
    if [ $? -ne 0 ] || [ -z "$warn_recent_interval" ]; then
        warn_recent_interval="1209600"
    fi
    ceph config set mgr mgr/crash/warn_recent_interval "$warn_recent_interval"
    ceph config-key del usm/mgr/crash/warn_recent_interval > /dev/null 2>&1
    log "Successfully enabled rook ceph crash alarms."
else
    log "Rook Ceph backend is not configured. Skipping."
fi
exit 0
