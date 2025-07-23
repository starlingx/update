#!/bin/bash
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script runs ceph mon enable-msgr2 on activate for upgrade
# and delete for rollback.
# This is necessary because ceph-mon is being reconfigured
# during agent-hooks run and msgr2 can only be enabled after
# host unlock.
#

NAME=$(basename "$0")

# The migration scripts are passed these parameters:
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

FROM_RELEASE_ARR=(${FROM_RELEASE//./ })
FROM_RELEASE_MAJOR=${FROM_RELEASE_ARR[0]}
TO_RELEASE_ARR=(${TO_RELEASE//./ })
TO_RELEASE_MAJOR=${TO_RELEASE_ARR[0]}

SOFTWARE_LOG_PATH="/var/log/software.log"

function log {
    echo "$(date -Iseconds | cut -d'+' -f1): ${NAME}[$$]: INFO: $*" >> "${SOFTWARE_LOG_PATH}" 2>&1
}

log "ceph-mon: enable ceph-mon msgr2"\
    "from $FROM_RELEASE to $TO_RELEASE with action $ACTION"

if [[ "$ACTION" == "activate" && ${TO_RELEASE_MAJOR} -eq 25 ]] || \
   [[ "$ACTION" == "delete"  && ${TO_RELEASE_MAJOR} -eq 24 ]]; then
    source /etc/platform/platform.conf
    if [[ "${system_mode}" == "simplex" ]]; then
        if [[ -f /etc/platform/.node_ceph_configured ]]; then
            timeout 30 ceph mon enable-msgr2
            status=$?
            if [ ${status} != 0 ]; then
                log "ceph-mon: 'timeout 30 ceph mon enable-msgr2' command failed with exit status ${RC}"
                exit 1
            else
                log "ceph-mon: enabling msgr2 succeeded"
            fi
        else
            log "ceph-mon: no actions required, bare metal ceph not configured"
        fi
    else
        log "ceph-mon: no actions required for ${system_mode}"
    fi
else
    log "ceph-mon: no actions required from release ${FROM_RELEASE} to ${TO_RELEASE} with action ${ACTION}"
fi

exit 0
