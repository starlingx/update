#!/bin/bash
#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# import common functions and constants
# file in update/software/service-files/software-functions
. /etc/software/software-functions

running="$BEFORE_REBOOT"
if [ -n "$1" ]; then
    running="$1"
fi

loginfo "### Start of post-install script running $running ###"

# Restart pods with stale mounts from the old ostree deployment.
# Only needed for in-service patching (no reboot). The node_is_software_updated_rr
# flag indicates a reboot is pending, so we skip the restart in that case.
NODE_IS_SOFTWARE_UPDATED_RR=/var/persist/software-agent/node_is_software_updated_rr
STALE_MOUNT_PODS="calico-node kube-multus multus-watcher"

restart_pods_with_stale_mounts() {
    for pod_name in ${STALE_MOUNT_PODS}; do
        container_ids=$(crictl ps -q --name "^${pod_name}$" 2>/dev/null)
        if [ -z "${container_ids}" ]; then
            loginfo "No running containers found for ${pod_name}"
            continue
        fi
        for cid in ${container_ids}; do
            loginfo "Restarting ${pod_name} container ${cid} to refresh mounts"
            crictl stop "${cid}" > /dev/null 2>&1 || \
                loginfo "Warning: failed to stop ${pod_name} container ${cid}"
        done
    done
}

if [[ "$running" == "$BEFORE_REBOOT" ]]; then
    loginfo "Running script before reboot (or in-service)"
    if [ ! -f ${NODE_IS_SOFTWARE_UPDATED_RR} ]; then
        loginfo "In-service patch detected, restarting pods with stale mounts"
        restart_pods_with_stale_mounts
    fi
else
    loginfo "Running script after reboot"
    # Put commands to run after reboot here
fi

loginfo "### End of post-install script ###"
exit $PATCH_STATUS_OK # in case of success
# exit $PATCH_STATUS_FAILED # in case of an error
