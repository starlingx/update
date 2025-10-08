#!/bin/bash
#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# Source platform.conf, for nodetype and subfunctions
. /etc/platform/platform.conf

PATCH_STATUS_OK=0
PATCH_STATUS_FAILED=1

logfile="/var/log/software.log"
NAME=$(basename "$0")

CREDENTIAL_FILE="/opt/platform/.keyring/24.09/.CREDENTIAL"
BOOTSTRAP_COMPLETED_FLAG="/etc/platform/.bootstrap_completed"
INITIAL_CONFIG_COMPLETE_FLAG="/etc/platform/.initial_config_complete"
RESTART_SERVICES_FLAG="/run/software/.activate.restart-services.flag"
PUPPET_GRUB_SCRIPT="/usr/local/bin/puppet-update-grub-env.py"

loginfo() {
    echo "$(date "+%FT%T.%3N"): $NAME: $*" >> "$logfile"
}

is_active_controller() {
    [[ "$nodetype" == "controller" && -f "$CREDENTIAL_FILE" ]]
}

is_standby_controller() {
    [[ "$nodetype" == "controller" &&  ! -f "$CREDENTIAL_FILE" ]]
}

not_controller() {
    [[ "$nodetype" != "controller" ]]
}

is_dc_central_controller() {
    [[ "$nodetype" == "controller" && "$distributed_cloud_role" == "systemcontroller" ]]
}

# Check if /etc is a bind mount
BIND_SOURCE=$(findmnt /etc -n -o SOURCE)
if [[ -z "$BIND_SOURCE" ]]; then
    loginfo "Not an inservice patch, exiting"
    exit "$PATCH_STATUS_OK"
fi

# Pre-bootstrap does not need to restart services since it will be unlocked later
if [ ! -f "$BOOTSTRAP_COMPLETED_FLAG" ] && [ ! -f "$INITIAL_CONFIG_COMPLETE_FLAG"]; then
    loginfo "Pre-bootstrap, exiting"
    exit "$PATCH_STATUS_OK"
fi

### Update kernel.env
if [[ $subfunction =~ "lowlatency" ]]; then
    $PUPPET_GRUB_SCRIPT --set-kernel-lowlatency
else
    $PUPPET_GRUB_SCRIPT --set-kernel-standard
fi

### Services to restart in all nodes
# Set flag to restart software-agent
touch /run/software/.restart.software-agent

### Services to restart in DC's Central Controllers
if is_dc_central_controller; then
    sm-restart-safe service dcmanager-manager
    sm-restart-safe service dcmanager-api
    sm-restart-safe service dcmanager-orchestrator

    # Do not exit yet.
fi

### Services to restart only in the active controller
if is_active_controller; then
    loginfo "Running in the active controller"

    # Let a flag for vim, vim-api, and software-controller
    # services to be restarted during activate
    touch "$RESTART_SERVICES_FLAG"

    sm-restart-safe service sysinv-conductor

    exit "$PATCH_STATUS_OK"
fi

### Services to restart only in the standby controller
if is_standby_controller; then
    loginfo "Running in the standby controller"

    # It is safe to restart software-controller in the standby controller
    pmon-restart software-controller-daemon

    exit "$PATCH_STATUS_OK"
fi

### Services to restart only in non-controller nodes
if not_controller; then
    loginfo "Running in non-controller node"

    exit "$PATCH_STATUS_OK"
fi

exit "$PATCH_STATUS_OK"
