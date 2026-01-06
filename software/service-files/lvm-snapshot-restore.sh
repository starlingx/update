#!/bin/bash
#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
### BEGIN INIT INFO
# Description: lvm-snapshot-restore
#
# Short-Description: Restore LVM Snapshots
# Provides: lvm-snapshot-restore
# Required-Start:
# Required-Stop:
# Default-Start: 3 5
# Default-Stop: 3 5
### END INIT INFO

NAME=$(basename $0)
LOG_FILE="/var/log/lvm-snapshot-restore.log"
RESTORE_SCRIPT="/usr/sbin/software-deploy/manage-lvm-snapshots"

# Function to log messages to both stdout and log file
log() {
    echo "$(date '+%FT%T.%3N'): $NAME: $*" >> $LOG_FILE
}

# Detect if the system booted into the previous deployment
if ! grep -q "ostree=/ostree/2" /proc/cmdline; then
    log "System is not booted from the rollback deployment."
    exit 0
fi
log "System is booted from rollback deployment."

# Verify if deployed commit-id matches rollback ostree commit-id
source /etc/build.info
log "Rollback major release version is ${SW_VERSION}"
DEPLOYED_COMMIT_ID=$(ostree admin status | grep "^\*" | awk '{ sub(/\.[0-9]+/, "", $3); print $3 }')
ROLLBACK_COMMIT_ID=$(ostree --repo=/var/www/pages/feed/rel-${SW_VERSION}/ostree_repo rev-parse starlingx)
if [ ! $DEPLOYED_COMMIT_ID = $ROLLBACK_COMMIT_ID ]; then
    log "Deployed ostree commit-id doesn't match ${SW_VERSION} ostree commit-id"
    exit 0
fi

log "Checking LVM snapshots..."
${RESTORE_SCRIPT} --list
if [ $? -ne 0 ]; then
    log "No LVM snapshots to restore."
    exit 0
fi

log "Starting LVM snapshot restore..."
${RESTORE_SCRIPT} --restore

if [ $? -eq 0 ]; then
    log "All LVM snapshots restored successfully. Rebooting..."
    reboot
else
    log "Couldn't restore the LVM snapshots, lvdisplay output:"
    log "$(lvdisplay)"
    log "Check software.log for more details."
    exit 1
fi

exit 0
