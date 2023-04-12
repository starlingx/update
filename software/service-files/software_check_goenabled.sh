#!/bin/bash
#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# Software "goenabled" check.
# If a minor software release version has been applied on this node,
# it is now out-of-date and should be rebooted.

NAME=$(basename $0)
SYSTEM_CHANGED_FLAG=/var/run/node_is_patched

logfile=/var/log/software.log

function LOG {
    logger "$NAME: $*"
    echo "`date "+%FT%T.%3N"`: $NAME: $*" >> $logfile
}

if [ -f $SYSTEM_CHANGED_FLAG ]; then
    LOG "Node has been patched. Failing goenabled check."
    exit 1
fi

exit 0

