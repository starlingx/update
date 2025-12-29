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

if [[ "$running" == "$BEFORE_REBOOT" ]]; then
    loginfo "Running script before reboot (or in-service)"
    # Put commands to run before reboot here
else
    loginfo "Running script after reboot"
    # Put commands to run after reboot here
fi

loginfo "### End of post-install script ###"
exit $PATCH_STATUS_OK # in case of success
# exit $PATCH_STATUS_FAILED # in case of an error
