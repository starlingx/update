#!/bin/bash
#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# import common functions and constants
# file in update/software/service-files/software-functions
. /etc/software/software-functions

loginfo "### Start of pre-install script ###"

# Put commands here

loginfo "### End of pre-install script ###"
exit $PATCH_STATUS_OK # in case of success
# exit $PATCH_STATUS_FAILED # in case of an error
