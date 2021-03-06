#!/bin/bash
#
# Copyright (c) 2018-2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

SCRIPTPATH=$(dirname $(readlink -f $0))
CGCSPATCH_DIR=$SCRIPTPATH/../../cgcs-patch

# Source release-info
. $SCRIPTPATH/../../../utilities/utilities/build-info/release-info.inc
export PLATFORM_RELEASE

# Set environment variables for python
export PYTHONPATH=$CGCSPATCH_DIR/cgcs-patch
export PYTHONDONTWRITEBYTECODE=true

# Run the patch_build tool 
exec $CGCSPATCH_DIR/bin/patch_build "$@"

