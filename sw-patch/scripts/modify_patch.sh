#!/bin/bash
#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

pushd `dirname $0` > /dev/null
SCRIPTPATH=`pwd`
popd > /dev/null

SWPATCH_DIR=$SCRIPTPATH/..

# Set environment variables for python
export PYTHONPATH=$SWPATCH_DIR/cgcs-patch
export PYTHONDONTWRITEBYTECODE=true

# Run the patch_build tool
exec $SWPATCH_DIR/bin/modify_patch "$@"

