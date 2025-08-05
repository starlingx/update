#!/bin/bash
#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

operation="apply"

if [[ "$1" == --operation=* ]]; then
    operation="${1#*=}"
fi

echo "### Start of pre-start script ###"

if [[ "$operation" == "apply" ]]; then
    echo "Running script while applying patch"
    # Put commands to run during apply here
else
    echo "Running script while removing patch"
    # Put commands to run during remove here
fi

echo "### End of pre-start script ###"

