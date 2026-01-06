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

patch="24.09.400"
patch_migration_script_dir="/etc/update.d"
activate_script_name="01-restart-services.py"
extra_script="/opt/software/rel-${patch}/extra/${activate_script_name}"

if [[ "$operation" == "apply" ]]; then
    echo "Running script while applying patch"
    # Put commands to run during apply here
else
    echo "Running script while removing patch"
    # Put commands to run during remove here
fi

# WA to upload the activate script
echo "Copying activate script"
if [[ -f "$extra_script" ]]; then
    # Ensure the directory exists
    mkdir -p "$patch_migration_script_dir"

    cp "$extra_script" "${patch_migration_script_dir}/${activate_script_name}"
    chmod +x "${patch_migration_script_dir}/${activate_script_name}"
    echo "Copied ${activate_script_name} to ${patch_migration_script_dir}"
else
    echo "Error: ${extra_script} not found"
fi

echo "### End of pre-start script ###"

