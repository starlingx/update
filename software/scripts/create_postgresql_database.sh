#!/bin/bash
#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#
# This script is used create a 2nd instance of postgres on a DX upgrade.
# It needs the port number as parameter and it should be different from the default.


DEFAULT_POSTGRESQL_PORT=5432
POSTGRESQL_PATH=/var/lib/postgresql
POSTGRESQL_BIN_DIR=$(pg_config --bindir)
POSTGRESQL_RUNTIME=/var/run/postgresql
INFO_FILE=/etc/build.info

if [ -z "$1" ]; then
    echo "Error: Port parameter is missing."
    exit 1
fi

PORT="$1"

# Prevent issues with the default postgres port
if [ "$PORT" -eq "$DEFAULT_POSTGRESQL_PORT" ]; then
    echo "Error: Port number should be different from the default."
    exit 1
fi

cleanup_and_exit() {
    local exit_code="$1"
    local error_message="$2"

    echo "Error: $error_message" >&2
    echo "Please check the error details and take appropriate action for recovery." >&2

    exit "$exit_code"
}

SW_VERSION=$(grep -o 'SW_VERSION="[0-9\.]*"' "$INFO_FILE" | cut -d '"' -f 2) ||
    cleanup_and_exit 1 "Failed to get software version"

POSTGRESQL_DATA_DIR=$POSTGRESQL_PATH/$SW_VERSION

# Remove existing data directory
rm -rf "$POSTGRESQL_DATA_DIR" ||
    cleanup_and_exit 1 "Failed to remove existing data directory: $POSTGRESQL_DATA_DIR"

mkdir -p "$POSTGRESQL_DATA_DIR" ||
    cleanup_and_exit 1 "Failed to create data directory: $POSTGRESQL_DATA_DIR"

chown postgres "$POSTGRESQL_DATA_DIR" ||
    cleanup_and_exit 1 "Failed to change ownership of data directory: $POSTGRESQL_DATA_DIR"

sudo -u postgres "$POSTGRESQL_BIN_DIR/initdb" -D "$POSTGRESQL_DATA_DIR" ||
    cleanup_and_exit 1 "Failed to initialize the PostgreSQL database"

chmod 700 "$POSTGRESQL_DATA_DIR" ||
    cleanup_and_exit 1 "Failed to set permissions for data directory: $POSTGRESQL_DATA_DIR"

chown postgres "$POSTGRESQL_DATA_DIR" ||
    cleanup_and_exit 1 "Failed to change ownership of data directory: $POSTGRESQL_DATA_DIR"

mkdir -p "$POSTGRESQL_RUNTIME" ||
    cleanup_and_exit 1 "Failed to create runtime directory: ${POSTGRESQL_RUNTIME}"

chown postgres "$POSTGRESQL_RUNTIME" ||
    cleanup_and_exit 1 "Failed to change ownership of runtime directory: ${POSTGRESQL_RUNTIME}"

sudo -u postgres "$POSTGRESQL_BIN_DIR/pg_ctl" -D "$POSTGRESQL_DATA_DIR" -o "-F -p $PORT" start ||
    cleanup_and_exit 1 "Failed to start PostgreSQL"

exit 0
