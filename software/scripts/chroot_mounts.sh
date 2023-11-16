#!/bin/bash
#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

DEV_PATH=/dev
PLATFORM_PATH=/opt/platform
RABBIT_PATH=/var/lib/rabbitmq
POSTGRES_PATH=/var/lib/postgresql
PLATFORM_CONF_PATH=/etc/platform
TMP_PATH=/tmp
USR_PATH=/usr
ETC_PATH=/etc
PROC_PATH=/proc
LOG_PATH=/var/log

mount_points=(
    "$DEV_PATH"
    "$PLATFORM_PATH"
    "$RABBIT_PATH"
    "$POSTGRES_PATH"
    "$PROC_PATH"
    "$LOG_PATH"
)

OSTREE_DEPLOYMENT_BRANCH="$1"

handle_error() {
    local exit_code="$1"
    local error_message="$2"

    echo "Error: $error_message" >&2
    echo "Please check the error details and take appropriate action for recovery." >&2

    exit "$exit_code"
}

mount_all() {
    for dir in "${mount_points[@]}"; do
        target_dir=$OSTREE_DEPLOYMENT_BRANCH$dir
        if [ ! -d "$target_dir" ]; then
            sudo mkdir -p "$target_dir"
        fi
        echo "mount --bind $dir $target_dir"
        sudo mount --bind "$dir" "$target_dir" ||
            handle_error 1 "Failed to bind mount $dir to $target_dir"
    done

    if [ ! -d "$TMP_PATH$PLATFORM_CONF_PATH" ]; then
        mkdir -p "$TMP_PATH$PLATFORM_CONF_PATH"
    fi

    echo "mkdir $OSTREE_DEPLOYMENT_BRANCH/etc -p"
    sudo mkdir $OSTREE_DEPLOYMENT_BRANCH/etc -p
    echo "mount --bind $OSTREE_DEPLOYMENT_BRANCH$USR_PATH$ETC_PATH $OSTREE_DEPLOYMENT_BRANCH$ETC_PATH"
    sudo mount --bind "$OSTREE_DEPLOYMENT_BRANCH$USR_PATH$ETC_PATH" "$OSTREE_DEPLOYMENT_BRANCH$ETC_PATH" ||
        handle_error 1 "Failed to bind mount $OSTREE_DEPLOYMENT_BRANCH$USR_PATH$ETC_PATH to
        $OSTREE_DEPLOYMENT_BRANCH$ETC_PATH"

    echo "mount --bind $PLATFORM_CONF_PATH $TMP_PATH$PLATFORM_CONF_PATH"
    sudo mount --bind "$PLATFORM_CONF_PATH" "$TMP_PATH$PLATFORM_CONF_PATH" ||
        handle_error 1 "Failed to bind mount $PLATFORM_CONF_PATH to $TMP_PATH$PLATFORM_CONF_PATH"
}

umount_all() {
    for dir in "${mount_points[@]}"; do
        target_dir=$OSTREE_DEPLOYMENT_BRANCH$dir
        echo "sudo umount $target_dir"
        sudo umount $target_dir
    done

    sudo umount $OSTREE_DEPLOYMENT_BRANCH$ETC_PATH
    sudo umount $TMP_PATH$PLATFORM_CONF_PATH
}


if [ -z "$1" ]; then
    echo "Error: Ostree deployment branch parameter is missing."
    exit 1
fi

if [[ $# -eq 2 && $2 == "-u" ]]; then
    umount_all
else
    mount_all
fi
