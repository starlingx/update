#!/bin/bash
#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

script_dir=$(dirname $0)
shell_utils=${script_dir}/shell-utils
if [ -f $shell_utils ]; then
    source $shell_utils
else
    echo "ERROR: ${shell_utils} module not found."
    exit 1
fi

DEV_PATH=/dev
PLATFORM_PATH=/opt/platform
RABBIT_PATH=/var/lib/rabbitmq
POSTGRES_PATH=/var/lib/postgresql
KUBERNETES_PATH=/var/lib/kubernetes
PLATFORM_CONF_PATH=/etc/platform
TMP_PATH=/tmp
USR_PATH=/usr
ETC_PATH=/etc
PROC_PATH=/proc
LOG_PATH=/var/log

OSTREE_DEPLOYMENT_BRANCH="$1"

# src:dst
mount_points=(
    "${DEV_PATH}:${OSTREE_DEPLOYMENT_BRANCH}/${DEV_PATH}"
    "${PLATFORM_PATH}:${OSTREE_DEPLOYMENT_BRANCH}/${PLATFORM_PATH}"
    "${RABBIT_PATH}:${OSTREE_DEPLOYMENT_BRANCH}/${RABBIT_PATH}"
    "${POSTGRES_PATH}:${OSTREE_DEPLOYMENT_BRANCH}/${POSTGRES_PATH}"
    "${KUBERNETES_PATH}:${OSTREE_DEPLOYMENT_BRANCH}/${KUBERNETES_PATH}"
    "${PROC_PATH}:${OSTREE_DEPLOYMENT_BRANCH}/${PROC_PATH}"
    "${LOG_PATH}:${OSTREE_DEPLOYMENT_BRANCH}/${LOG_PATH}"
    "${OSTREE_DEPLOYMENT_BRANCH}/${USR_PATH}/${ETC_PATH}:${OSTREE_DEPLOYMENT_BRANCH}/${ETC_PATH}"
    "${PLATFORM_CONF_PATH}:${TMP_PATH}/${PLATFORM_CONF_PATH}"
)

# for upgrade from 22.12 only
# begin
source /etc/build.info
if [ ${SW_VERSION} == '22.12' ]; then
    mount_points=(
        "${DEV_PATH}:${OSTREE_DEPLOYMENT_BRANCH}/${DEV_PATH}"
        "${PLATFORM_PATH}:${OSTREE_DEPLOYMENT_BRANCH}/${PLATFORM_PATH}"
        "${RABBIT_PATH}:${OSTREE_DEPLOYMENT_BRANCH}/${RABBIT_PATH}"
        "${POSTGRES_PATH}:${OSTREE_DEPLOYMENT_BRANCH}/${POSTGRES_PATH}"
        "/usr/local/kubernetes/current/stage1:${OSTREE_DEPLOYMENT_BRANCH}/${KUBERNETES_PATH}/stage1"
        "/usr/local/kubernetes/current/stage2:${OSTREE_DEPLOYMENT_BRANCH}/${KUBERNETES_PATH}/stage2"
        "${PROC_PATH}:${OSTREE_DEPLOYMENT_BRANCH}/${PROC_PATH}"
        "${LOG_PATH}:${OSTREE_DEPLOYMENT_BRANCH}/${LOG_PATH}"
        "${OSTREE_DEPLOYMENT_BRANCH}/${USR_PATH}/${ETC_PATH}:${OSTREE_DEPLOYMENT_BRANCH}/${ETC_PATH}"
        "${PLATFORM_CONF_PATH}:${TMP_PATH}/${PLATFORM_CONF_PATH}"
    )
fi
# end

handle_error() {
    local exit_code="$1"
    local error_message="$2"

    log "$error_message" >&2
    log "Please check the error details and take appropriate action for recovery." >&2

    # attempt to unmount if there were successful mounts before the error
    umount_all

    exit "$exit_code"
}

mount_all() {
    for mnt in ${mount_points[@]}; do
        # split source and destination, squeeze multiple '/'
        src_dst=($(echo ${mnt//:/ } | tr -s "/"))
        src=${src_dst[0]}
        dst=${src_dst[1]}

        info "Bind mounting ${src} -> ${dst}"
        sudo mkdir -p ${dst}
        sudo mount --bind ${src} ${dst} || handle_error 1 "Failed to bind mount ${src} to ${dst}"
    done
    return 0
}

umount_all() {
    local rc=0
    for mnt in ${mount_points[@]}; do
        # split source and destination, squeeze multiple '/'
        src_dst=($(echo ${mnt//:/ } | tr -s "/"))
        src=${src_dst[0]}
        dst=${src_dst[1]}

        info "Unmounting $dst"
        umount_output=$(sudo umount -l $dst 2>&1)
        if [ $? -ne 0 ]; then
            # ignore messages that are not harmful
            if [[ ! $umount_output =~ ("not mounted"|"no mount point specified") ]]; then
                error "$umount_output"
                rc=1
            fi
        fi
    done
    return $rc
}

check_all() {
    local rc=0
    local mounted=()
    for mnt in ${mount_points[@]}; do
        # split source and destination, squeeze multiple '/'
        src_dst=($(echo ${mnt//:/ } | tr -s "/"))
        src=${src_dst[0]}
        dst=${src_dst[1]}

        mount | grep -w $dst 2>&1 > /dev/null
        if [[ $? -eq 0 ]]; then
            rc=1
            mounted+=(${dst})
        fi
    done
    if [[ ${#mounted[@]} -gt 0 ]]; then
        info "Mounted mount points:"
        for mnt in ${mounted[@]}; do
            info $mnt
        done
    fi
    return $rc
}

if [ -z "$1" ]; then
    error "OSTree deployment branch parameter is missing."
    exit 1
fi

if [[ $# -eq 2 ]]; then
    if [[ $2 == "-u" ]]; then
        umount_all
        rc=$?
    elif [[ $2 == "-c" ]]; then
        check_all
        rc=$?
    fi
else
    mount_all
    rc=$?
fi

exit $rc
