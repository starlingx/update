#! /bin/sh
#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

### BEGIN INIT INFO
# Description: usm-initialize
#
# Short-Description: USM initialize service.
# Provides: usm-initialize
# Required-Start:
# Required-Stop:
# Default-Start: 3 5
# Default-Stop: 3 5
### END INIT INFO

logfile="/var/log/software.log"
INITIAL_CONFIG_COMPLETE="/etc/platform/.initial_config_complete"
SERVICE_NAME="usm-initialize.service"
PXELINUX_SYMLINK="/var/pxeboot/pxelinux.cfg"

log() {
    echo "`date "+%FT%T.%3N"`: $0: $*" >> $logfile
}

set_presets() {
    . /etc/platform/platform.conf
    if [ "${system_type}" == "All-in-one" ] ; then
        log "AIO System"
        if [[ "${subfunction}" =~ "lowlatency" ]] ; then
            log "System is lowlatency"
            ln -sf /usr/share/systemd-presets/lowlatency.preset /etc/systemd/system-preset/10-aio.preset
        else
            ln -sf /usr/share/systemd-presets/aio.preset /etc/systemd/system-preset/10-aio.preset
        fi
    else
        log "Standard System"
        log "Setting ${nodetype} preset"
        if [[ "${nodetype}" == "worker" ]] ; then
            if [[ "${subfunction}" =~ "lowlatency" ]] ; then
                log "System is lowlatency"
                ln -sf /usr/share/systemd-presets/worker-lowlatency.preset /etc/systemd/system-preset/10-worker.preset
            else
                ln -sf /usr/share/systemd-presets/worker.preset /etc/systemd/system-preset/10-worker.preset
            fi
        elif [ "${nodetype}" == "storage" ] ; then
            ln -sf /usr/share/systemd-presets/storage.preset /etc/systemd/system-preset/10-storage.preset
        else
            ln -sf /usr/share/systemd-presets/controller.preset /etc/systemd/system-preset/10-controller.preset
        fi
    fi

    systemctl daemon-reload
    systemctl preset-all --preset-mode=full
}

reset_initial_config_complete() {
    if [[ -f ${INITIAL_CONFIG_COMPLETE} ]]; then
        log "Removing ${INITIAL_CONFIG_COMPLETE}"
        rm ${INITIAL_CONFIG_COMPLETE} || log "Failed to remove ${INITIAL_CONFIG_COMPLETE}"
    fi
}

disable_service() {
    systemctl disable $SERVICE_NAME
    rc=$?
    if [ $rc -ne 0 ]; then
        log "Failed to disable $SERVICE_NAME"
    else
        log "Disabled $SERVICE_NAME"
    fi
}

remove_pxelinux_symlink() {
    if [[ -h $PXELINUX_SYMLINK ]]; then
        unlink $PXELINUX_SYMLINK
        log "Removed ${PXELINUX_SYMLINK} symlink"
    fi
}

start() {
    set_presets
    reset_initial_config_complete
    disable_service
    remove_pxelinux_symlink
}

case "$1" in
    start)
        start
        exit 0
        ;;
    stop)
        ;;
    status)
        ;;
    restart)
        ;;
    reload)
        ;;
    force-reload)
        ;;
    *)
esac

exit 0
