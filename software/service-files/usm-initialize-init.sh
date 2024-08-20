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

. /etc/platform/platform.conf
export controller=false
export worker=false
export storage=false

if [ "${nodetype}" == "controller" ]; then
    controller=true
    if [ "${subfunction}" == "controller,worker" ]; then
        worker=true
    fi
fi

if [ "${nodetype}" == "worker" ]; then
    worker=true
fi

if [ "${nodetype}" == "storage" ]; then
    storage=true
fi

log() {
    echo "`date "+%FT%T.%3N"`: $0: $*" >> $logfile
}

set_presets() {
    log "apply preset"
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

refresh_init_links() {
    log "setup goenable and host config"
    # below should be identical to kickstart.cfg operations, as if setting up from a fresh install
    if [ ! "${controller}" = true -a "${worker}" = true ] ; then
        ln -s /etc/goenabled.d/config_goenabled_check.sh.worker /etc/goenabled.d/config_goenabled_check.sh
        ln -s /dev/null /etc/systemd/system/controllerconfig.service
        ln -s /dev/null /etc/systemd/system/storageconfig.service
    elif [ "${storage}" = true ] ; then
        ln -s /etc/goenabled.d/config_goenabled_check.sh.storage /etc/goenabled.d/config_goenabled_check.sh
        ln -s /dev/null /etc/systemd/system/controllerconfig.service
        ln -s /dev/null /etc/systemd/system/workerconfig.service
    elif [ "${controller}" = true ] ; then
        ln -s /etc/goenabled.d/config_goenabled_check.sh.controller /etc/goenabled.d/config_goenabled_check.sh
        ln -s /dev/null /etc/systemd/system/workerconfig.service
        ln -s /dev/null /etc/systemd/system/storageconfig.service
    fi

    chmod 700 /etc/goenabled.d/config_goenabled_check.sh

    log "Refresh /etc/pmon.d"
    rm -rf /etc/pmon.d
    mkdir /etc/pmon.d -p

    # below create pmon link for new pmon monitored daemons
    if [ "${controller}" = true ] ; then
        ln -s /usr/share/starlingx/pmon.d/acpid.conf /etc/pmon.d/acpid.conf
        ln -s /usr/share/starlingx/pmon.d/containerd.conf /etc/pmon.d/containerd.conf
        ln -s /usr/share/starlingx/pmon.d/docker.conf /etc/pmon.d/docker.conf
        ln -s /usr/share/starlingx/pmon.d/fm-api.conf /etc/pmon.d/fm-api.conf
        ln -s /usr/share/starlingx/pmon.d/fsmon.conf /etc/pmon.d/fsmon.conf
        ln -s /usr/share/starlingx/pmon.d/hbsAgent.conf /etc/pmon.d/hbsAgent.conf
        ln -s /usr/share/starlingx/pmon.d/hbsClient.conf /etc/pmon.d/hbsClient.conf
        ln -s /usr/share/starlingx/pmon.d/lmon.conf /etc/pmon.d/lmon.conf
        ln -s /usr/share/starlingx/pmon.d/logmgmt /etc/pmon.d/logmgmt
        ln -s /usr/share/starlingx/pmon.d/mtcClient.conf /etc/pmon.d/mtcClient.conf
        ln -s /usr/share/starlingx/pmon.d/mtcalarm.conf /etc/pmon.d/mtcalarm.conf
        ln -s /usr/share/starlingx/pmon.d/mtclogd.conf /etc/pmon.d/mtclogd.conf
        ln -s /usr/share/starlingx/pmon.d/sm-api.conf /etc/pmon.d/sm-api.conf
        ln -s /usr/share/starlingx/pmon.d/sm-eru.conf /etc/pmon.d/sm-eru.conf
        ln -s /usr/share/starlingx/pmon.d/sm.conf /etc/pmon.d/sm.conf
        ln -s /usr/share/starlingx/pmon.d/sshd.conf /etc/pmon.d/sshd.conf
        ln -s /usr/share/starlingx/pmon.d/sssd.conf /etc/pmon.d/sssd.conf
        ln -s /usr/share/starlingx/pmon.d/sw-patch-agent.conf /etc/pmon.d/sw-patch-agent.conf
        ln -s /usr/share/starlingx/pmon.d/sw-patch-controller-daemon.conf /etc/pmon.d/sw-patch-controller-daemon.conf
        ln -s /usr/share/starlingx/pmon.d/sysinv-agent.conf /etc/pmon.d/sysinv-agent.conf
        ln -s /usr/share/starlingx/pmon.d/syslog-ng.conf /etc/pmon.d/syslog-ng.conf
        ln -s /usr/share/starlingx/pmon.d/luks.conf /etc/pmon.d/luks.conf
        ln -s /usr/share/starlingx/pmon.d/ipsec-server.conf /etc/pmon.d/ipsec-server.conf
        ln -s /usr/share/starlingx/pmon.d/software-controller-daemon.conf /etc/pmon.d/software-controller-daemon.conf
        ln -s /usr/share/starlingx/pmon.d/software-agent.conf /etc/pmon.d/software-agent.conf
    fi
    if [ "${worker}" = true ] ; then
        ln -s /usr/share/starlingx/pmon.d/acpid.conf /etc/pmon.d/acpid.conf
        ln -s /usr/share/starlingx/pmon.d/containerd.conf /etc/pmon.d/containerd.conf
        ln -s /usr/share/starlingx/pmon.d/docker.conf /etc/pmon.d/docker.conf
        ln -s /usr/share/starlingx/pmon.d/fsmon.conf /etc/pmon.d/fsmon.conf
        ln -s /usr/share/starlingx/pmon.d/hbsClient.conf /etc/pmon.d/hbsClient.conf
        ln -s /usr/share/starlingx/pmon.d/isolcpu_plugin.conf /etc/pmon.d/isolcpu_plugin.conf
        ln -s /usr/share/starlingx/pmon.d/lmon.conf /etc/pmon.d/lmon.conf
        ln -s /usr/share/starlingx/pmon.d/logmgmt /etc/pmon.d/logmgmt
        ln -s /usr/share/starlingx/pmon.d/mtcClient.conf /etc/pmon.d/mtcClient.conf
        ln -s /usr/share/starlingx/pmon.d/mtcalarm.conf /etc/pmon.d/mtcalarm.conf
        ln -s /usr/share/starlingx/pmon.d/mtclogd.conf /etc/pmon.d/mtclogd.conf
        ln -s /usr/share/starlingx/pmon.d/sm-eru.conf /etc/pmon.d/sm-eru.conf
        ln -s /usr/share/starlingx/pmon.d/sshd.conf /etc/pmon.d/sshd.conf
        ln -s /usr/share/starlingx/pmon.d/sssd.conf /etc/pmon.d/sssd.conf
        ln -s /usr/share/starlingx/pmon.d/sw-patch-agent.conf /etc/pmon.d/sw-patch-agent.conf
        ln -s /usr/share/starlingx/pmon.d/sysinv-agent.conf /etc/pmon.d/sysinv-agent.conf
        ln -s /usr/share/starlingx/pmon.d/syslog-ng.conf /etc/pmon.d/syslog-ng.conf
    fi
    if [ "${storage}" = true ] ; then
        ln -s /usr/share/starlingx/pmon.d/acpid.conf /etc/pmon.d/acpid.conf
        ln -s /usr/share/starlingx/pmon.d/containerd.conf /etc/pmon.d/containerd.conf
        ln -s /usr/share/starlingx/pmon.d/docker.conf /etc/pmon.d/docker.conf
        ln -s /usr/share/starlingx/pmon.d/fsmon.conf /etc/pmon.d/fsmon.conf
        ln -s /usr/share/starlingx/pmon.d/hbsClient.conf /etc/pmon.d/hbsClient.conf
        ln -s /usr/share/starlingx/pmon.d/lmon.conf /etc/pmon.d/lmon.conf
        ln -s /usr/share/starlingx/pmon.d/logmgmt /etc/pmon.d/logmgmt
        ln -s /usr/share/starlingx/pmon.d/mtcClient.conf /etc/pmon.d/mtcClient.conf
        ln -s /usr/share/starlingx/pmon.d/mtcalarm.conf /etc/pmon.d/mtcalarm.conf
        ln -s /usr/share/starlingx/pmon.d/mtclogd.conf /etc/pmon.d/mtclogd.conf
        ln -s /usr/share/starlingx/pmon.d/sm-eru.conf /etc/pmon.d/sm-eru.conf
        ln -s /usr/share/starlingx/pmon.d/sshd.conf /etc/pmon.d/sshd.conf
        ln -s /usr/share/starlingx/pmon.d/sssd.conf /etc/pmon.d/sssd.conf
        ln -s /usr/share/starlingx/pmon.d/sw-patch-agent.conf /etc/pmon.d/sw-patch-agent.conf
        ln -s /usr/share/starlingx/pmon.d/sysinv-agent.conf /etc/pmon.d/sysinv-agent.conf
        ln -s /usr/share/starlingx/pmon.d/syslog-ng.conf /etc/pmon.d/syslog-ng.conf
    fi
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
    refresh_init_links
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
