#!/bin/bash
#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Unified Software Management
# chkconfig: 345 20 23
# description: StarlingX Unified Software Management init script

### BEGIN INIT INFO
# Provides:          software
# Required-Start:    $syslog
# Required-Stop:     $syslog
# Default-Start:     2 3 5
# Default-Stop:      0 1 6
# Short-Description: software
# Description:       Provides the Unified Software Management component
### END INIT INFO

NAME=$(basename $0)

. /usr/bin/tsconfig
. /etc/platform/platform.conf

logfile=/var/log/software.log
software_install_failed_file=/var/run/software_install_failed
software_updated_during_init_file=/etc/software/.software_updated_during_init
node_is_software_updated_rr_file=/var/run/node_is_software_updated_rr

# if the system has never been bootstrapped, system_mode is not set
# treat a non bootstrapped system like it is simplex
# and manually manage lighttpd, etc..
if [ "${system_mode}" = "" ]; then
    system_mode="simplex"
fi

function LOG_TO_FILE {
    echo "`date "+%FT%T.%3N"`: $NAME: $*" >> $logfile
}

function check_for_rr_software_update {
    if [ -f ${node_is_software_updated_rr_file} ]; then
        if [ ! -f ${software_updated_during_init_file} ]; then
            echo
            echo "Node has had its software updated and requires an immediate reboot."
            echo
            LOG_TO_FILE "Node has had its software updated, with reboot-required flag set. Rebooting"
            touch ${software_updated_during_init_file}
            /sbin/reboot
        else
            echo
            echo "Node has had its software updated during init a second consecutive time. Skipping reboot due to possible error"
            echo
            LOG_TO_FILE "Node has had its software updated during init a second consecutive time. Skipping reboot due to possible error"
            touch ${software_install_failed_file}
            rm -f ${software_updated_during_init_file}
            exit 1
        fi
    else
        rm -f ${software_updated_during_init_file}
    fi
}

function check_install_uuid {
    # Check whether our installed load matches the active controller
    CONTROLLER_UUID=`curl -sf http://controller:${http_port}/feed/rel-${SW_VERSION}/install_uuid`
    if [ $? -ne 0 ]; then
        if [ "$HOSTNAME" = "controller-1" ]; then
            # If we're on controller-1, controller-0 may not have the install_uuid
            # matching this release, if we're in an upgrade. If the file doesn't exist,
            # bypass this check
            return 0
        fi

        LOG_TO_FILE "Unable to retrieve installation uuid from active controller"
        echo "Unable to retrieve installation uuid from active controller"
        return 1
    fi

    if [ "$INSTALL_UUID" != "$CONTROLLER_UUID" ]; then
        LOG_TO_FILE "This node is running a different load than the active controller and must be reinstalled"
        echo "This node is running a different load than the active controller and must be reinstalled"
        return 1
    fi

    return 0
}

# Check for installation failure
if [ -f /etc/platform/installation_failed ] ; then
    LOG_TO_FILE "/etc/platform/installation_failed flag is set. Aborting."
    echo "$(basename $0): Detected installation failure. Aborting."
    exit 1
fi

# For AIO-SX, abort if config is not yet applied and this is running in init
if [ "${system_mode}" = "simplex" -a ! -f ${INITIAL_CONTROLLER_CONFIG_COMPLETE} -a "$1" = "start" ]; then
    LOG_TO_FILE "Config is not yet applied. Skipping init software"
    exit 0
fi

# If the management interface is bonded, it may take some time
# before communications can be properly setup.
# Allow up to $DELAY_SEC seconds to reach controller.
DELAY_SEC=120
START=`date +%s`
FOUND=0
while [ $(date +%s) -lt $(( ${START} + ${DELAY_SEC} )) ]; do
    LOG_TO_FILE "Waiting for controller to be pingable"
    ping -c 1 controller > /dev/null 2>&1 || ping6 -c 1 controller > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        LOG_TO_FILE "controller is pingable"
        FOUND=1
        break
    fi
    sleep 1
done

if [ ${FOUND} -eq 0 ]; then
    # 'controller' is not available, just exit
    LOG_TO_FILE "Unable to contact active controller (controller). Boot will continue."
    exit 1
fi

RC=0
case "$1" in
    start)
        if [ "${system_mode}" = "simplex" ]; then
            # On a simplex CPE, we need to launch the http server first,
            # before we can do the software installation
            LOG_TO_FILE "***** Launching lighttpd *****"
            /etc/init.d/lighttpd start

            LOG_TO_FILE "***** Starting software operation *****"
            /usr/bin/software-agent --install 2>>$logfile
            if [ -f ${software_install_failed_file} ]; then
                RC=1
                LOG_TO_FILE "***** Software operation failed *****"
            fi
            LOG_TO_FILE "***** Finished software operation *****"

            LOG_TO_FILE "***** Shutting down lighttpd *****"
            /etc/init.d/lighttpd stop
        else
            check_install_uuid
            if [ $? -ne 0 ]; then
                # The INSTALL_UUID doesn't match the active controller, so exit
                exit 1
            fi

            LOG_TO_FILE "***** Starting software operation *****"
            /usr/bin/software-agent --install 2>>$logfile
            if [ -f ${software_install_failed_file} ]; then
                RC=1
                LOG_TO_FILE "***** Software operation failed *****"
            fi
            LOG_TO_FILE "***** Finished software operation *****"
        fi

        check_for_rr_software_update
        ;;
    stop)
        # Nothing to do here
        ;;
    restart)
        LOG_TO_FILE "***** Starting software operation *****"
        /usr/bin/software-agent --install 2>>$logfile
        if [ -f ${software_install_failed_file} ]; then
            RC=1
            LOG_TO_FILE "***** Software operation failed *****"
        fi
        LOG_TO_FILE "***** Finished software operation *****"
        ;;
    *)
        echo "Usage: $0 {start|stop|restart}"
        exit 1
esac

exit $RC

