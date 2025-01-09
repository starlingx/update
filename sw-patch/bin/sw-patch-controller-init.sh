#!/bin/bash
#
# Copyright (c) 2014-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# StarlingX Patching Controller setup
# chkconfig: 345 20 24
# description: CGCS Patching Controller init script

### BEGIN INIT INFO
# Provides:          sw-patch-controller
# Required-Start:    $syslog
# Required-Stop:     $syslog
# Default-Start:     2 3 5
# Default-Stop:      0 1 6
# Short-Description: sw-patch-controller
# Description:       Provides the StarlingX Patch Controller Daemon
### END INIT INFO

. /usr/bin/tsconfig

NAME=$(basename $0)

REPO_ID=updates
REPO_ROOT=/var/www/pages/${REPO_ID}
REPO_DIR=${REPO_ROOT}/rel-${SW_VERSION}
GROUPS_FILE=$REPO_DIR/comps.xml
PATCHING_DIR=/opt/patching

logfile=/var/log/patching.log

function LOG {
    logger "$NAME: $*"
    echo "`date "+%FT%T.%3N"`: $NAME: $*" >> $logfile
}

function LOG_TO_FILE {
    echo "`date "+%FT%T.%3N"`: $NAME: $*" >> $logfile
}

function do_setup {
    # Does the repo exist?
    if [ ! -d $REPO_DIR ]; then
        LOG "Creating repo. UNDER CONSTRUCTION for OSTREE"
        mkdir -p $REPO_DIR

        # The original Centos code would create the groups and call createrepo
        # todo(jcasteli): determine if the ostree code needs a setup also
    fi

    if [ ! -d $PATCHING_DIR ]; then
        LOG "Creating $PATCHING_DIR"
        mkdir -p $PATCHING_DIR
    fi

    # If we can ping the active controller, sync the repos
    LOG_TO_FILE "ping -c 1 -w 1 controller"
    ping -c 1 -w 1 controller >> $logfile 2>&1 || ping6 -c 1 -w 1 controller >> $logfile 2>&1
    if [ $? -ne 0 ]; then
        LOG "Cannot ping controller. Nothing to do"
        return 0
    fi

    # Sync the patching dir
    LOG_TO_FILE "rsync -acv --delete rsync://controller/patching/ ${PATCHING_DIR}/"
    rsync -acv --delete rsync://controller/patching/ ${PATCHING_DIR}/ >> $logfile 2>&1

    # sync the repo from peer controller if both are running the same sw_version
    tmp_dir=$(mktemp -d)
    rsync -acv rsync://controller/platform/platform.conf ${tmp_dir}
    my_tag="^sw_version=${SW_VERSION}$"
    grep ${my_tag} ${tmp_dir}/platform.conf
    rc=$?
    rm ${tmp_dir}/platform.conf
    rmdir ${tmp_dir}

    if [ ${rc} -eq 0 ]; then
        # Sync the repo dir
        LOG_TO_FILE "rsync -acv --delete rsync://controller/repo/ ${REPO_ROOT}/"
        rsync -acv --delete rsync://controller/repo/ ${REPO_ROOT}/ >> $logfile 2>&1
    else
        LOG "Skip rsync. Peer is not running the same software version"
    fi
}

case "$1" in
    start)
        do_setup
        ;;
    status)
        ;;
    stop)
        # Nothing to do here
        ;;
    restart)
        do_setup
        ;;
    *)
        echo "Usage: $0 {status|start|stop|restart}"
        exit 1
esac

exit 0

