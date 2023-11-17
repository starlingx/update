#!/bin/bash
#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# StarlingX Patching Controller setup
# chkconfig: 345 20 24
# description: CGCS Patching Controller init script

### BEGIN INIT INFO
# Provides:          software-controller
# Required-Start:    $syslog
# Required-Stop:     $syslog
# Default-Start:     2 3 5
# Default-Stop:      0 1 6
# Short-Description: software-controller
# Description:       Provides the Unified Software Management Controller Daemon
### END INIT INFO

. /usr/bin/tsconfig

NAME=$(basename $0)

REPO_ID=updates
REPO_ROOT=/var/www/pages/${REPO_ID}
REPO_DIR=${REPO_ROOT}/debian/rel-${SW_VERSION}
GROUPS_FILE=$REPO_DIR/comps.xml
PATCHING_DIR=/opt/software
RELEASE=bullseye

logfile=/var/log/software.log

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
        LOG "Creating repo."

        # TODO(cshort) Remove this once gpg support is added.
        sed -i '$a gpg-verify=false' \
            /var/www/pages/feed/rel-${SW_VERSION}/ostree_repo/config
        sed -i '$a gpg-verify=false' \
            /sysroot/ostree/repo/config

        apt-ostree repo init \
            --feed $REPO_DIR \
            --release $RELEASE \
            --origin $REPO_ID
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

    # Sync the software dir
    LOG_TO_FILE "rsync -acv --delete rsync://controller/software/ ${PATCHING_DIR}/"
    rsync -acv --delete rsync://controller/software/ ${PATCHING_DIR}/ >> $logfile 2>&1

    # Sync the repo dir
    LOG_TO_FILE "rsync -acv --delete rsync://controller/repo/ ${REPO_ROOT}/"
    rsync -acv --delete rsync://controller/repo/ ${REPO_ROOT}/ >> $logfile 2>&1
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

