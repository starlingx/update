#!/bin/bash
#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
### BEGIN INIT INFO
# Description: reset-boot-counter
#
# Short-Description: Reset Boot Counter
# Provides: reset-boot-counter
# Required-Start:
# Required-Stop:
# Default-Start: 3 5
# Default-Stop: 3 5
### END INIT INFO

NAME=$(basename $0)
BOOT_ENV="/boot/efi/EFI/BOOT/boot.env"

grub-editenv $BOOT_ENV set boot_failure="0"

# Reaching a normal boot means this is not a factory-restore boot, so clear
# the machine-local install_bootnum. It is re-armed per machine when a restore
# is triggered, so a stale/cloned value cannot select Local Factory Restore.
if grep -q "^install_bootnum=" "$BOOT_ENV" 2>/dev/null; then
    grub-editenv $BOOT_ENV unset install_bootnum
fi

exit 0
