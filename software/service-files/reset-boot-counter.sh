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

exit 0
