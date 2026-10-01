#!/usr/bin/env python
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Reset the LUKS vault passphrase-type metadata on rollback.

A snapshot rollback reverts var-lv (the vault image, back to the legacy-only
keyslot) but not /etc (ostree), so created_luks.json still records the
migrated HWID_V2 type. This restores the from-side metadata to match the
legacy-only vault, so a rolled-back system looks non-upgraded.

Runs only on the delete action of a rollback (to_release < from_release), and
skips a rollback whose target is >= 26.10 (which ships HWID_V2 natively). It
must not run on the delete that completes a forward upgrade. Idempotent and
best-effort.
"""

import json
import logging
import os
import sys

from packaging.version import Version

from _loader import CPlugin
from software.utilities.utils import configure_logging

LOG = logging.getLogger('main_logger')

CREATED_LUKS_JSON = "/etc/luks-fs-mgr.d/created_luks.json"
LEGACY_TYPE = "HWID"

# TODO(mdecastr): Remove when the oldest possible target is 26.10
# First release to ship the HWID_V2 vault natively. Any target at or above
# this keeps HWID_V2, so this repair must not touch it.
FIRST_NATIVE_HWID_V2_RELEASE = "26.10"


def _is_rollback(from_release, to_release):
    """True when this deploy is a rollback (target older than source)."""
    try:
        return Version(to_release) < Version(from_release)
    except Exception:
        return to_release < from_release


def _skip_for_native_hwid_v2_target(to_release):
    """True when the rollback target ships HWID_V2 natively (>= 26.10).

    Resetting PASSPHRASE_TYPE to HWID on such a target would be wrong.
    """
    if not to_release:
        return False
    try:
        return Version(to_release) >= Version(FIRST_NATIVE_HWID_V2_RELEASE)
    except Exception:
        return to_release.startswith(FIRST_NATIVE_HWID_V2_RELEASE)


def reset_luks_passphrase_type():
    if not os.path.isfile(CREATED_LUKS_JSON):
        LOG.info("%s not present; nothing to reset.", CREATED_LUKS_JSON)
        return

    try:
        with open(CREATED_LUKS_JSON, "r") as fp:
            config = json.load(fp)
    except (ValueError, OSError) as e:
        LOG.warning("Could not read/parse %s (%s); leaving unchanged.",
                    CREATED_LUKS_JSON, e)
        return

    volumes = config.get("luksvolumes")
    if not isinstance(volumes, list) or not volumes:
        LOG.warning("%s missing 'luksvolumes' array; leaving unchanged.",
                    CREATED_LUKS_JSON)
        return

    # Mutate the first volume in place so other fields are preserved.
    volume = volumes[0]
    current_type = volume.get("PASSPHRASE_TYPE")
    had_removed_flag = "LEGACY_KEYSLOT_REMOVED" in volume

    if current_type == LEGACY_TYPE and not had_removed_flag:
        LOG.info("%s already non-upgraded; no change.", CREATED_LUKS_JSON)
        return

    volume["PASSPHRASE_TYPE"] = LEGACY_TYPE
    volume.pop("LEGACY_KEYSLOT_REMOVED", None)

    try:
        with open(CREATED_LUKS_JSON, "w") as fp:
            json.dump(config, fp)
    except OSError as e:
        LOG.error("Failed to write %s (%s).", CREATED_LUKS_JSON, e)
        raise

    LOG.info("Reset %s: PASSPHRASE_TYPE %s -> %s.",
             CREATED_LUKS_JSON, current_type, LEGACY_TYPE)


class RollbackLuksPassphraseType(CPlugin):
    def __init__(self):
        super().__init__(
            matching_action='delete',
            required_state=None,
            plugin_name='rollback-luks-passphrase-type',
            completed_state='rollback-luks-passphrase-type-completed'
        )

    def _run(self, from_release, to_release, action, port):
        LOG.info("%s invoked from_release = %s to_release = %s action = %s"
                 % (self.name, from_release, to_release, action))

        if not _is_rollback(from_release, to_release):
            LOG.info("Not a rollback (to_release %s >= from_release %s); "
                     "no change.", to_release, from_release)
            return

        # A target at or above 26.10 ships HWID_V2 natively, so a rollback
        # to it must keep PASSPHRASE_TYPE=HWID_V2; resetting to HWID is wrong.
        if _skip_for_native_hwid_v2_target(to_release):
            LOG.error("NOTICE: %s should not run for a rollback to %s "
                      "(>= %s uses HWID_V2 natively); skipping.",
                      self.name, to_release, FIRST_NATIVE_HWID_V2_RELEASE)
            return

        reset_luks_passphrase_type()


if __name__ == "__main__":
    from_release = None
    to_release = None
    action = None
    port = None
    arg = 1

    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]
        elif arg == 3:
            action = sys.argv[arg]
        elif arg == 4:
            port = sys.argv[arg]
        else:
            print("Invalid option %s." % sys.argv[arg])
            sys.exit(1)
        arg += 1

    configure_logging()

    if action != "delete":
        sys.exit(0)

    plugin = RollbackLuksPassphraseType()
    result = plugin.run(from_release, to_release, action, port)
    if result and 'failed' in result:
        sys.exit(1)
