#!/usr/bin/env python
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Rollback cleanup for Keystone federation resources.

During upgrade from a release without federation support to one with it,
Keystone federation resources (IdP, mapping, protocol) and configuration
(keystone.conf settings, template files) are created. On rollback, the
target release does not have puppet classes to manage these resources,
leaving them orphaned.

This script removes:
- [federation] section settings from keystone.conf
- 'openid' from [auth] methods in keystone.conf
- /etc/keystone/sso_callback_template.html
- /etc/keystone/dex_mapping.json
- Keystone DB resources: protocol (openid), mapping (dex_mapping), IdP (dex)

Group (federated_users) and project (federated_project) are intentionally
preserved as they may contain user data or active role assignments.
"""

import logging
import os
import subprocess
import sys

from _loader import CPlugin
from software.utilities.utils import configure_logging

LOG = logging.getLogger('main_logger')

KEYSTONE_CONF = '/etc/keystone/keystone.conf'
OPENRC = '/etc/platform/openrc'
SSO_CALLBACK_TEMPLATE = '/etc/keystone/sso_callback_template.html'
DEX_MAPPING_FILE = '/etc/keystone/dex_mapping.json'
OIDC_LOGIN_CONFIG = '/opt/platform/.oidc_login_config'
WEBSSO_SETTINGS_FILE = '/etc/openstack-dashboard/local_settings.d/_31_websso_settings.py'

# Default auth methods without 'openid' (pre-federation)
DEFAULT_AUTH_METHODS = 'password,token,oauth1,mapped,application_credential'


def _run_openstack_cmd(cmd):
    """Run an openstack CLI command sourcing openrc first."""
    full_cmd = f"source {OPENRC} && {cmd}"
    result = subprocess.run(
        full_cmd, shell=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    return result.returncode, result.stdout.strip()


def _resource_exists(check_cmd):
    """Check if an OpenStack resource exists."""
    rc, _ = _run_openstack_cmd(check_cmd)
    return rc == 0


def _cleanup_keystone_conf():
    """Remove federation settings from keystone.conf.

    Uses line-by-line editing to preserve comments and formatting.
    """
    if not os.path.isfile(KEYSTONE_CONF):
        LOG.info("keystone.conf not found, skipping conf cleanup")
        return

    with open(KEYSTONE_CONF, 'r') as f:
        lines = f.readlines()

    new_lines = []
    changed = False

    # Keys to remove from [federation] section
    federation_remove_keys = (
        'remote_id_attribute',
        'trusted_dashboard',
        'sso_callback_template',
    )

    for line in lines:
        stripped = line.strip()

        # Remove federation keys (regardless of section header tracking,
        # these keys are unique to the federation section)
        if any(stripped.startswith(k + ' ') or stripped.startswith(k + '=')
               for k in federation_remove_keys):
            LOG.info("Removed from keystone.conf: %s" % stripped)
            changed = True
            continue

        # Fix auth/methods line — remove openid and saml2
        if stripped.startswith('methods') and ('openid' in stripped):
            # Parse the value after '='
            if '=' in stripped:
                key_part, val_part = stripped.split('=', 1)
                methods = [m.strip() for m in val_part.split(',')
                           if m.strip() not in ('openid', 'saml2')]
                new_line = "%s=%s\n" % (key_part, ','.join(methods))
                new_lines.append(new_line)
                changed = True
                LOG.info("Restored [auth]/methods: %s" % ','.join(methods))
                continue

        new_lines.append(line)

    if changed:
        with open(KEYSTONE_CONF, 'w') as f:
            f.writelines(new_lines)
        LOG.info("keystone.conf updated successfully")
    else:
        LOG.info("No federation settings found in keystone.conf")


def _cleanup_files():
    """Remove federation template files and flag file."""
    for filepath in (SSO_CALLBACK_TEMPLATE, DEX_MAPPING_FILE, OIDC_LOGIN_CONFIG, WEBSSO_SETTINGS_FILE):
        if os.path.isfile(filepath):
            os.remove(filepath)
            LOG.info("Removed %s" % filepath)
        else:
            LOG.info("File %s not present, skipping" % filepath)

    # Remove the deferred federation flag if it exists
    # (may have been created during activate but not yet processed)
    import glob
    for flag in glob.glob('/opt/platform/config/*/.federation_config_required'):
        os.remove(flag)
        LOG.info("Removed flag file %s" % flag)


def _cleanup_keystone_resources():
    """Remove federation resources from Keystone DB."""
    # Check if keystone is responsive
    rc, _ = _run_openstack_cmd("openstack token issue")
    if rc != 0:
        LOG.warning("Keystone not responsive, skipping DB resource cleanup. "
                    "Orphaned resources are harmless and can be removed "
                    "manually later.")
        return

    # Delete in reverse dependency order: protocol -> mapping -> IdP
    if _resource_exists(
            "openstack federation protocol show --identity-provider dex openid"):
        rc, output = _run_openstack_cmd(
            "openstack federation protocol delete --identity-provider dex openid")
        if rc == 0:
            LOG.info("Deleted federation protocol 'openid'")
        else:
            LOG.warning("Failed to delete protocol 'openid': %s" % output)

    if _resource_exists("openstack mapping show dex_mapping"):
        rc, output = _run_openstack_cmd(
            "openstack mapping delete dex_mapping")
        if rc == 0:
            LOG.info("Deleted mapping 'dex_mapping'")
        else:
            LOG.warning("Failed to delete mapping 'dex_mapping': %s" % output)

    if _resource_exists("openstack identity provider show dex"):
        rc, output = _run_openstack_cmd(
            "openstack identity provider delete dex")
        if rc == 0:
            LOG.info("Deleted identity provider 'dex'")
        else:
            LOG.warning("Failed to delete identity provider 'dex': %s"
                        % output)


def rollback_keystone_federation():
    """Main rollback cleanup logic."""
    LOG.info("Starting Keystone federation rollback cleanup")

    _cleanup_keystone_conf()
    _cleanup_files()
    _cleanup_keystone_resources()

    LOG.info("Keystone federation rollback cleanup completed")


class RollbackKeystoneFederation(CPlugin):
    def __init__(self):
        super().__init__(
            matching_action='activate-rollback',
            required_state=None,
            plugin_name='rollback-keystone-federation',
            completed_state='rollback-keystone-federation-completed'
        )

    def _run(self, from_release, to_release, action, port):
        configure_logging()
        LOG.info("%s invoked from_release = %s to_release = %s action = %s"
                 % (self.name, from_release, to_release, action))
        rollback_keystone_federation()


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
    plugin = RollbackKeystoneFederation()
    result = plugin.run(from_release, to_release, action, port)
    if result and 'failed' in result:
        sys.exit(1)
