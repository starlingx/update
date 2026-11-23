#!/usr/bin/env python
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Add cgroup-v2 service parameters during upgrade migration.
#
# Inserts platform/config/cgroup_v2_enabled and kubernetes/kubelet
# cgroupDriver and cgroupRoot directly into the to-release database.
#
# No version guard needed. This script can be revisited once the
# to-release supports only cgroup v2 or all supported from-releases
# are cgroup v2 only.

import logging
import subprocess
import sys
import uuid

from _loader import CPlugin
from software.utilities.utils import configure_logging

LOG = logging.getLogger("main_logger")


def _run_sql(sql, port, fetch=False):
    """Run a SQL statement against the to-release DB."""
    cmd = ['sudo', '-u', 'postgres', 'psql', '-d', 'sysinv',
           '--port=%s' % port, '-t', '-c', sql]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        LOG.error("SQL failed: %s\nstderr: %s", sql, e.stderr)
        raise
    if fetch:
        return result.stdout.strip()
    return result


def _param_exists(service, section, name, port):
    """Check if a service parameter exists in the DB."""
    sql = (
        "SELECT COUNT(*) FROM service_parameter "
        "WHERE service='%s' AND section='%s' AND name='%s';"
        % (service, section, name)
    )
    count = int(_run_sql(sql, port, fetch=True))
    return count > 0


def _get_param_value(service, section, name, port):
    """Get value of a service parameter from DB."""
    sql = (
        "SELECT value FROM service_parameter "
        "WHERE service='%s' AND section='%s' AND name='%s';"
        % (service, section, name)
    )
    return _run_sql(sql, port, fetch=True)


def _insert_param(service, section, name, value, port):
    """Insert a new service parameter."""
    param_uuid = str(uuid.uuid4())
    sql = (
        "INSERT INTO service_parameter "
        "(uuid, service, section, name, value, personality, resource, created_at) "
        "VALUES ('%s', '%s', '%s', '%s', '%s', NULL, NULL, now());"
        % (param_uuid, service, section, name, value)
    )
    _run_sql(sql, port)
    LOG.info("Inserted %s/%s/%s=%s (uuid=%s)",
             service, section, name, value, param_uuid)


def _upsert_param(service, section, name, value, port):
    """Insert or update a service parameter."""
    if _param_exists(service, section, name, port):
        sql = (
            "UPDATE service_parameter SET value='%s', updated_at=now() "
            "WHERE service='%s' AND section='%s' AND name='%s';"
            % (value, service, section, name)
        )
        _run_sql(sql, port)
        LOG.info("Updated %s/%s/%s=%s", service, section, name, value)
    else:
        _insert_param(service, section, name, value, port)


def do_migrate(port):
    """Main migration logic for cgroup v2 parameters."""

    # Default is cgroup v2
    value = "true"
    driver = "systemd"

    # Check if cgroup_v2_enabled was already set in the from-release DB
    if _param_exists("platform", "config", "cgroup_v2_enabled", port):
        value = _get_param_value("platform", "config", "cgroup_v2_enabled", port)
        LOG.info("cgroup_v2_enabled already exists with value=%s", value)
        driver = "systemd" if value == "true" else "cgroupfs"
    else:
        _insert_param("platform", "config", "cgroup_v2_enabled", value, port)

    # Set kubelet cgroup parameters
    _upsert_param("kubernetes", "kubelet", "cgroupDriver", driver, port)
    _upsert_param("kubernetes", "kubelet", "cgroupRoot", "/k8sinfra", port)

    LOG.info("cgroup-v2 migration complete: cgroup_v2_enabled=%s "
             "cgroupDriver=%s cgroupRoot=/k8sinfra", value, driver)


class AddCgroupV2ServiceParameters(CPlugin):
    """USM upgrade plugin to add cgroup-v2 service parameters.

    Runs during 'software deploy start' (migrate phase) to populate
    the to-release database before hosts are upgraded.
    """

    def __init__(self):
        super().__init__(
            matching_action=['migrate'],
            required_state=None,
            plugin_name='add-cgroup-v2-service-parameters',
            completed_state='add-cgroup-v2-service-parameters-completed'
        )

    def _run(self, from_release, to_release, action, port):
        LOG.info("%s invoked from_release=%s to_release=%s action=%s port=%s",
                 self.name, from_release, to_release, action, port)

        if action == "migrate":
            do_migrate(port)
        else:
            LOG.info("Nothing to do for action '%s'", action)


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
    # TODO(lbonatti) remove this condition once stx13 become N release.
    if action != "migrate":
        LOG.info("Nothing to do. Skipping cgroup v2 service parameters.")
        sys.exit(0)
    plugin = AddCgroupV2ServiceParameters()
    plugin.run(sys.argv[1], sys.argv[2], sys.argv[3])
