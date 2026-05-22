#!/usr/bin/env python
# Copyright (c) 2021-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will clear the host config target.
# This is required in order to ensure tracking is aligned with config
# requests in N+1 release and not due to potential stale configuration
# from N release.

import logging
import sys

from controllerconfig.common import constants
from controllerconfig import utils
from psycopg2.extras import RealDictCursor

from software.utilities.plugin_runner import CPlugin
from software.utilities.utils import configure_logging

LOG = logging.getLogger('main_logger')


def reset_config_target(port):
    conn = utils.connect_to_postgresql(port)
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("update i_host set config_target=NULL",)
    LOG.info("Reset host config_target completed")


class ResetConfigTarget(CPlugin):
    def __init__(self):
        super().__init__(
            matching_action='migrate',
            required_state=None,
            plugin_name='reset-config-target',
            completed_state='reset-config-target-completed'
        )

    def _run(self, from_release, to_release, action, port):
        configure_logging()
        LOG.info("%s invoked from_release = %s to_release = %s action = %s"
                 % (self.name, from_release, to_release, action))
        postgres_port = port if port else constants.POSTGRESQL_DEFAULT_PORT
        reset_config_target(postgres_port)


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

    plugin = ResetConfigTarget()
    result = plugin.run(from_release, to_release, action, port)
    if result and 'failed' in result:
        sys.exit(1)
