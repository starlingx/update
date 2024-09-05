# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_config import cfg

API_SERVICE_OPTS = [
    cfg.StrOpt('auth_api_bind_ip',
               default=None,
               help='IP for the authenticated Unified Software Management API server to bind to'),
    cfg.IntOpt('auth_api_port',
               default=5499,
               help='The port for the authenticated Unified Software Management API server for GET operations'),
    cfg.IntOpt('auth_api_alt_port',
               default=5500,
               help='The port for the authenticated Unified Software Management API server for update and slow operations'),
    cfg.IntOpt('api_limit_max',
               default=1000,
               help='the maximum number of items returned in a single '
                    'response from a collection resource')
]

CONF = cfg.CONF
opt_group = cfg.OptGroup(name='api',
                         title='Options for the patch-api service')
CONF.register_group(opt_group)
CONF.register_opts(API_SERVICE_OPTS)
