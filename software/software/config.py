"""
Copyright (c) 2023 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
from oslo_config import cfg

# setup a shareable config
CONF = cfg.CONF

# define the pecan configuration options
PECAN_CONFIG_GROUP = 'pecan'
# todo(abailey): Add help text for these options
pecan_opts = [
    cfg.StrOpt(
        'root',
        default='software.api.controllers.root.RootController'
    ),
    cfg.ListOpt(
        'modules',
        default=["software.api"]
    ),
    cfg.BoolOpt(
        'debug',
        default=False
    ),
    cfg.BoolOpt(
        'auth_enable',
        default=True
    ),
    cfg.BoolOpt(
        'force_canonical',
        default=True
    ),
    cfg.BoolOpt(
        'guess_content_type_from_ext',
        default=False
    ),
]

# register the configuration for this component
CONF.register_opts(pecan_opts, group=PECAN_CONFIG_GROUP)
