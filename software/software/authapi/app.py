"""
Copyright (c) 2023-2024 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

from oslo_config import cfg
import pecan

from software.authapi import acl
from software.authapi import config
from software.authapi import hooks
from software.authapi import policy
from software.utils import ExceptionHook
from software.logging_hook import LoggingHook


auth_opts = [
    cfg.StrOpt('auth_strategy',
               default='keystone',
               help='Method to use for auth: noauth or keystone.'),
]

CONF = cfg.CONF
CONF.register_opts(auth_opts)


def get_pecan_config():
    # Set up the pecan configuration
    filename = config.__file__.replace('.pyc', '.py')
    return pecan.configuration.conf_from_file(filename)


def setup_app(pecan_config=None, extra_hooks=None):
    policy.init()

    app_hooks = [hooks.ConfigHook(),
                 hooks.ContextHook(pecan_config.app.acl_public_routes),
                 ExceptionHook(), LoggingHook(),
                 ]
    if extra_hooks:
        app_hooks.extend(extra_hooks)

    if not pecan_config:
        pecan_config = get_pecan_config()

    if pecan_config.app.enable_acl:
        app_hooks.append(hooks.AccessPolicyHook())

    pecan.configuration.set_config(dict(pecan_config), overwrite=True)

    app = pecan.make_app(
        pecan_config.app.root,
        static_root=pecan_config.app.static_root,
        template_path=pecan_config.app.template_path,
        debug=False,
        force_canonical=getattr(pecan_config.app, 'force_canonical', True),
        hooks=app_hooks,
        guess_content_type_from_ext=False,  # Avoid mime-type lookup
    )

    # config_parser must contain the keystone_auth
    if pecan_config.app.enable_acl:
        CONF.import_group(acl.OPT_GROUP_NAME, acl.OPT_GROUP_PROVIDER)
        return acl.install(app, CONF, pecan_config.app.acl_public_routes)

    return app


class VersionSelectorApplication(object):
    def __init__(self):
        pc = get_pecan_config()
        pc.app.enable_acl = (CONF.auth_strategy == 'keystone')
        self.v1 = setup_app(pecan_config=pc)

    def __call__(self, environ, start_response):
        return self.v1(environ, start_response)
