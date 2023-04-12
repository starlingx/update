"""
Copyright (c) 2023 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import pecan

from software.config import CONF


def get_pecan_config():
    """Load the pecan configuration."""
    pecan_opts = CONF.pecan

    cfg_dict = {
        # todo(abailey): add server defaults to config
        "server": {
            "port": "5496",
            "host": "127.0.0.1"
        },
        "app": {
            "root": pecan_opts.root,
            "modules": pecan_opts.modules,
            "debug": pecan_opts.debug,
            "auth_enable": pecan_opts.auth_enable,
            "force_canonical": pecan_opts.force_canonical,
            "guess_content_type_from_ext":
                pecan_opts.guess_content_type_from_ext,
        }
    }
    return pecan.configuration.conf_from_dict(cfg_dict)


def setup_app(pecan_config=None):
    """Setup the pecan REST API."""
    if not pecan_config:
        pecan_config = get_pecan_config()
    pecan.configuration.set_config(dict(pecan_config), overwrite=True)

    # todo(abailey): Add in the hooks
    hooks = []

    # todo(abailey): It seems like the call to pecan.configuration above
    # mean that the following lines are redundnant?
    app = pecan.make_app(
        pecan_config.app.root,
        debug=pecan_config.app.debug,
        hooks=hooks,
        force_canonical=pecan_config.app.force_canonical,
        guess_content_type_from_ext=pecan_config.app.guess_content_type_from_ext
    )
    return app


class VersionSelectorApplication(object):
    def __init__(self):
        pc = get_pecan_config()
        self.v1 = setup_app(pecan_config=pc)

    def __call__(self, environ, start_response):
        return self.v1(environ, start_response)
