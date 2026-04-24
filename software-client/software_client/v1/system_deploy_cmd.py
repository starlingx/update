#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from software_client.common import utils
from software_client.v1 import system_deploy_shell


SYSTEM_DEPLOY_COMMAND_MODULES = [
    system_deploy_shell,
]

# system-deploy commands:
#     - init
#     - show
#     - delete
UN_RESTRICTED_COMMANDS = []


def enhance_parser(parser, subparsers, cmd_mapper):
    '''Take a basic (nonversioned) parser and enhance it with
    commands and options specific for this version of API.

    :param parser: top level parser :param subparsers: top level
        parser's subparsers collection where subcommands will go
    '''
    system_deploy_cmds = {}

    for command_module in SYSTEM_DEPLOY_COMMAND_MODULES:
        utils.define_commands_from_module(subparsers, command_module,
                                          system_deploy_cmds,
                                          UN_RESTRICTED_COMMANDS,
                                          cmd_area='system-deploy')

    cmd_mapper.update({f"system-deploy {k}": v for k, v in system_deploy_cmds.items()})
