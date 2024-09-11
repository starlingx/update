#
# Copyright (c) 2013-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#

from software_client.common import utils
from software_client.v1 import deploy_shell


DEPLOY_COMMAND_MODULES = [
    deploy_shell,
]

# sofware deploy commands
#     - precheck
#     - start
#     - host
#     - abort
#     - activate
#     - activate-rollback
#     - complete
#     - delete
# non root/sudo users can run:
#     - host-list
#     - show
# Deploy commands are region_restricted, which means
# that they are not permitted to be run in DC
#
# UN_RESTRICTED_COMMANDS is used to set argparser argument 'restricted' to False
UN_RESTRICTED_COMMANDS = ['show', 'host-list']


def enhance_parser(parser, subparsers, cmd_mapper):
    '''Take a basic (nonversioned) parser and enhance it with
    commands and options specific for this version of API.

    :param parser: top level parser :param subparsers: top level
        parser's subparsers collection where subcommands will go
    '''
    deploy_cmds = {}

    for command_module in DEPLOY_COMMAND_MODULES:
        utils.define_commands_from_module(subparsers, command_module,
                                          deploy_cmds, UN_RESTRICTED_COMMANDS)

    cmd_mapper.update({f"deploy {k}": v for k, v in deploy_cmds.items()})
