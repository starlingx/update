#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#

from software_client.common import utils
from software_client.v1 import metapackage_shell


METAPACKAGE_COMMAND_MODULES = [
    metapackage_shell,
]

# software metapackage commands
#     - list
# non root/sudo users can run:
#     - list
#
# UN_RESTRICTED_COMMANDS is used to set argparser argument 'restricted' to False
UN_RESTRICTED_COMMANDS = ['list']


def enhance_parser(parser, subparsers, cmd_mapper):
    '''Take a basic (nonversioned) parser and enhance it with
    commands and options specific for this version of API.

    :param parser: top level parser :param subparsers: top level
        parser's subparsers collection where subcommands will go
    '''
    metapackage_cmds = {}

    for command_module in METAPACKAGE_COMMAND_MODULES:
        utils.define_commands_from_module(subparsers, command_module,
                                          metapackage_cmds, UN_RESTRICTED_COMMANDS, cmd_area='metapackage')

    cmd_mapper.update({f"metapackage {k}": v for k, v in metapackage_cmds.items()})
