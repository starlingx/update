#
# Copyright (c) 2013-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


"""
Command-line interface for Software
"""

from __future__ import print_function
import argparse
import httplib2
import logging
import os
import subprocess
import sys

import software_client

from software_client import client as sclient
from software_client import exc
from software_client.common import utils
from software_client.constants import LOCAL_ROOT
from software_client.constants import KEYSTONE
from software_client.constants import TOKEN


VIRTUAL_REGION = 'SystemController'


def software_command_not_implemented_yet(args):
    print("NOT IMPLEMENTED %s" % args)
    return 1


def check_for_os_region_name(args):
    # argparse converts os-region-name to os_region_name
    region = args.os_region_name
    if region is None:
        return False

    global VIRTUAL_REGION
    if region != VIRTUAL_REGION:
        return False

    # check it is running on the active controller
    # not able to use sm-query due to it requires sudo
    try:
        subprocess.check_output("pgrep -f dcorch-api-proxy", shell=True)
    except subprocess.CalledProcessError:
        return False

    return True


def check_keystone_credentials(args):
    if not args.os_username:
        return False

    if not args.os_password:
        # priviledge check (only allow Keyring retrieval if we are root)
        if os.geteuid() == 0:
            import keyring
            args.os_password = keyring.get_password('CGCS', args.os_username)
        else:
            return False

    if not (args.os_project_id or args.os_project_name):
        return False

    if not args.os_auth_url:
        return False

    if not args.os_region_name:
        return False

    return True


class SoftwareClientShell(object):

    def __init__(self):
        self.subcommands = None
        self.parser = None

    def get_base_parser(self):
        parser = argparse.ArgumentParser(
            prog='software',
            description=__doc__.strip(),
            epilog='See "software help COMMAND" '
                   'for help on a specific command.',
            add_help=False,
            formatter_class=HelpFormatter,
        )

        # Global arguments
        parser.add_argument('-h', '--help',
                            action='store_true',
                            help=argparse.SUPPRESS,
                            )

        parser.add_argument('--version',
                            action='version',
                            version=software_client.__version__)

        parser.add_argument('--debug',
                            default=bool(utils.env('SOFTWARECLIENT_DEBUG')),
                            action='store_true',
                            help='Defaults to env[SOFTWARECLIENT_DEBUG]')

        parser.add_argument('-v', '--verbose',
                            default=False, action="store_true",
                            help="Print more verbose output")

        parser.add_argument('-k', '--insecure',
                            default=False,
                            action='store_true',
                            help="Explicitly allow system client to "
                            "perform \"insecure\" SSL (https) requests. "
                            "The server's certificate will "
                            "not be verified against any certificate "
                            "authorities. This option should be used with "
                            "caution")

        parser.add_argument('--cert-file',
                            help='Path of certificate file to use in SSL '
                            'connection. This file can optionally be prepended'
                            ' with the private key')

        parser.add_argument('--key-file',
                            help='Path of client key to use in SSL connection.'
                            ' This option is not necessary if your key is '
                            'prepended to your cert file')

        parser.add_argument('--ca-file',
                            default=utils.env('OS_CACERT'),
                            help='Path of CA SSL certificate(s) used to verify'
                            ' the remote server certificate. Without this '
                            'option systemclient looks for the default system '
                            'CA certificates')

        parser.add_argument('--timeout',
                            default=600,
                            help='Number of seconds to wait for a response')

        parser.add_argument('--os-username',
                            default=utils.env('OS_USERNAME'),
                            help='Defaults to env[OS_USERNAME]')

        parser.add_argument('--os_username',
                            help=argparse.SUPPRESS)

        parser.add_argument('--os-password',
                            default=utils.env('OS_PASSWORD'),
                            help='Defaults to env[OS_PASSWORD]')

        parser.add_argument('--os_password',
                            help=argparse.SUPPRESS)

        parser.add_argument('--os-tenant-id',
                            default=utils.env('OS_TENANT_ID'),
                            help='Defaults to env[OS_TENANT_ID]')

        parser.add_argument('--os_tenant_id',
                            help=argparse.SUPPRESS)

        parser.add_argument('--os-tenant-name',
                            default=utils.env('OS_TENANT_NAME'),
                            help='Defaults to env[OS_TENANT_NAME]')

        parser.add_argument('--os_tenant_name',
                            help=argparse.SUPPRESS)

        parser.add_argument('--os-auth-url',
                            default=utils.env('OS_AUTH_URL'),
                            help='Defaults to env[OS_AUTH_URL]')

        parser.add_argument('--os_auth_url',
                            help=argparse.SUPPRESS)

        parser.add_argument('--os-region-name',
                            default=utils.env('OS_REGION_NAME'),
                            help='Defaults to env[OS_REGION_NAME]')

        parser.add_argument('--os_region_name',
                            help=argparse.SUPPRESS)

        parser.add_argument('--os-auth-token',
                            default=utils.env('OS_AUTH_TOKEN'),
                            help='Defaults to env[OS_AUTH_TOKEN]')

        parser.add_argument('--os_auth_token',
                            help=argparse.SUPPRESS)

        parser.add_argument('--software-url',
                            default=utils.env('SYSTEM_URL'),
                            help='Defaults to env[SYSTEM_URL]')

        parser.add_argument('--software_url',
                            help=argparse.SUPPRESS)

        parser.add_argument('--system-api-version',
                            default=utils.env('SYSTEM_API_VERSION', default='1'),
                            help='Defaults to env[SYSTEM_API_VERSION] '
                            'or 1')

        parser.add_argument('--system_api_version',
                            help=argparse.SUPPRESS)

        parser.add_argument('--os-service-type',
                            default=utils.env('OS_SERVICE_TYPE'),
                            help='Defaults to env[OS_SERVICE_TYPE]')

        parser.add_argument('--os_service_type',
                            help=argparse.SUPPRESS)

        parser.add_argument('--os-endpoint-type',
                            default=utils.env('OS_ENDPOINT_TYPE'),
                            help='Defaults to env[OS_ENDPOINT_TYPE]')

        parser.add_argument('--os_endpoint_type',
                            help=argparse.SUPPRESS)

        parser.add_argument('--os-user-domain-id',
                            default=utils.env('OS_USER_DOMAIN_ID'),
                            help='Defaults to env[OS_USER_DOMAIN_ID].')

        parser.add_argument('--os-user-domain-name',
                            default=utils.env('OS_USER_DOMAIN_NAME'),
                            help='Defaults to env[OS_USER_DOMAIN_NAME].')

        parser.add_argument('--os-project-id',
                            default=utils.env('OS_PROJECT_ID'),
                            help='Another way to specify tenant ID. '
                                 'This option is mutually exclusive with '
                                 ' --os-tenant-id. '
                                 'Defaults to env[OS_PROJECT_ID].')

        parser.add_argument('--os-project-name',
                            default=utils.env('OS_PROJECT_NAME'),
                            help='Another way to specify tenant name. '
                                 'This option is mutually exclusive with '
                                 ' --os-tenant-name. '
                                 'Defaults to env[OS_PROJECT_NAME].')

        parser.add_argument('--os-project-domain-id',
                            default=utils.env('OS_PROJECT_DOMAIN_ID'),
                            help='Defaults to env[OS_PROJECT_DOMAIN_ID].')

        parser.add_argument('--os-project-domain-name',
                            default=utils.env('OS_PROJECT_DOMAIN_NAME'),
                            help='Defaults to env[OS_PROJECT_DOMAIN_NAME].')

        # All commands are considered restricted, unless explicitly set to False
        parser.set_defaults(restricted=True)
        # All functions are initially defined as 'not implemented yet'
        # The func will be overridden by the command definition as they are completed
        parser.set_defaults(func=software_command_not_implemented_yet)

        # No commands are region restricted, unless explicitly set to True
        parser.set_defaults(region_restricted=False)

        return parser

    def get_subcommand_parser(self, version):
        parser = self.get_base_parser()

        self.subcommands = {}
        subparsers = parser.add_subparsers(metavar='<subcommand>')
        submodule = utils.import_versioned_module(version, 'shell')
        submodule.enhance_parser(parser, subparsers, self.subcommands)
        utils.define_commands_from_module(subparsers, self, self.subcommands)
        subparsers2 = self._add_deploy_subparser(subparsers)
        deploy_submodule = utils.import_versioned_module(version, 'deploy_cmd')
        deploy_submodule.enhance_parser(parser, subparsers2, self.subcommands)
        utils.define_commands_from_module(subparsers2, self, self.subcommands)
        self._add_bash_completion_subparser(subparsers2)
        return parser

    def _add_bash_completion_subparser(self, subparsers):
        subparser = subparsers.add_parser(
            'bash_completion',
            add_help=False,
            formatter_class=HelpFormatter
        )
        self.subcommands['bash_completion'] = subparser
        subparser.set_defaults(func=self.do_bash_completion)

    def _add_deploy_subparser(self, subparsers):
        """deploy commands
        - precheck
        - start
        - host
        - activate
        - complete
        non root/sudo users can run:
        - host-list
        - show
        Deploy commands are region_restricted, which means
        that they are not permitted to be run in DC
        """

        cmd_area = 'deploy'
        cmd_parser = subparsers.add_parser(
            cmd_area,
            help='Software Deploy',
            epilog="StarlingX Unified Software Deployment"
        )
        cmd_parser.set_defaults(cmd_area=cmd_area)
        self.subcommands['deploy'] = cmd_parser

        # Deploy commands are region_restricted, which means
        # that they are not permitted to be run in DC
        cmd_parser.set_defaults(region_restricted=True)

        sub_cmds = cmd_parser.add_subparsers(
            title='Software Deploy Commands:',
            metavar=''
        )
        sub_cmds.required = True

        return sub_cmds

    def _setup_debugging(self, debug):
        if debug:
            logging.basicConfig(
                format="%(levelname)s (%(module)s:%(lineno)d) %(message)s",
                level=logging.DEBUG)

            httplib2.debuglevel = 1
        else:
            logging.basicConfig(format="%(levelname)s %(message)s", level=logging.CRITICAL)

    def main(self, argv):
        # Parse args once to find version
        parser = self.get_base_parser()
        (options, args) = parser.parse_known_args(argv)
        self._setup_debugging(options.debug)

        # build available subcommands based on version
        api_version = options.system_api_version
        subcommand_parser = self.get_subcommand_parser(api_version)
        self.parser = subcommand_parser

        # Handle top-level --help/-h before attempting to parse
        # a command off the command line
        if options.help or not argv:
            self.do_help(options)
            return 0

        # Parse args again and call whatever callback was selected
        args = subcommand_parser.parse_args(argv)

        # Short-circuit and deal with help command right away.
        if args.func == self.do_help:  # pylint: disable=comparison-with-callable
            self.do_help(args)
            return 0
        elif args.func == self.do_bash_completion:  # pylint: disable=comparison-with-callable
            self.do_bash_completion(args)
            return 0

        dc_request = check_for_os_region_name(args)

        # Reject the commands that are not supported in the virtual region
        if dc_request and args.region_restricted:
            global VIRTUAL_REGION
            print("\n%s command is not allowed in %s region" % (args.cmd_area,
                                                                VIRTUAL_REGION))
            rc = 1
            exit(rc)

        endpoint_type = 'public'
        if dc_request:
            endpoint_type = 'internal'

        # Identify authentication mode [token, keystone, local_root]
        if args.software_url and args.os_auth_token:
            auth_mode = TOKEN
        elif check_keystone_credentials(args):
            auth_mode = KEYSTONE
        elif os.geteuid() == 0:
            auth_mode = LOCAL_ROOT
        else:
            exception_msg = ('Invalid authentication credentials. '
                             'Acceptable authentication modes are, '
                             'user-defined endpoint & token OR '
                             'keystone credentials OR '
                             'software commands as root (sudo)')
            raise exc.CommandError(exception_msg)

        args.os_endpoint_type = endpoint_type
        client = sclient.get_client(api_version, auth_mode, **(args.__dict__))

        try:
            return args.func(client, args)
        except exc.Unauthorized:
            raise exc.CommandError("Invalid Identity credentials.")
        except exc.HTTPForbidden:
            raise exc.CommandError("Error: Forbidden")

    def do_bash_completion(self, args):
        """Prints all of the commands and options to stdout.
        """
        commands = set()
        options = set()
        for sc_str, sc in self.subcommands.items():
            commands.add(sc_str)
            for option in list(sc._optionals._option_string_actions):
                options.add(option)

        commands.remove('bash_completion')
        print(' '.join(commands | options))

    @utils.arg('command', metavar='<subcommand>', nargs='?',
               help='Display help for <subcommand>')
    def do_help(self, args):
        """Display help about this program or one of its subcommands."""
        if getattr(args, 'command', None):
            if args.command in self.subcommands:
                self.subcommands[args.command].print_help()
            else:
                raise exc.CommandError("'%s' is not a valid subcommand" %
                                       args.command)
        else:
            self.parser.print_help()


class HelpFormatter(argparse.HelpFormatter):
    def start_section(self, heading):
        # Title-case the headings
        heading = '%s%s' % (heading[0].upper(), heading[1:])
        super(HelpFormatter, self).start_section(heading)


def main():
    try:
        return SoftwareClientShell().main(sys.argv[1:])

    except KeyboardInterrupt as e:
        print(('caught: %r, aborting' % (e)), file=sys.stderr)
        sys.exit(0)

    except IOError:
        sys.exit(0)

    except Exception as e:
        print(e, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    sys.exit(main())
