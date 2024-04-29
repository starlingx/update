# Copyright 2013-2024 Wind River, Inc
# Copyright 2012 OpenStack LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from __future__ import print_function

import argparse
import json
import os
import re
from tabulate import tabulate
from oslo_utils import importutils

from software_client.common.http_errors import HTTP_ERRORS

#####################################################

TERM_WIDTH = 72


class HelpFormatter(argparse.HelpFormatter):
    def start_section(self, heading):
        # Title-case the headings
        heading = '%s%s' % (heading[0].upper(), heading[1:])
        super(HelpFormatter, self).start_section(heading)


def define_command(subparsers, command, callback, cmd_mapper, unrestricted_cmds):
    '''Define a command in the subparsers collection.

    :param subparsers: subparsers collection where the command will go
    :param command: command name
    :param callback: function that will be used to process the command
    '''
    desc = callback.__doc__ or ''
    help = desc.strip().split('\n')[0]
    arguments = getattr(callback, 'arguments', [])

    subparser = subparsers.add_parser(command, help=help,
                                      description=desc,
                                      add_help=False,
                                      formatter_class=HelpFormatter)
    subparser.add_argument('-h', '--help', action='help',
                           help=argparse.SUPPRESS)

    func = callback
    cmd_mapper[command] = subparser
    for (args, kwargs) in arguments:
        subparser.add_argument(*args, **kwargs)
    subparser.set_defaults(func=func)

    if command in unrestricted_cmds:
        subparser.set_defaults(restricted=False)


def define_commands_from_module(subparsers, command_module, cmd_mapper, unrestricted_cmds=[]):
    '''Find all methods beginning with 'do_' in a module, and add them
    as commands into a subparsers collection.
    '''
    for method_name in (a for a in dir(command_module) if a.startswith('do_')):
        # Commands should be hypen-separated instead of underscores.
        command = method_name[3:].replace('_', '-')
        callback = getattr(command_module, method_name)
        define_command(subparsers, command, callback, cmd_mapper, unrestricted_cmds)


# Decorator for cli-args
def arg(*args, **kwargs):
    def _decorator(func):
        # Because of the sematics of decorator composition if we just append
        # to the options list positional options will appear to be backwards.
        func.__dict__.setdefault('arguments', []).insert(0, (args, kwargs))
        return func

    return _decorator


def env(*vars, **kwargs):
    """Search for the first defined of possibly many env vars

    Returns the first environment variable defined in vars, or
    returns the default defined in kwargs.
    """
    for v in vars:
        value = os.environ.get(v, None)
        if value:
            return value
    return kwargs.get('default', '')


def import_versioned_module(version, submodule=None):
    module = 'software_client.v%s' % version
    if submodule:
        module = '.'.join((module, submodule))
    return importutils.import_module(module)


def check_rc(req, data):
    rc = 0
    if req.status_code == 200:
        if data and 'error' in data and data["error"] != "":
            rc = 1
    else:
        rc = 1

    return rc


def _display_info(text):
    '''display the basic info json object '''
    try:
        data = json.loads(text)
    except Exception:
        print(f"Invalid response format: {text}")
        return

    if "error" in data and data["error"] != "":
        print("Error:\n%s" % data["error"])
    elif "warning" in data and data["warning"] != "":
        print("Warning:\n%s" % data["warning"])
    elif "info" in data and data["info"] != "":
        print(data["info"])


def _display_error(status_code, text):
    try:
        data = json.loads(text)
    except Exception:
        print("Error:\n%s", HTTP_ERRORS[status_code])
        return

    if "code" in data:
        print("Status: %s." % data["code"], end="")
    else:
        print("Status: %s." % status_code, end="")

    if "description" in data:
        print(" " + data["description"])
    elif "title" in data:
        print(" " + data["title"])
    else:
        # any 4xx and 5xx errors does not contain API information.
        print(HTTP_ERRORS[status_code])


def display_info(resp):
    '''
    This function displays basic REST API return, w/ info json object:
    {
        "info":"",
        "warning":"",
        "error":"",
    }

    or an webob exception:
    {"code": 404, "title": "", "description": ""}

    or default message based on status code
    '''

    status_code = resp.status_code
    text = resp.text

    if status_code == 500:
        # all 500 error comes with basic info json object
        _display_info(text)
    elif status_code in HTTP_ERRORS:
        _display_error(status_code, text)
    else:
        # print out the basic info json object
        _display_info(text)


def display_result_list(header_data_list, data):
    header = [h for h in header_data_list]
    table = []
    for d in data:
        row = []
        for _, k in header_data_list.items():
            row.append(d[k])
        table.append(row)
    if len(table) == 0:
        print("No data")
    else:
        print(tabulate(table, header, tablefmt='pretty', colalign=("left", "left")))


def display_detail_result(data):
    header = ["Property", "Value"]
    table = []
    for k, v in data.items():
        if isinstance(v, list):
            if len(v) > 0:
                row = [k, v[0]]
                v.pop(0)
            else:
                row = [k, '']
            table.append(row)

            for r in v:
                row = ['', r]
                table.append(row)
        else:
            row = [k, v]
            table.append(row)
    print(tabulate(table, header, tablefmt='pretty', colalign=("left", "left")))


def print_software_op_result(resp, data):
    if resp.status_code == 200:
        if 'sd' in data:
            sd = data['sd']

            # Calculate column widths
            hdr_release = "Release"
            hdr_version = "Version"
            hdr_rr = "RR"
            hdr_state = "State"

            width_release = len(hdr_release)
            width_version = len(hdr_version)
            width_rr = len(hdr_rr)
            width_state = len(hdr_state)

            show_all = False

            for release_id in list(sd):
                width_release = max(len(release_id), width_release)
                width_state = max(len(sd[release_id]["state"]), width_state)
                if "sw_version" in sd[release_id]:
                    show_all = True
                    width_version = max(len(sd[release_id]["sw_version"]), width_version)

            if show_all:
                print("{0:^{width_release}}  {1:^{width_rr}}  {2:^{width_version}}  {3:^{width_state}}".format(
                    hdr_release, hdr_rr, hdr_version, hdr_state,
                    width_release=width_release, width_rr=width_rr,
                    width_version=width_version, width_state=width_state))

                print("{0}  {1}  {2}  {3}".format(
                    '=' * width_release, '=' * width_rr, '=' * width_version, '=' * width_state))

                for release_id in sorted(list(sd)):
                    if "reboot_required" in sd[release_id]:
                        rr = sd[release_id]["reboot_required"]
                    else:
                        rr = "Y"

                    print("{0:<{width_release}}  {1:^{width_rr}}  {2:^{width_version}}  {3:^{width_state}}".format(
                        release_id,
                        rr,
                        sd[release_id]["sw_version"],
                        sd[release_id]["state"],
                        width_release=width_release, width_rr=width_rr,
                        width_version=width_version, width_state=width_state))
            else:
                print("{0:^{width_release}}  {1:^{width_state}}".format(
                    hdr_release, hdr_state,
                    width_release=width_release, width_state=width_state))

                print("{0}  {1}".format(
                    '=' * width_release, '=' * width_state))

                for release_id in sorted(list(sd)):
                    if "reboot_required" in sd[release_id]:
                        rr = sd[release_id]["reboot_required"]
                    else:
                        rr = "Y"

                    print("{0:<{width_release}}  {1:^{width_rr}}  {2:^{width_state}}".format(
                        release_id,
                        rr,
                        sd[release_id]["state"],
                        width_release=width_release, width_rr=width_rr,
                        width_state=width_state))

            print("")

        if 'info' in data and data["info"] != "":
            print(data["info"])

        if 'warning' in data and data["warning"] != "":
            print("Warning:")
            print(data["warning"])

        if 'error' in data and data["error"] != "":
            print("Error:")
            print(data["error"])

    elif resp.status_code == 500:
        print("An internal error has occurred. Please check /var/log/software.log for details")
    else:
        # print("Error: %s has occurred. %s" % (resp.status_code, resp.reason))
        print("Error: %s has occurred." % (resp.status_code))


def print_result_debug(req, data):
    if req.status_code == 200:
        if 'sd' in data:
            print(json.dumps(data['sd'],
                             sort_keys=True,
                             indent=4,
                             separators=(',', ': ')))
        elif 'data' in data:
            print(json.dumps(data['data'],
                             sort_keys=True,
                             indent=4,
                             separators=(',', ': ')))
        else:
            print(json.dumps(data,
                             sort_keys=True,
                             indent=4,
                             separators=(',', ': ')))
    elif req.status_code == 500:
        print("An internal error has occurred. Please check /var/log/software.log for details")
    else:
        m = re.search("(Error message:.*)", data, re.MULTILINE)
        if m:
            print(m.group(0))
        else:
            print("%s %s" % (req.status_code, req.reason))
