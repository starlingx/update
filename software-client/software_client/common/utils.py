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
import textwrap

from oslo_utils import importutils
from six.moves import zip

from software_client.common.http_errors import HTTP_ERRORS


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
    if req.status_code == 200 and data:
        if 'error' in data and data["error"] != "":
            rc = 1
    else:
        rc = 1

    return rc


def _display_info(text):
    ''' display the basic info json object '''
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


def display_info(resp):
    '''
    This function displays basic REST API return, w/ info json object:
    {
        "info":"",
        "warning":"",
        "error":"",
    }
    '''

    status_code = resp.status_code
    text = resp.text

    if resp.status_code == 500:
        # all 500 error comes with basic info json object
        _display_info(text)
    elif resp.status_code in HTTP_ERRORS:
        # any 4xx and 5xx errors does not contain API information.
        print("Error:\n%s", HTTP_ERRORS[status_code])
    else:
        # print out the basic info json object
        _display_info(text)


def print_result_list(header_data_list, data_list, has_error, sort_key=0):
    """
    Print a list of data in a simple table format
    :param header_data_list: Array of header data
    :param data_list: Array of data
    :param has_error: Boolean indicating if the request has error message
    :param sort_key: Sorting key for the list
    """

    if has_error:
        return

    if data_list is None or len(data_list) == 0:
        return

    # Find the longest header string in each column
    header_lengths = [len(str(x)) for x in header_data_list]
    # Find the longest content string in each column
    content_lengths = [max(len(str(x[i])) for x in data_list)
                       for i in range(len(header_data_list))]
    # Find the max of the two for each column
    col_lengths = [(x if x > y else y) for x, y in zip(header_lengths, content_lengths)]

    print('  '.join(f"{x.center(col_lengths[i])}" for i, x in enumerate(header_data_list)))
    print('  '.join('=' * length for length in col_lengths))
    for item in sorted(data_list, key=lambda d: d[sort_key]):
        print('  '.join(f"{str(x).center(col_lengths[i])}" for i, x in enumerate(item)))
    print("\n")


def print_software_deploy_host_list_result(req, data):
    if req.status_code == 200 and data:
        data = data.get("data", None)
        if not data:
            print("No deploy in progress.\n")
            return

        # Calculate column widths
        hdr_hn = "Hostname"
        hdr_rel = "Software Release"
        hdr_tg_rel = "Target Release"
        hdr_rr = "Reboot Required"
        hdr_state = "Host State"

        width_hn = len(hdr_hn)
        width_rel = len(hdr_rel)
        width_tg_rel = len(hdr_tg_rel)
        width_rr = len(hdr_rr)
        width_state = len(hdr_state)

        for agent in sorted(data, key=lambda a: a["hostname"]):
            if agent.get("host_state") is None:
                agent["host_state"] = "No active deployment"
            if agent.get("target_release") is None:
                agent["target_release"] = "N/A"
            if len(agent["hostname"]) > width_hn:
                width_hn = len(agent["hostname"])
            if len(agent["software_release"]) > width_rel:
                width_rel = len(agent["software_release"])
            if len(agent["target_release"]) > width_tg_rel:
                width_tg_rel = len(agent["target_release"])
            if len(agent["host_state"]) > width_state:
                width_state = len(agent["host_state"])

        print("{0:^{width_hn}}  {1:^{width_rel}}  {2:^{width_tg_rel}}  {3:^{width_rr}}  {4:^{width_state}}".format(
            hdr_hn, hdr_rel, hdr_tg_rel, hdr_rr, hdr_state,
            width_hn=width_hn, width_rel=width_rel, width_tg_rel=width_tg_rel, width_rr=width_rr, width_state=width_state))

        print("{0}  {1}  {2}  {3}  {4}".format(
            '=' * width_hn, '=' * width_rel, '=' * width_tg_rel, '=' * width_rr, '=' * width_state))

        for agent in sorted(data, key=lambda a: a["hostname"]):
            print("{0:<{width_hn}}  {1:^{width_rel}}  {2:^{width_tg_rel}}  {3:^{width_rr}}  {4:^{width_state}}".format(
                agent["hostname"],
                agent["software_release"],
                agent["target_release"],
                "Yes" if agent.get("reboot_required", None) else "No",
                agent["host_state"],
                width_hn=width_hn, width_rel=width_rel, width_tg_rel=width_tg_rel, width_rr=width_rr, width_state=width_state))

    elif req.status_code == 500:
        print("An internal error has occurred. Please check /var/log/software.log for details")



def print_release_show_result(req, data, list_packages=False):
    if req.status_code == 200:

        if 'metadata' in data:
            sd = data['metadata']
            contents = data['contents']
            for release_id in sorted(list(sd)):
                print("%s:" % release_id)

                if "sw_version" in sd[release_id] and sd[release_id]["sw_version"] != "":
                    print(textwrap.fill("    {0:<15} ".format("Version:") + sd[release_id]["sw_version"],
                                        width=TERM_WIDTH, subsequent_indent=' ' * 20))

                if "state" in sd[release_id] and sd[release_id]["state"] != "":
                    print(textwrap.fill("    {0:<15} ".format("State:") + sd[release_id]["state"],
                                        width=TERM_WIDTH, subsequent_indent=' ' * 20))

                if "status" in sd[release_id] and sd[release_id]["status"] != "":
                    print(textwrap.fill("    {0:<15} ".format("Status:") + sd[release_id]["status"],
                                        width=TERM_WIDTH, subsequent_indent=' ' * 20))

                if "unremovable" in sd[release_id] and sd[release_id]["unremovable"] != "":
                    print(textwrap.fill("    {0:<15} ".format("Unremovable:") + sd[release_id]["unremovable"],
                                        width=TERM_WIDTH, subsequent_indent=' ' * 20))

                if "reboot_required" in sd[release_id] and sd[release_id]["reboot_required"] != "":
                    print(textwrap.fill("    {0:<15} ".format("RR:") + sd[release_id]["reboot_required"],
                                        width=TERM_WIDTH, subsequent_indent=' ' * 20))

                if "apply_active_release_only" in sd[release_id] and sd[release_id]["apply_active_release_only"] != "":
                    print(textwrap.fill("    {0:<15} ".format("Apply Active Release Only:") + sd[release_id]["apply_active_release_only"],
                                        width=TERM_WIDTH, subsequent_indent=' ' * 20))

                if "summary" in sd[release_id] and sd[release_id]["summary"] != "":
                    print(textwrap.fill("    {0:<15} ".format("Summary:") + sd[release_id]["summary"],
                                        width=TERM_WIDTH, subsequent_indent=' ' * 20))

                if "description" in sd[release_id] and sd[release_id]["description"] != "":
                    first_line = True
                    for line in sd[release_id]["description"].split('\n'):
                        if first_line:
                            print(textwrap.fill("    {0:<15} ".format("Description:") + line,
                                                width=TERM_WIDTH, subsequent_indent=' ' * 20))
                            first_line = False
                        else:
                            print(textwrap.fill(line,
                                                width=TERM_WIDTH, subsequent_indent=' ' * 20,
                                                initial_indent=' ' * 20))

                if "install_instructions" in sd[release_id] and sd[release_id]["install_instructions"] != "":
                    print("    Install Instructions:")
                    for line in sd[release_id]["install_instructions"].split('\n'):
                        print(textwrap.fill(line,
                                            width=TERM_WIDTH, subsequent_indent=' ' * 20,
                                            initial_indent=' ' * 20))

                if "warnings" in sd[release_id] and sd[release_id]["warnings"] != "":
                    first_line = True
                    for line in sd[release_id]["warnings"].split('\n'):
                        if first_line:
                            print(textwrap.fill("    {0:<15} ".format("Warnings:") + line,
                                                width=TERM_WIDTH, subsequent_indent=' ' * 20))
                            first_line = False
                        else:
                            print(textwrap.fill(line,
                                                width=TERM_WIDTH, subsequent_indent=' ' * 20,
                                                initial_indent=' ' * 20))

                if "requires" in sd[release_id] and len(sd[release_id]["requires"]) > 0:
                    print("    Requires:")
                    for req_patch in sorted(sd[release_id]["requires"]):
                        print(' ' * 20 + req_patch)

                if "contents" in data and release_id in data["contents"]:
                    print("    Contents:\n")
                    if "number_of_commits" in contents[release_id] and \
                            contents[release_id]["number_of_commits"] != "":
                        print(textwrap.fill("    {0:<15} ".format("No. of commits:") +
                                            contents[release_id]["number_of_commits"],
                                            width=TERM_WIDTH, subsequent_indent=' ' * 20))
                    if "base" in contents[release_id] and \
                            contents[release_id]["base"]["commit"] != "":
                        print(textwrap.fill("    {0:<15} ".format("Base commit:") +
                                            contents[release_id]["base"]["commit"],
                                            width=TERM_WIDTH, subsequent_indent=' ' * 20))
                    if "number_of_commits" in contents[release_id] and \
                            contents[release_id]["number_of_commits"] != "":
                        for i in range(int(contents[release_id]["number_of_commits"])):
                            print(textwrap.fill("    {0:<15} ".format("Commit%s:" % (i + 1)) +
                                                contents[release_id]["commit%s" % (i + 1)]["commit"],
                                                width=TERM_WIDTH, subsequent_indent=' ' * 20))

                if list_packages:
                    if "packages" in sd[release_id] and len(sd[release_id]["packages"]):
                        print("    Packages:")
                        for package in sorted(sd[release_id]["packages"]):
                            print(" " * 20 + package)

                print("\n")

        if 'info' in data and data["info"] != "":
            print(data["info"])

        if 'warning' in data and data["warning"] != "":
            print("Warning:")
            print(data["warning"])

        if 'error' in data and data["error"] != "":
            print("Error:")
            print(data["error"])

    elif req.status_code == 500:
        print("An internal error has occurred. Please check /var/log/software.log for details")


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
