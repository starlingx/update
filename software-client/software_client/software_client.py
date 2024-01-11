"""
Copyright (c) 2023 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
# PYTHON_ARGCOMPLETE_OK
import argcomplete
import argparse
import json
import os
import re
import requests
import signal
import software_client.constants as constants
import subprocess
import sys
import textwrap
import time

from requests_toolbelt import MultipartEncoder
from urllib.parse import urlparse

from tsconfig.tsconfig import SW_VERSION as RUNNING_SW_VERSION

api_addr = "127.0.0.1:5493"
auth_token = None

TERM_WIDTH = 72
VIRTUAL_REGION = 'SystemController'
IPV6_FAMILY = 6


def set_term_width():
    global TERM_WIDTH

    try:
        with open(os.devnull, 'w') as NULL:
            output = subprocess.check_output(["tput", "cols"], stderr=NULL)
            width = int(output)
            if width > 60:
                TERM_WIDTH = width - 4
    except Exception:
        pass


def check_rc(req):
    rc = 0
    if req.status_code == 200:
        data = json.loads(req.text)
        if 'error' in data and data["error"] != "":
            rc = 1
    else:
        rc = 1

    return rc


def print_result_debug(req):
    if req.status_code == 200:
        data = json.loads(req.text)
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
        m = re.search("(Error message:.*)", req.text, re.MULTILINE)
        if m:
            print(m.group(0))
        else:
            print("%s %s" % (req.status_code, req.reason))


def print_software_op_result(req):
    if req.status_code == 200:
        data = json.loads(req.text)

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

    elif req.status_code == 500:
        print("An internal error has occurred. Please check /var/log/software.log for details")
    else:
        print("Error: %s has occurred. %s" % (req.status_code, req.reason))


def print_release_show_result(req):
    if req.status_code == 200:
        data = json.loads(req.text)

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


def _print_result_list(header_data_list, data_list):
    """
    Print a list of data in a simple table format
    :param header_data_list: Array of header data
    :param data_list: Array of data
    """

    # Find the longest header string in each column
    header_lengths = [len(str(x)) for x in header_data_list]
    # Find the longest content string in each column
    content_lengths = [max(len(str(x[i])) for x in data_list)
                       for i in range(len(header_data_list))]
    # Find the max of the two for each column
    col_lengths = [(x if x > y else y) for x, y in zip(header_lengths, content_lengths)]

    print('  '.join(f"{x.center(col_lengths[i])}" for i, x in enumerate(header_data_list)))
    print('  '.join('=' * length for length in col_lengths))
    for item in data_list:
        print('  '.join(f"{str(x).center(col_lengths[i])}" for i, x in enumerate(item)))
    print("\n")


def software_command_not_implemented_yet(args):
    print("NOT IMPLEMENTED %s" % args)
    return 1


def release_is_available_req(args):

    releases = "/".join(args.release)
    url = "http://%s/software/is_available/%s" % (api_addr, releases)

    headers = {}
    append_auth_token_if_required(headers)
    req = requests.post(url, headers=headers)

    rc = 1

    if req.status_code == 200:
        result = json.loads(req.text)
        print(result)
        if result is True:
            rc = 0
    elif req.status_code == 500:
        print("An internal error has occurred. Please check /var/log/software.log for details")
    else:
        print("Error: %s has occurred. %s" % (req.status_code, req.reason))

    return rc


def release_is_deployed_req(args):

    releases = "/".join(args.release)
    url = "http://%s/software/is_deployed/%s" % (api_addr, releases)

    headers = {}
    append_auth_token_if_required(headers)
    req = requests.post(url, headers=headers)

    rc = 1

    if req.status_code == 200:
        result = json.loads(req.text)
        print(result)
        if result is True:
            rc = 0
    elif req.status_code == 500:
        print("An internal error has occurred. Please check /var/log/software.log for details")
    else:
        print("Error: %s has occurred. %s" % (req.status_code, req.reason))

    return rc


def release_is_committed_req(args):

    releases = "/".join(args.release)
    url = "http://%s/software/is_committed/%s" % (api_addr, releases)

    headers = {}
    append_auth_token_if_required(headers)
    req = requests.post(url, headers=headers)

    rc = 1

    if req.status_code == 200:
        result = json.loads(req.text)
        print(result)
        if result is True:
            rc = 0
    elif req.status_code == 500:
        print("An internal error has occurred. Please check /var/log/software.log for details")
    else:
        print("Error: %s has occurred. %s" % (req.status_code, req.reason))

    return rc


def release_upload_req(args):
    rc = 0

    # arg.release is a list
    releases = args.release
    is_local = args.local  # defaults to False

    # Ignore interrupts during this function
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    to_upload_files = {}
    valid_files = []
    invalid_files = []

    # Validate all the files
    valid_files = [os.path.abspath(software_file) for software_file in releases if os.path.isfile(
        software_file) and os.path.splitext(software_file)[1] in constants.SUPPORTED_UPLOAD_FILE_EXT]
    invalid_files = [software_file for software_file in releases
                     if software_file not in valid_files]

    for software_file in invalid_files:
        if os.path.isdir(software_file):
            print("Error: %s is a directory. Please use upload-dir" % software_file)
        elif os.path.isfile(software_file):
            print("Error: %s has the unsupported file extension." % software_file)
        else:
            print("Error: File does not exist: %s" % software_file)

    if len(valid_files) == 0:
        print("No file to be uploaded.")
        return rc

    if is_local:
        to_upload_filenames = json.dumps(valid_files)
        headers = {'Content-Type': 'text/plain'}
    else:
        for software_file in valid_files:
            with open(software_file, 'rb') as file:
                data_content = file.read()
            to_upload_files[software_file] = (software_file, data_content)

        encoder = MultipartEncoder(fields=to_upload_files)
        headers = {'Content-Type': encoder.content_type}

    url = "http://%s/software/upload" % api_addr
    append_auth_token_if_required(headers)
    req = requests.post(url,
                        data=to_upload_filenames if is_local else encoder,
                        headers=headers)

    if args.debug:
        print_result_debug(req)
    else:
        print_software_op_result(req)
        data = json.loads(req.text)
        data_list = [(k, v["id"])
                     for d in data["upload_info"] for k, v in d.items()
                     if not k.endswith(".sig")]

        header_data_list = ["Uploaded File", "Id"]

        _print_result_list(header_data_list, data_list)
    if check_rc(req) != 0:
        # We hit a failure.  Update rc but keep looping
        rc = 1

    return rc


def release_delete_req(args):
    # arg.release is a list
    releases = "/".join(args.release)

    # Ignore interrupts during this function
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    url = "http://%s/software/delete/%s" % (api_addr, releases)

    headers = {}
    append_auth_token_if_required(headers)
    req = requests.post(url, headers=headers)

    if args.debug:
        print_result_debug(req)
    else:
        print_software_op_result(req)

    return check_rc(req)


def commit_patch_req(args):

    # Ignore interrupts during this function
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    # Default to running release
    # this all needs to be changed
    relopt = RUNNING_SW_VERSION

    headers = {}
    append_auth_token_if_required(headers)
    if args.sw_version and not args.all:
        # Disallow
        print("Use of --sw-version option requires --all")
        return 1
    elif args.all:
        # Get a list of all patches
        extra_opts = "&release=%s" % relopt
        url = "http://%s/software/query?show=patch%s" % (api_addr, extra_opts)

        req = requests.get(url, headers=headers)

        patch_list = []
        if req.status_code == 200:
            data = json.loads(req.text)

            if 'sd' in data:
                patch_list = sorted(list(data['sd']))
        elif req.status_code == 500:
            print("Failed to get patch list. Aborting...")
            return 1

        if len(patch_list) == 0:
            print("There are no %s patches to commit." % relopt)
            return 0

        print("The following patches will be committed:")
        for patch_id in patch_list:
            print("    %s" % patch_id)
        print()

        patches = "/".join(patch_list)
    else:
        # args.patch is a list
        patches = "/".join(args.patch)

        # First, get a list of dependencies and ask for confirmation
        url = "http://%s/software/query_dependencies/%s?recursive=yes" % (api_addr, patches)

        req = requests.get(url, headers=headers)

        if req.status_code == 200:
            data = json.loads(req.text)

            if 'patches' in data:
                print("The following patches will be committed:")
                for release_id in sorted(data['patches']):
                    print("    %s" % release_id)
                print()
            else:
                print("No patches found to commit")
                return 1

        elif req.status_code == 500:
            print("An internal error has occurred. Please check /var/log/software.log for details")
            return 1

    # Run dry-run
    url = "http://%s/software/commit_dry_run/%s" % (api_addr, patches)

    req = requests.post(url, headers=headers)
    print_software_op_result(req)

    if check_rc(req) != 0:
        print("Aborting...")
        return 1

    if args.dry_run:
        return 0

    print()
    commit_warning = "WARNING: Committing a patch is an irreversible operation. " + \
                     "Committed patches cannot be removed."
    print(textwrap.fill(commit_warning, width=TERM_WIDTH, subsequent_indent=' ' * 9))
    print()

    user_input = input("Would you like to continue? [y/N]: ")
    if user_input.lower() != 'y':
        print("Aborting...")
        return 1

    url = "http://%s/software/commit_patch/%s" % (api_addr, patches)
    req = requests.post(url, headers=headers)

    if args.debug:
        print_result_debug(req)
    else:
        print_software_op_result(req)

    return check_rc(req)


def release_list_req(args):
    state = args.state  # defaults to "all"
    extra_opts = ""
    if args.release:
        extra_opts = "&release=%s" % args.release
    url = "http://%s/software/query?show=%s%s" % (api_addr, state, extra_opts)
    headers = {}
    append_auth_token_if_required(headers)
    req = requests.get(url, headers=headers)

    if args.debug:
        print_result_debug(req)
    else:
        header_data_list = ["Release", "RR", "State"]
        data = json.loads(req.text)
        data_list = [(k, v["reboot_required"], v["state"]) for k, v in data["sd"].items()]
        _print_result_list(header_data_list, data_list)

    return check_rc(req)


def print_software_deploy_host_list_result(req):
    if req.status_code == 200:
        data = json.loads(req.text)
        if 'data' not in data:
            print("Invalid data returned:")
            print_result_debug(req)
            return

        agents = data['data']

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

        for agent in sorted(agents, key=lambda a: a["hostname"]):
            if agent.get("deploy_host_state") is None:
                agent["deploy_host_state"] = "No active deployment"
            if agent.get("to_release") is None:
                agent["to_release"] = "N/A"
            if len(agent["hostname"]) > width_hn:
                width_hn = len(agent["hostname"])
            if len(agent["sw_version"]) > width_rel:
                width_rel = len(agent["sw_version"])
            if len(agent["to_release"]) > width_tg_rel:
                width_tg_rel = len(agent["to_release"])
            if len(agent["deploy_host_state"]) > width_state:
                width_state = len(agent["deploy_host_state"])

        print("{0:^{width_hn}}  {1:^{width_rel}}  {2:^{width_tg_rel}}  {3:^{width_rr}}  {4:^{width_state}}".format(
            hdr_hn, hdr_rel, hdr_tg_rel, hdr_rr, hdr_state,
            width_hn=width_hn, width_rel=width_rel, width_tg_rel=width_tg_rel, width_rr=width_rr, width_state=width_state))

        print("{0}  {1}  {2}  {3}  {4}".format(
            '=' * width_hn, '=' * width_rel, '=' * width_tg_rel, '=' * width_rr, '=' * width_state))

        for agent in sorted(agents, key=lambda a: a["hostname"]):
            print("{0:<{width_hn}}  {1:^{width_rel}}  {2:^{width_tg_rel}}  {3:^{width_rr}}  {4:^{width_state}}".format(
                agent["hostname"],
                agent["sw_version"],
                agent["to_release"],
                "Yes" if agent.get("reboot_required", None) else "No",
                agent["deploy_host_state"],
                width_hn=width_hn, width_rel=width_rel, width_tg_rel=width_tg_rel, width_rr=width_rr, width_state=width_state))

    elif req.status_code == 500:
        print("An internal error has occurred. Please check /var/log/software.log for details")


def deploy_host_list_req(args):
    url = "http://%s/software/host_list" % api_addr
    req = requests.get(url)
    if args.debug:
        print_result_debug(req)
    else:
        print_software_deploy_host_list_result(req)

    return check_rc(req)


def release_show_req(args):
    # arg.release is a list
    releases = "/".join(args.release)

    url = "http://%s/software/show/%s" % (api_addr, releases)

    headers = {}
    append_auth_token_if_required(headers)
    # todo(abailey): convert this to a GET
    req = requests.post(url, headers=headers)

    if args.debug:
        print_result_debug(req)
    else:
        print_release_show_result(req)

    return check_rc(req)


def wait_for_install_complete(agent_ip):
    url = "http://%s/software/host_list" % api_addr
    rc = 0

    max_retries = 4
    retriable_count = 0

    while True:
        # Sleep on the first pass as well, to allow time for the
        # agent to respond
        time.sleep(5)

        try:
            req = requests.get(url)
        except requests.exceptions.ConnectionError:
            # The local software-controller may have restarted.
            retriable_count += 1
            if retriable_count <= max_retries:
                continue
            else:
                print("Lost communications with the software controller")
                rc = 1
                break

        if req.status_code == 200:
            data = json.loads(req.text)
            if 'data' not in data:
                print("Invalid host-list data returned:")
                print_result_debug(req)
                rc = 1
                break

            state = None
            agents = data['data']
            interim_state = None

            for agent in agents:
                if agent['hostname'] == agent_ip \
                   or agent['ip'] == agent_ip:
                    state = agent.get('state')
                    interim_state = agent.get('interim_state')

            if state is None:
                # If the software daemons have restarted, there's a
                # window after the software-controller restart that the
                # hosts table will be empty.
                retriable_count += 1
                if retriable_count <= max_retries:
                    continue
                else:
                    print("%s agent has timed out." % agent_ip)
                    rc = 1
                    break

            if state == constants.PATCH_AGENT_STATE_INSTALLING or \
                    interim_state is True:
                # Still installing
                sys.stdout.write(".")
                sys.stdout.flush()
            elif state == constants.PATCH_AGENT_STATE_INSTALL_REJECTED:
                print("\nInstallation rejected. Node must be locked")
                rc = 1
                break
            elif state == constants.PATCH_AGENT_STATE_INSTALL_FAILED:
                print("\nInstallation failed. Please check logs for details.")
                rc = 1
                break
            elif state == constants.PATCH_AGENT_STATE_IDLE:
                print("\nInstallation was successful.")
                rc = 0
                break
            else:
                print("\nPatch agent is reporting unknown state: %s" % state)
                rc = 1
                break

        elif req.status_code == 500:
            print("An internal error has occurred. Please check /var/log/software.log for details")
            rc = 1
            break
        else:
            m = re.search("(Error message:.*)", req.text, re.MULTILINE)
            if m:
                print(m.group(0))
            else:
                print(vars(req))
            rc = 1
            break

    return rc


def host_install(args):
    rc = 0
    agent_ip = args.agent

    # Issue deploy_host request and poll for results
    url = "http://%s/software/deploy_host/%s" % (api_addr, agent_ip)

    if args.force:
        url += "/force"

    req = requests.post(url)

    if req.status_code == 200:
        data = json.loads(req.text)
        if 'error' in data and data["error"] != "":
            print("Error:")
            print(data["error"])
            rc = 1
        else:
            rc = wait_for_install_complete(agent_ip)
    elif req.status_code == 500:
        print("An internal error has occurred. "
              "Please check /var/log/software.log for details")
        rc = 1
    else:
        m = re.search("(Error message:.*)", req.text, re.MULTILINE)
        if m:
            print(m.group(0))
        else:
            print("%s %s" % (req.status_code, req.reason))
        rc = 1

    return rc


def drop_host(args):
    host_ip = args.host

    url = "http://%s/software/drop_host/%s" % (api_addr, host_ip)

    req = requests.post(url)

    if args.debug:
        print_result_debug(req)
    else:
        print_software_op_result(req)

    return check_rc(req)


def install_local(args):  # pylint: disable=unused-argument
    # Ignore interrupts during this function
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    url = "http://%s/software/install_local" % (api_addr)

    headers = {}
    append_auth_token_if_required(headers)
    req = requests.get(url, headers=headers)

    if args.debug:
        print_result_debug(req)
    else:
        print_software_op_result(req)

    return check_rc(req)


def release_upload_dir_req(args):
    # arg.release is a list
    release_dirs = args.release

    # Ignore interrupts during this function
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    to_upload_files = {}
    raw_files = []

    # Find all files that need to be uploaded in given directories
    for release_dir in release_dirs:
        raw_files = [f for f in os.listdir(release_dir)
                     if os.path.isfile(os.path.join(release_dir, f))]

        # Get absolute path of files
        raw_files = [os.path.abspath(os.path.join(release_dir, f)) for f in raw_files]

    for software_file in sorted(set(raw_files)):
        _, ext = os.path.splitext(software_file)
        if ext in constants.SUPPORTED_UPLOAD_FILE_EXT:
            to_upload_files[software_file] = (software_file, open(software_file, 'rb'))

    encoder = MultipartEncoder(fields=to_upload_files)
    url = "http://%s/software/upload" % api_addr
    headers = {'Content-Type': encoder.content_type}
    append_auth_token_if_required(headers)
    req = requests.post(url,
                        data=encoder,
                        headers=headers)
    if args.debug:
        print_result_debug(req)
    else:
        print_software_op_result(req)
    return check_rc(req)


def deploy_precheck_req(args):
    # args.deployment is a string
    deployment = args.deployment

    # args.region is a string
    region_name = args.region_name

    # Issue deploy_precheck request
    url = "http://%s/software/deploy_precheck/%s" % (api_addr, deployment)
    if args.force:
        url += "/force"
    url += "?region_name=%s" % region_name

    headers = {}
    append_auth_token_if_required(headers)
    req = requests.post(url, headers=headers)

    if args.debug:
        print_result_debug(req)
    else:
        print_software_op_result(req)

    return check_rc(req)


def deploy_start_req(args):
    # args.deployment is a string
    deployment = args.deployment

    # Ignore interrupts during this function
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    # Issue deploy_start request
    url = "http://%s/software/deploy_start/%s" % (api_addr, deployment)

    headers = {}
    append_auth_token_if_required(headers)
    req = requests.post(url, headers=headers)

    if args.debug:
        print_result_debug(req)
    else:
        print_software_op_result(req)

    return check_rc(req)


def deploy_activate_req(args):
    # args.deployment is a string
    deployment = args.deployment

    # Ignore interrupts during this function
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    # Issue deploy_start request
    url = "http://%s/software/deploy_activate/%s" % (api_addr, deployment)

    headers = {}
    append_auth_token_if_required(headers)
    req = requests.post(url, headers=headers)

    if args.debug:
        print_result_debug(req)
    else:
        print_software_op_result(req)

    return check_rc(req)


def deploy_complete_req(args):
    # args.deployment is a string
    deployment = args.deployment

    # Ignore interrupts during this function
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    # Issue deploy_complete request
    url = "http://%s/software/deploy_complete/%s" % (api_addr, deployment)

    headers = {}
    append_auth_token_if_required(headers)
    req = requests.post(url, headers=headers)

    if args.debug:
        print_result_debug(req)
    else:
        print_software_op_result(req)

    return check_rc(req)


def deploy_show_req(args):
    url = "http://%s/software/deploy_show" % api_addr
    headers = {}
    append_auth_token_if_required(headers)
    req = requests.get(url, headers=headers)

    if req.status_code >= 500:
        print("An internal error has occurred. Please check /var/log/software.log for details")
        return 1
    elif req.status_code >= 400:
        print("Respond code %d. Error: %s" % (req.status_code, req.reason))
        return 1

    data = json.loads(req.text)
    if not data:
        print("No deploy in progress.\n")
    else:
        data["reboot_required"] = "Yes" if data.get("reboot_required") else "No"
        data_list = [[k, v] for k, v in data.items()]
        transposed_data_list = list(zip(*data_list))

        transposed_data_list[0] = [s.title().replace('_', ' ') for s in transposed_data_list[0]]
        # Find the longest header string in each column
        header_lengths = [len(str(x)) for x in transposed_data_list[0]]
        # Find the longest content string in each column
        content_lengths = [len(str(x)) for x in transposed_data_list[1]]
        # Find the max of the two for each column
        col_lengths = [(x if x > y else y) for x, y in zip(header_lengths, content_lengths)]

        print('  '.join(f"{x.center(col_lengths[i])}" for i,
              x in enumerate(transposed_data_list[0])))
        print('  '.join('=' * length for length in col_lengths))
        print('  '.join(f"{x.center(col_lengths[i])}" for i,
              x in enumerate(transposed_data_list[1])))

    return 0


def deploy_host_req(args):
    rc = 0
    agent_ip = args.agent

    # Issue deploy_host request and poll for results
    url = "http://%s/software/deploy_host/%s" % (api_addr, agent_ip)

    if args.force:
        url += "/force"

    req = requests.post(url)

    if req.status_code == 200:
        data = json.loads(req.text)
        if 'error' in data and data["error"] != "":
            print("Error:")
            print(data["error"])
            rc = 1
        else:
            rc = wait_for_install_complete(agent_ip)
    elif req.status_code == 500:
        print("An internal error has occurred. "
              "Please check /var/log/software.log for details")
        rc = 1
    else:
        m = re.search("(Error message:.*)", req.text, re.MULTILINE)
        if m:
            print(m.group(0))
        else:
            print("%s %s" % (req.status_code, req.reason))
        rc = 1
    return rc


def patch_init_release(args):
    # Ignore interrupts during this function
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    release = args.release

    url = "http://%s/software/init_release/%s" % (api_addr, release)

    req = requests.post(url)

    if args.debug:
        print_result_debug(req)
    else:
        print_software_op_result(req)

    return check_rc(req)


def patch_del_release(args):
    # Ignore interrupts during this function
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    release = args.release

    url = "http://%s/software/del_release/%s" % (api_addr, release)

    req = requests.post(url)

    if args.debug:
        print_result_debug(req)
    else:
        print_software_op_result(req)

    return check_rc(req)


def patch_report_app_dependencies_req(args):  # pylint: disable=unused-argument
    extra_opts = [args.app]
    extra_opts_str = '?%s' % '&'.join(extra_opts)

    patches = "/".join(args)
    url = "http://%s/software/report_app_dependencies/%s%s" \
          % (api_addr, patches, extra_opts_str)

    headers = {}
    append_auth_token_if_required(headers)
    req = requests.post(url, headers=headers)

    if req.status_code == 200:
        return 0
    else:
        print("An internal error has occurred. "
              "Please check /var/log/software.log for details.")
        return 1


def patch_query_app_dependencies_req():
    url = "http://%s/software/query_app_dependencies" % api_addr

    headers = {}
    append_auth_token_if_required(headers)
    req = requests.post(url, headers=headers)

    if req.status_code == 200:
        data = json.loads(req.text)
        if len(data) == 0:
            print("There are no application dependencies.")
        else:
            hdr_app = "Application"
            hdr_list = "Required Patches"
            width_app = len(hdr_app)
            width_list = len(hdr_list)

            for app, patch_list in data.items():
                width_app = max(width_app, len(app))
                width_list = max(width_list, len(', '.join(patch_list)))

            print("{0:<{width_app}}  {1:<{width_list}}".format(
                hdr_app, hdr_list,
                width_app=width_app, width_list=width_list))

            print("{0}  {1}".format(
                '=' * width_app, '=' * width_list))

            for app, patch_list in sorted(data.items()):
                print("{0:<{width_app}}  {1:<{width_list}}".format(
                    app, ', '.join(patch_list),
                    width_app=width_app, width_list=width_list))

        return 0
    else:
        print("An internal error has occurred. "
              "Please check /var/log/software.log for details.")
        return 1


def check_env(env, var):
    if env not in os.environ:
        print("You must provide a %s via env[%s]" % (var, env))
        exit(-1)


def get_auth_token_and_endpoint(region_name):
    from keystoneauth1 import exceptions
    from keystoneauth1 import identity
    from keystoneauth1 import session

    user_env_map = {'OS_USERNAME': 'username',
                    'OS_PASSWORD': 'password',
                    'OS_PROJECT_NAME': 'project_name',
                    'OS_AUTH_URL': 'auth_url',
                    'OS_USER_DOMAIN_NAME': 'user_domain_name',
                    'OS_PROJECT_DOMAIN_NAME': 'project_domain_name'}

    for k, v in user_env_map.items():
        check_env(k, v)

    user = dict()
    for k, v in user_env_map.items():
        user[v] = os.environ.get(k)

    auth = identity.V3Password(**user)
    sess = session.Session(auth=auth)
    try:
        token = auth.get_token(sess)
        endpoint = auth.get_endpoint(sess, service_type='usm',
                                     interface='internal',
                                     region_name=region_name)
    except (exceptions.http.Unauthorized, exceptions.EndpointNotFound) as e:
        print(str(e))
        exit(-1)

    return token, endpoint


def append_auth_token_if_required(headers):
    global auth_token
    if auth_token is not None:
        headers['X-Auth-Token'] = auth_token


def format_url_address(address):
    import netaddr
    try:
        ip_addr = netaddr.IPAddress(address)
        if ip_addr.version == IPV6_FAMILY:
            return "[%s]" % address
        else:
            return address
    except netaddr.AddrFormatError:
        return address


def check_for_os_region_name(args):
    # argparse converts os-region-name to os_region_name
    region = args.os_region_name
    if region is None:
        return False

    global VIRTUAL_REGION
    if region != VIRTUAL_REGION:
        print("Unsupported region name: %s" % region)
        exit(1)

    # check it is running on the active controller
    # not able to use sm-query due to it requires sudo
    try:
        subprocess.check_output("pgrep -f dcorch-api-proxy", shell=True)
    except subprocess.CalledProcessError:
        print("Command must be run from the active controller.")
        exit(1)

    # get a token and fetch the internal endpoint in SystemController
    global auth_token
    auth_token, endpoint = get_auth_token_and_endpoint(region)
    if endpoint is not None:
        global api_addr
        url = urlparse(endpoint)
        address = format_url_address(url.hostname)
        api_addr = '{}:{}'.format(address, url.port)

    return True


def register_deploy_commands(commands):
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
    cmd_parser = commands.add_parser(
        cmd_area,
        help='Software Deploy',
        epilog="StarlingX Unified Software Deployment"
    )
    cmd_parser.set_defaults(cmd_area=cmd_area)

    # Deploy commands are region_restricted, which means
    # that they are not permitted to be run in DC
    cmd_parser.set_defaults(region_restricted=True)

    sub_cmds = cmd_parser.add_subparsers(
        title='Software Deploy Commands',
        metavar=''
    )
    sub_cmds.required = True

    # --- software deploy precheck -----------------------
    cmd = sub_cmds.add_parser(
        'precheck',
        help='Verify whether prerequisites for installing the software deployment are satisfied'
    )
    cmd.set_defaults(cmd='precheck')
    cmd.set_defaults(func=deploy_precheck_req)
    cmd.add_argument('deployment',
                     help='Verify if prerequisites are met for this Deployment ID')
    cmd.add_argument('-f',
                     '--force',
                     action='store_true',
                     required=False,
                     help='Allow bypassing non-critical checks')
    cmd.add_argument('--region_name',
                     default='RegionOne',
                     required=False,
                     help='Run precheck against a subcloud')

    # --- software deploy start --------------------------
    cmd = sub_cmds.add_parser(
        'start',
        help='Start the software deployment'
    )
    cmd.set_defaults(cmd='start')
    cmd.set_defaults(func=deploy_start_req)
    cmd.add_argument('deployment',
                     help='Deployment ID to start')

    # --- software deploy host ---------------------------
    cmd = sub_cmds.add_parser(
        'host',
        help='Deploy prestaged software deployment to the host'
    )
    cmd.set_defaults(cmd='host')
    cmd.set_defaults(func=deploy_host_req)
    cmd.add_argument('agent',
                     help="Agent on which host deploy is triggered")
    cmd.add_argument('-f',
                     '--force',
                     action='store_true',
                     required=False,
                     help="Force deploy host")

    # --- software deploy activate -----------------------
    cmd = sub_cmds.add_parser(
        'activate',
        help='Activate the software deployment'
    )
    cmd.set_defaults(cmd='activate')
    cmd.set_defaults(func=deploy_activate_req)
    cmd.add_argument('deployment',
                     help='Deployment ID to activate')

    # --- software deploy complete -----------------------
    cmd = sub_cmds.add_parser(
        'complete',
        help='Complete the software deployment'
    )
    cmd.set_defaults(cmd='complete')
    cmd.set_defaults(func=deploy_complete_req)
    cmd.add_argument('deployment',
                     help='Deployment ID to complete')

    # --- software deploy show ---------------------------
    cmd = sub_cmds.add_parser(
        'show',
        help='Show the software deployments states'
    )
    cmd.set_defaults(cmd='show')
    cmd.set_defaults(func=deploy_show_req)
    cmd.set_defaults(restricted=False)  # can run non root
    # --deployment is an optional argument
    cmd.add_argument('--deployment',
                     required=False,
                     help='List the deployment specified')
    # --state is an optional argument.
    # default: "all"
    # acceptable values: inactive, active, prestaging, prestaged, all
    cmd.add_argument('--state',
                     default="all",
                     required=False,
                     help='List all deployments that have this state')

    # --- software deploy host-list -------------
    cmd = sub_cmds.add_parser(
        'host-list',
        help='List of hosts for software deployment'
    )
    cmd.set_defaults(cmd='host-list')
    cmd.set_defaults(func=deploy_host_list_req)
    cmd.set_defaults(restricted=False)  # can run non root


def setup_argparse():
    parser = argparse.ArgumentParser(prog="software",
                                     description="Unified Software Management",
                                     epilog="Used for patching and upgrading")
    parser.add_argument('--debug', action='store_true', help="Enable debug output")
    # parser.add_argument('--os-auth-url', default=None)
    # parser.add_argument('--os-project-name', default=None)
    # parser.add_argument('--os-project-domain-name', default=None)
    # parser.add_argument('--os-username', default=None)
    # parser.add_argument('--os-password', default=None)
    # parser.add_argument('--os-user-domain-name', default=None)
    parser.add_argument('--os-region-name', default=None)
    # parser.add_argument('--os-interface', default=None)

    # All commands are considered restricted, unless explicitly set to False
    parser.set_defaults(restricted=True)
    # All functions are initially defined as 'not implemented yet'
    # The func will be overridden by the command definition as they are completed
    parser.set_defaults(func=software_command_not_implemented_yet)

    # No commands are region restricted, unless explicitly set to True
    parser.set_defaults(region_restricted=False)

    commands = parser.add_subparsers(title='Commands', metavar='')
    commands.required = True

    # -- software commit-patch <release> ---------------
    cmd = commands.add_parser(
        'commit-patch',
        help='Commit patches to free disk space. WARNING: This action is irreversible!'
    )
    cmd.set_defaults(cmd='commit-patch')
    cmd.set_defaults(func=commit_patch_req)
    cmd.add_argument('patch',
                     nargs="+",  # accepts a list
                     help='Patch ID/s to commit')
    # --dry-run is an optional argument
    cmd.add_argument('--dry-run',
                     action='store_true',
                     required=False,
                     help='Check the space savings without committing the patch')
    # --all is an optional argument
    cmd.add_argument('--all',
                     action='store_true',
                     required=False,
                     help='Commit all the applied patches')
    # --sw-version is an optional argument
    cmd.add_argument('--sw-version',
                     required=False,
                     help='Software release version')

    # -- software delete <release> ---------------
    cmd = commands.add_parser(
        'delete',
        help='Delete the software release'
    )
    cmd.set_defaults(cmd='delete')
    cmd.set_defaults(func=release_delete_req)
    cmd.add_argument('release',
                     nargs="+",  # accepts a list
                     help='Release ID to delete')

    # -- software install-local ---------------
    cmd = commands.add_parser(
        'install-local',
        help='Trigger patch install/remove on the local host. ' +
             'This command can only be used for patch installation ' +
             'prior to initial configuration.'
    )
    cmd.set_defaults(cmd='install-local')
    cmd.set_defaults(func=install_local)

    # --- software is-available <release> ------
    cmd = commands.add_parser(
        'is-available',
        help='Query Available state for list of releases. Returns True if all are Available, False otherwise.'
    )
    cmd.set_defaults(cmd='is-available')
    cmd.set_defaults(func=release_is_available_req)
    cmd.add_argument('release',
                     nargs="+",  # accepts a list
                     help='List of releases')

    # --- software is-committed <release> ------
    cmd = commands.add_parser(
        'is-committed',
        help='Query Committed state for list of releases. Returns True if all are Committed, False otherwise.'
    )
    cmd.set_defaults(cmd='is-committed')
    cmd.set_defaults(func=release_is_committed_req)
    cmd.add_argument('release',
                     nargs="+",  # accepts a list
                     help='List of releases')

    # --- software is-deployed  <release> ------
    cmd = commands.add_parser(
        'is-deployed',
        help='Query Deployed state for list of releases. Returns True if all are Deployed, False otherwise.'
    )
    cmd.set_defaults(cmd='is-deployed')
    cmd.set_defaults(func=release_is_deployed_req)
    cmd.add_argument('release',
                     nargs="+",  # accepts a list
                     help='List of releases')

    # --- software list ---------------------------
    cmd = commands.add_parser(
        'list',
        help='List the software releases'
    )
    cmd.set_defaults(cmd='list')
    cmd.set_defaults(func=release_list_req)
    cmd.set_defaults(restricted=False)  # can run non root
    # --release is an optional argument
    cmd.add_argument('--release',
                     required=False,
                     help='filter against a release ID')
    # --state is an optional argument. default: "all"
    cmd.add_argument('--state',
                     default="all",
                     required=False,
                     help='filter against a release state')

    # --- software show <release> -----------------
    cmd = commands.add_parser(
        'show',
        help='Show the software release'
    )
    cmd.set_defaults(cmd='show')
    cmd.set_defaults(func=release_show_req)
    cmd.set_defaults(restricted=False)  # can run non root
    cmd.add_argument('release',
                     nargs="+",  # accepts a list
                     help='Release ID to show')

    # --- software upload <release> ---------------
    cmd = commands.add_parser(
        'upload',
        help='Upload a software release'
    )
    cmd.set_defaults(cmd='upload')
    cmd.set_defaults(func=release_upload_req)
    cmd.add_argument('release',
                     nargs="+",  # accepts a list
                     help='software releases to upload')
    cmd.add_argument('--local',
                     required=False,
                     default=False,
                     action='store_true',
                     help='Upload files from active controller')

    # --- software upload-dir <release dir> ------
    cmd = commands.add_parser(
        'upload-dir',
        help='Upload a software release dir'
    )
    cmd.set_defaults(cmd='upload-dir')
    cmd.set_defaults(func=release_upload_dir_req)
    cmd.add_argument('release',
                     nargs="+",  # accepts a list
                     help='directory containing software releases to upload')

    register_deploy_commands(commands)
    return parser


def main():
    set_term_width()

    rc = 0
    parser = setup_argparse()
    argcomplete.autocomplete(parser)
    args = parser.parse_args()
    dc_request = check_for_os_region_name(args)

    # Reject the commands that are not supported in the virtual region
    if dc_request and args.region_restricted:
        global VIRTUAL_REGION
        print("\n%s %s command is not allowed in %s region" % (args.cmd_area,
                                                               args.cmd,
                                                               VIRTUAL_REGION))
        rc = 1
        exit(rc)

    if auth_token is None and os.geteuid() != 0:
        if args.restricted:
            print("Error: Command must be run as sudo or root", file=sys.stderr)
            rc = 1
            exit(rc)

    # Call the function registered with argparse, and pass the 'args' to it
    rc = args.func(args)
    exit(rc)
