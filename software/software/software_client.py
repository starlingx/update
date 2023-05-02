"""
Copyright (c) 2023 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import argparse
import json
import os
import re
import requests
import signal
import subprocess
import sys
import textwrap
import time

from requests_toolbelt import MultipartEncoder
from urllib.parse import urlparse

import software.constants as constants

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
        if 'pd' in data:
            print(json.dumps(data['pd'],
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

        if 'pd' in data:
            pd = data['pd']

            # Calculate column widths
            hdr_id = "Patch ID"
            hdr_rr = "RR"
            hdr_rel = "Release"
            hdr_repo = "Repo State"
            hdr_state = "Patch State"

            width_id = len(hdr_id)
            width_rr = len(hdr_rr)
            width_rel = len(hdr_rel)
            width_repo = len(hdr_repo)
            width_state = len(hdr_state)

            show_repo = False

            for patch_id in list(pd):
                if len(patch_id) > width_id:
                    width_id = len(patch_id)
                if len(pd[patch_id]["sw_version"]) > width_rel:
                    width_rel = len(pd[patch_id]["sw_version"])
                if len(pd[patch_id]["repostate"]) > width_repo:
                    width_repo = len(pd[patch_id]["repostate"])
                if len(pd[patch_id]["patchstate"]) > width_state:
                    width_state = len(pd[patch_id]["patchstate"])
                if pd[patch_id]["patchstate"] == "n/a":
                    show_repo = True

            if show_repo:
                print("{0:^{width_id}}  {1:^{width_rr}}  {2:^{width_rel}}  {3:^{width_repo}}  {4:^{width_state}}".format(
                    hdr_id, hdr_rr, hdr_rel, hdr_repo, hdr_state,
                    width_id=width_id, width_rr=width_rr,
                    width_rel=width_rel, width_repo=width_repo, width_state=width_state))

                print("{0}  {1}  {2}  {3}  {4}".format(
                    '=' * width_id, '=' * width_rr, '=' * width_rel, '=' * width_repo, '=' * width_state))

                for patch_id in sorted(list(pd)):
                    if "reboot_required" in pd[patch_id]:
                        rr = pd[patch_id]["reboot_required"]
                    else:
                        rr = "Y"

                    print("{0:<{width_id}}  {1:^{width_rr}}  {2:^{width_rel}}  {3:^{width_repo}}  {4:^{width_state}}".format(
                        patch_id,
                        rr,
                        pd[patch_id]["sw_version"],
                        pd[patch_id]["repostate"],
                        pd[patch_id]["patchstate"],
                        width_id=width_id, width_rr=width_rr,
                        width_rel=width_rel, width_repo=width_repo, width_state=width_state))
            else:
                print("{0:^{width_id}}  {1:^{width_rr}}  {2:^{width_rel}}  {3:^{width_state}}".format(
                    hdr_id, hdr_rr, hdr_rel, hdr_state,
                    width_id=width_id, width_rr=width_rr, width_rel=width_rel, width_state=width_state))

                print("{0}  {1}  {2}  {3}".format(
                    '=' * width_id, '=' * width_rr, '=' * width_rel, '=' * width_state))

                for patch_id in sorted(list(pd)):
                    if "reboot_required" in pd[patch_id]:
                        rr = pd[patch_id]["reboot_required"]
                    else:
                        rr = "Y"

                    print("{0:<{width_id}}  {1:^{width_rr}}  {2:^{width_rel}}  {3:^{width_state}}".format(
                        patch_id,
                        rr,
                        pd[patch_id]["sw_version"],
                        pd[patch_id]["patchstate"],
                        width_id=width_id, width_rr=width_rr, width_rel=width_rel, width_state=width_state))

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


def print_patch_show_result(req):
    if req.status_code == 200:
        data = json.loads(req.text)

        if 'metadata' in data:
            pd = data['metadata']
            contents = data['contents']
            for patch_id in sorted(list(pd)):
                print("%s:" % patch_id)

                if "sw_version" in pd[patch_id] and pd[patch_id]["sw_version"] != "":
                    print(textwrap.fill("    {0:<15} ".format("Release:") + pd[patch_id]["sw_version"],
                                        width=TERM_WIDTH, subsequent_indent=' ' * 20))

                if "patchstate" in pd[patch_id] and pd[patch_id]["patchstate"] != "":
                    print(textwrap.fill("    {0:<15} ".format("Patch State:") + pd[patch_id]["patchstate"],
                                        width=TERM_WIDTH, subsequent_indent=' ' * 20))

                    if pd[patch_id]["patchstate"] == "n/a":
                        if "repostate" in pd[patch_id] and pd[patch_id]["repostate"] != "":
                            print(textwrap.fill("    {0:<15} ".format("Repo State:") + pd[patch_id]["repostate"],
                                                width=TERM_WIDTH, subsequent_indent=' ' * 20))

                if "status" in pd[patch_id] and pd[patch_id]["status"] != "":
                    print(textwrap.fill("    {0:<15} ".format("Status:") + pd[patch_id]["status"],
                                        width=TERM_WIDTH, subsequent_indent=' ' * 20))

                if "unremovable" in pd[patch_id] and pd[patch_id]["unremovable"] != "":
                    print(textwrap.fill("    {0:<15} ".format("Unremovable:") + pd[patch_id]["unremovable"],
                                        width=TERM_WIDTH, subsequent_indent=' ' * 20))

                if "reboot_required" in pd[patch_id] and pd[patch_id]["reboot_required"] != "":
                    print(textwrap.fill("    {0:<15} ".format("RR:") + pd[patch_id]["reboot_required"],
                                        width=TERM_WIDTH, subsequent_indent=' ' * 20))

                if "apply_active_release_only" in pd[patch_id] and pd[patch_id]["apply_active_release_only"] != "":
                    print(textwrap.fill("    {0:<15} ".format("Apply Active Release Only:") + pd[patch_id]["apply_active_release_only"],
                                        width=TERM_WIDTH, subsequent_indent=' ' * 20))

                if "summary" in pd[patch_id] and pd[patch_id]["summary"] != "":
                    print(textwrap.fill("    {0:<15} ".format("Summary:") + pd[patch_id]["summary"],
                                        width=TERM_WIDTH, subsequent_indent=' ' * 20))

                if "description" in pd[patch_id] and pd[patch_id]["description"] != "":
                    first_line = True
                    for line in pd[patch_id]["description"].split('\n'):
                        if first_line:
                            print(textwrap.fill("    {0:<15} ".format("Description:") + line,
                                                width=TERM_WIDTH, subsequent_indent=' ' * 20))
                            first_line = False
                        else:
                            print(textwrap.fill(line,
                                                width=TERM_WIDTH, subsequent_indent=' ' * 20,
                                                initial_indent=' ' * 20))

                if "install_instructions" in pd[patch_id] and pd[patch_id]["install_instructions"] != "":
                    print("    Install Instructions:")
                    for line in pd[patch_id]["install_instructions"].split('\n'):
                        print(textwrap.fill(line,
                                            width=TERM_WIDTH, subsequent_indent=' ' * 20,
                                            initial_indent=' ' * 20))

                if "warnings" in pd[patch_id] and pd[patch_id]["warnings"] != "":
                    first_line = True
                    for line in pd[patch_id]["warnings"].split('\n'):
                        if first_line:
                            print(textwrap.fill("    {0:<15} ".format("Warnings:") + line,
                                                width=TERM_WIDTH, subsequent_indent=' ' * 20))
                            first_line = False
                        else:
                            print(textwrap.fill(line,
                                                width=TERM_WIDTH, subsequent_indent=' ' * 20,
                                                initial_indent=' ' * 20))

                if "requires" in pd[patch_id] and len(pd[patch_id]["requires"]) > 0:
                    print("    Requires:")
                    for req_patch in sorted(pd[patch_id]["requires"]):
                        print(' ' * 20 + req_patch)

                if "contents" in data and patch_id in data["contents"]:
                    print("    Contents:\n")
                    if "number_of_commits" in contents[patch_id] and \
                            contents[patch_id]["number_of_commits"] != "":
                        print(textwrap.fill("    {0:<15} ".format("No. of commits:") +
                                            contents[patch_id]["number_of_commits"],
                                            width=TERM_WIDTH, subsequent_indent=' ' * 20))
                    if "base" in contents[patch_id] and \
                            contents[patch_id]["base"]["commit"] != "":
                        print(textwrap.fill("    {0:<15} ".format("Base commit:") +
                                            contents[patch_id]["base"]["commit"],
                                            width=TERM_WIDTH, subsequent_indent=' ' * 20))
                    if "number_of_commits" in contents[patch_id] and \
                            contents[patch_id]["number_of_commits"] != "":
                        for i in range(int(contents[patch_id]["number_of_commits"])):
                            print(textwrap.fill("    {0:<15} ".format("Commit%s:" % (i + 1)) +
                                                contents[patch_id]["commit%s" % (i + 1)]["commit"],
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


def software_command_not_implemented_yet(args):
    print("NOT IMPLEMENTED %s" % args)
    return 1


def release_upload_req(args):
    rc = 0

    # arg.release is a list
    releases = args.release

    # Ignore interrupts during this function
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    for patchfile in sorted(list(set(releases))):
        if os.path.isdir(patchfile):
            print("Error: %s is a directory. Please use upload-dir" % patchfile)
            continue

        if not os.path.isfile(patchfile):
            print("Error: File does not exist: %s" % patchfile)
            continue

        enc = MultipartEncoder(fields={'file': (patchfile,
                                                open(patchfile, 'rb'),
                                                )})
        url = "http://%s/software/upload" % api_addr
        headers = {'Content-Type': enc.content_type}
        append_auth_token_if_required(headers)
        req = requests.post(url,
                            data=enc,
                            headers=headers)

        if args.debug:
            print_result_debug(req)
        else:
            print_software_op_result(req)

        if check_rc(req) != 0:
            rc = 1

    return rc


def patch_apply_req(args):
    print("patch_apply_req UNDER CONSTRUCTION")

    # Ignore interrupts during this function
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    extra_opts = []

    if "--skip-semantic" in args:
        idx = args.index("--skip-semantic")

        # Get rid of the --skip-semantic
        args.pop(idx)

        # Append the extra opts
        extra_opts.append("skip-semantic=yes")

    if len(extra_opts) == 0:
        extra_opts_str = ''
    else:
        extra_opts_str = '?%s' % '&'.join(extra_opts)

    patches = "/".join(args)
    url = "http://%s/software/apply/%s%s" % (api_addr, patches, extra_opts_str)

    headers = {}
    append_auth_token_if_required(headers)
    req = requests.post(url, headers=headers)

    if args.debug:
        print_result_debug(req)
    else:
        print_software_op_result(req)

    return check_rc(req)


def patch_remove_req(args):
    print("patch_remove_req UNDER CONSTRUCTION")

    # Ignore interrupts during this function
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    extra_opts = []

    # The removeunremovable option is hidden and should not be added to help
    # text or customer documentation. It is for emergency use only - under
    # supervision of the design team.
    if "--removeunremovable" in args:
        idx = args.index("--removeunremovable")

        # Get rid of the --removeunremovable
        args.pop(idx)

        # Append the extra opts
        extra_opts.append('removeunremovable=yes')

    if "--skipappcheck" in args:
        idx = args.index("--skipappcheck")

        # Get rid of the --skipappcheck
        args.pop(idx)

        # Append the extra opts
        extra_opts.append("skipappcheck=yes")

    if "--skip-semantic" in args:
        idx = args.index("--skip-semantic")

        # Get rid of the --skip-semantic
        args.pop(idx)

        # Append the extra opts
        extra_opts.append("skip-semantic=yes")

    if len(extra_opts) == 0:
        extra_opts_str = ''
    else:
        extra_opts_str = '?%s' % '&'.join(extra_opts)

    patches = "/".join(args)
    url = "http://%s/software/remove/%s%s" % (api_addr, patches, extra_opts_str)

    headers = {}
    append_auth_token_if_required(headers)
    req = requests.post(url, headers=headers)

    if args.debug:
        print_result_debug(req)
    else:
        print_software_op_result(req)

    return check_rc(req)


def release_delete_req(args):
    # arg.release is a list
    releases = args.release

    # Ignore interrupts during this function
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    patches = "/".join(releases)

    url = "http://%s/software/delete/%s" % (api_addr, patches)

    headers = {}
    append_auth_token_if_required(headers)
    req = requests.post(url, headers=headers)

    if args.debug:
        print_result_debug(req)
    else:
        print_software_op_result(req)

    return check_rc(req)


def patch_commit_req(args):
    print("patch_commit_req UNDER CONSTRUCTION")

    # Ignore interrupts during this function
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    dry_run = False
    if constants.CLI_OPT_DRY_RUN in args:
        dry_run = True
        args.remove(constants.CLI_OPT_DRY_RUN)

    all_patches = False
    if constants.CLI_OPT_ALL in args:
        all_patches = True
        args.remove(constants.CLI_OPT_ALL)

    # Default to running release
    # this all needs to be changed
    relopt = RUNNING_SW_VERSION
    release = args.release

    headers = {}
    append_auth_token_if_required(headers)
    if release and not all_patches:
        # Disallow
        print("Use of --release option requires --all")
        return 1
    elif all_patches:
        # Get a list of all patches
        extra_opts = "&release=%s" % relopt
        url = "http://%s/software/query?show=all%s" % (api_addr, extra_opts)

        req = requests.get(url, headers=headers)

        patch_list = []
        if req.status_code == 200:
            data = json.loads(req.text)

            if 'pd' in data:
                patch_list = sorted(list(data['pd']))
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
        patches = "/".join(args)

        # First, get a list of dependencies and ask for confirmation
        url = "http://%s/software/query_dependencies/%s?recursive=yes" % (api_addr, patches)

        req = requests.get(url, headers=headers)

        if req.status_code == 200:
            data = json.loads(req.text)

            if 'patches' in data:
                print("The following patches will be committed:")
                for patch_id in sorted(data['patches']):
                    print("    %s" % patch_id)
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

    if dry_run:
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

    url = "http://%s/software/commit/%s" % (api_addr, patches)
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
        print_software_op_result(req)

    return check_rc(req)


def print_software_deploy_query_result(req):
    if req.status_code == 200:
        data = json.loads(req.text)
        if 'data' not in data:
            print("Invalid data returned:")
            print_result_debug(req)
            return

        agents = data['data']

        # Calculate column widths
        hdr_hn = "Hostname"
        hdr_ip = "IP Address"
        hdr_pc = "Patch Current"
        hdr_rr = "Reboot Required"
        hdr_rel = "Release"
        hdr_state = "State"

        width_hn = len(hdr_hn)
        width_ip = len(hdr_ip)
        width_pc = len(hdr_pc)
        width_rr = len(hdr_rr)
        width_rel = len(hdr_rel)
        width_state = len(hdr_state)

        for agent in sorted(agents, key=lambda a: a["hostname"]):
            if len(agent["hostname"]) > width_hn:
                width_hn = len(agent["hostname"])
            if len(agent["ip"]) > width_ip:
                width_ip = len(agent["ip"])
            if len(agent["sw_version"]) > width_rel:
                width_rel = len(agent["sw_version"])
            if len(agent["state"]) > width_state:
                width_state = len(agent["state"])

        print("{0:^{width_hn}}  {1:^{width_ip}}  {2:^{width_pc}}  {3:^{width_rr}}  {4:^{width_rel}}  {5:^{width_state}}".format(
            hdr_hn, hdr_ip, hdr_pc, hdr_rr, hdr_rel, hdr_state,
            width_hn=width_hn, width_ip=width_ip, width_pc=width_pc, width_rr=width_rr, width_rel=width_rel, width_state=width_state))

        print("{0}  {1}  {2}  {3}  {4}  {5}".format(
            '=' * width_hn, '=' * width_ip, '=' * width_pc, '=' * width_rr, '=' * width_rel, '=' * width_state))

        for agent in sorted(agents, key=lambda a: a["hostname"]):
            patch_current_field = "Yes" if agent["patch_current"] else "No"
            if agent.get("interim_state") is True:
                patch_current_field = "Pending"

            if agent["patch_failed"]:
                patch_current_field = "Failed"

            print("{0:<{width_hn}}  {1:<{width_ip}}  {2:^{width_pc}}  {3:^{width_rr}}  {4:^{width_rel}}  {5:^{width_state}}".format(
                agent["hostname"],
                agent["ip"],
                patch_current_field,
                "Yes" if agent["requires_reboot"] else "No",
                agent["sw_version"],
                agent["state"],
                width_hn=width_hn, width_ip=width_ip, width_pc=width_pc, width_rr=width_rr, width_rel=width_rel, width_state=width_state))

    elif req.status_code == 500:
        print("An internal error has occurred. Please check /var/log/software.log for details")


def deploy_query_hosts_req(args):
    url = "http://%s/software/query_hosts" % api_addr
    req = requests.get(url)
    if args.debug:
        print_result_debug(req)
    else:
        print_software_deploy_query_result(req)

    return check_rc(req)


def release_show_req(args):
    # arg.release is a list
    releases = "/".join(args.release)

    url = "http://%s/software/show/%s" % (api_addr, releases)

    headers = {}
    append_auth_token_if_required(headers)
    req = requests.post(url, headers=headers)

    if args.debug:
        print_result_debug(req)
    else:
        print_patch_show_result(req)

    return check_rc(req)


def wait_for_install_complete(agent_ip):
    url = "http://%s/software/query_hosts" % api_addr
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
                print("Invalid query-hosts data returned:")
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
            print(m.group(0))
            rc = 1
            break

    return rc


def host_install(args):
    rc = 0
    agent_ip = args.agent

    # Issue host_install_async request and poll for results
    url = "http://%s/software/host_install_async/%s" % (api_addr, agent_ip)

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


def release_upload_dir_req(args):
    # arg.release is a list
    release_dirs = args.release

    # Ignore interrupts during this function
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    dirlist = {}
    i = 0
    for d in sorted(list(set(release_dirs))):
        dirlist["dir%d" % i] = os.path.abspath(d)
        i += 1

    url = "http://%s/software/upload_dir" % api_addr

    headers = {}
    append_auth_token_if_required(headers)
    req = requests.post(url, params=dirlist, headers=headers)

    if args.debug:
        print_result_debug(req)
    else:
        print_software_op_result(req)
    return check_rc(req)


def software_deploy_host_req(args):
    rc = 0
    agent_ip = args.agent

    # Issue host_install_async request and poll for results
    url = "http://%s/software/host_install_async/%s" % (api_addr, agent_ip)

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


def patch_is_applied_req(args):
    releases = args.releases
    patches = "/".join(releases)
    url = "http://%s/software/is_applied/%s" % (api_addr, patches)

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
        m = re.search("(Error message:.*)", req.text, re.MULTILINE)
        if m:
            print(m.group(0))
        else:
            print("%s %s" % (req.status_code, req.reason))
        rc = 1

    return rc


def patch_is_available_req(args):
    releases = args.releases
    patches = "/".join(releases)
    url = "http://%s/software/is_available/%s" % (api_addr, patches)

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
        m = re.search("(Error message:.*)", req.text, re.MULTILINE)
        if m:
            print(m.group(0))
        else:
            print("%s %s" % (req.status_code, req.reason))
        rc = 1

    return rc


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
        endpoint = auth.get_endpoint(sess, service_type='software',
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
      - activate
      - complete
      - host
      - list
      - query
      - start
    non root/sudo users can run:
       - list
       - query
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

    # --- software deploy activate -----------------------
    cmd = sub_cmds.add_parser(
        'activate',
        help='Activate the software deployment'
    )
    cmd.set_defaults(cmd='activate')

    # --- software deploy complete -----------------------
    cmd = sub_cmds.add_parser(
        'complete',
        help='Complete the software deployment'
    )
    cmd.set_defaults(cmd='complete')

    # --- software deploy host ---------------------------
    cmd = sub_cmds.add_parser(
        'host',
        help='Deploy to a software host'
    )
    cmd.set_defaults(cmd='host')

    # --- software deploy list ---------------------------
    cmd = sub_cmds.add_parser(
        'list',
        help='List the software deployments'
    )
    cmd.set_defaults(cmd='list')
    cmd.set_defaults(restricted=False)  # can run non root

    # --- software deploy query <deployment> -------------
    cmd = sub_cmds.add_parser(
        'query',
        help='Query a software deployment'
    )
    cmd.set_defaults(cmd='query')
    cmd.set_defaults(restricted=False)  # can run non root
    cmd.add_argument('--deployment', required=True)

    # --- software deploy start --------------------------
    cmd = sub_cmds.add_parser(
        'start',
        help='Start the software deployment'
    )
    cmd.set_defaults(cmd='start')


def register_release_commands(commands):
    """release commands
      - delete
      - list
      - show
      - upload
      - upload-dir
    non root/sudo users can run:
       - show
       - list
    """
    cmd_area = 'release'
    cmd_parser = commands.add_parser(
        cmd_area,
        help='Software Release',
        epilog="StarlingX Unified Software Deployment"
    )
    cmd_parser.set_defaults(cmd_area=cmd_area)
    sub_cmds = cmd_parser.add_subparsers(
        title='Software Release Commands',
        metavar=''
    )
    sub_cmds.required = True

    # -- software release delete <release> ---------------
    cmd = sub_cmds.add_parser(
        'delete',
        help='Delete the software release'
    )
    cmd.set_defaults(cmd='delete')
    cmd.set_defaults(func=release_delete_req)
    cmd.add_argument('--release',
                     nargs="+",  # accepts a list
                     required=True)

    # --- software release list ---------------------------
    cmd = sub_cmds.add_parser(
        'list',
        help='List the software releases'
    )
    cmd.set_defaults(cmd='list')
    cmd.set_defaults(func=release_list_req)
    cmd.set_defaults(restricted=False)  # can run non root
    # --release is an optional argument
    cmd.add_argument('--release',
                     required=False)
    # --state is an optional argument. default: "all"
    cmd.add_argument('--state',
                     default="all",
                     required=False)

    # --- software release show <release> -----------------
    cmd = sub_cmds.add_parser(
        'show',
        help='Show the software release'
    )
    cmd.set_defaults(cmd='show')
    cmd.set_defaults(func=release_show_req)
    cmd.set_defaults(restricted=False)  # can run non root
    cmd.add_argument('--release',
                     nargs="+",  # accepts a list
                     required=True)

    # --- software release upload <release> ---------------
    cmd = sub_cmds.add_parser(
        'upload',
        help='Upload a software release'
    )
    cmd.set_defaults(cmd='upload')
    cmd.set_defaults(func=release_upload_req)
    cmd.add_argument('--release',
                     nargs="+",  # accepts a list
                     required=True)

    # --- software release upload-dir <release dir> ------
    cmd = sub_cmds.add_parser(
        'upload-dir',
        help='Upload a software release dir'
    )
    cmd.set_defaults(cmd='upload-dir')
    cmd.set_defaults(func=release_upload_dir_req)
    cmd.add_argument('--release',
                     nargs="+",  # accepts a list
                     required=True)


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

    register_deploy_commands(commands)
    register_release_commands(commands)
    return parser


def main():
    set_term_width()

    rc = 0
    parser = setup_argparse()
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
