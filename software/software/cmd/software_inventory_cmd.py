
"""
Copyright (c) 2026 Wind River Systems, Inc.
SPDX-License-Identifier: Apache-2.0
"""

import argparse
import logging
import os
import sys

from software.exceptions import BranchNotFound
from software.ostree_utils import get_repo
from software.software_functions import LOG
from software.software_inventory import SoftwareInventoryManager
from software.software_inventory import get_release_by_commit
from software.software_inventory import get_top_commit


def handle_exception(exc_type, exc_value, exc_traceback):
    """Exception handler to log any uncaught exceptions"""
    LOG.error("Uncaught exception",
              exc_info=(exc_type, exc_value, exc_traceback))
    sys.__excepthook__(exc_type, exc_value, exc_traceback)


def configure_logging(logtostdout=False, level=logging.INFO):
    LOG.setLevel(level)

    if logtostdout:
        stdout_handler = logging.StreamHandler(sys.stdout)
        LOG.addHandler(stdout_handler)

    sys.excepthook = handle_exception


def show_sw_release(sw_ver, branch_name=None, show_commit_id=False):
    """Show all software releases included in a branch, marking the current deploy."""
    if branch_name is None:
        branch_name = SoftwareInventoryManager.DEPLOY_BRANCH
    sim = SoftwareInventoryManager(sw_ver)
    releases = sim.list_sw_release(branch_name)
    try:
        deploy_commit = get_top_commit(sim.repo_path, SoftwareInventoryManager.DEPLOY_BRANCH)
        repo = get_repo(sim.repo_path)
        current_deploy = get_release_by_commit(repo, deploy_commit)
    except BranchNotFound:
        current_deploy = None
    for release in releases:
        if show_commit_id:
            commit_id = get_top_commit(sim.repo_path, release)
            to_display = f"{release}: {commit_id}"
        else:
            to_display = release

        if release == current_deploy:
            print(f"{to_display} <== current deploy")
        else:
            print(to_display)


def create_op_trace(cmd):
    trace_cmds = ["upload"]
    trace_filepath = "/opt/software/"
    if cmd in trace_cmds:
        with open(os.path.join(trace_filepath, f".{cmd}.pid"), "w") as f:
            f.write(str(os.getpid()))


def main():
    parser = argparse.ArgumentParser(
        description="Process starlingx patch")
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list",
                                        help="List all software releases")
    list_parser.add_argument("--sw-ver", default=None,
                             help="Software version (major release version)")

    show_parser = subparsers.add_parser("show",
                                        help="Show a software release and its dependencies")
    show_parser.add_argument("sw_release", nargs="?", default=None,
                             help="The software release id")
    show_parser.add_argument("--commit-id", action="store_true",
                             help="List commit IDs instead")
    show_parser.add_argument("--sw-ver", default=None,
                             help="Software version (major release version)")

    args = parser.parse_args()
    create_op_trace(args.command)

    if args.command == "show":
        show_sw_release(args.sw_ver, args.sw_release, args.commit_id)
    elif args.command == "list":
        sim = SoftwareInventoryManager(args.sw_ver)
        for branch in sorted(sim.get_branches()):
            print(branch)


if __name__ == "__main__":
    configure_logging(logtostdout=True)
    main()
