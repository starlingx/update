#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from software_client.common import utils


# --all is an optional argument. Default: highest currently deployed release.
@utils.arg('--all',
           default=False,
           required=False,
           action="store_true",
           help='displays all metapackages')
# --state is an optional argument.
@utils.arg('--state',
           default=None,
           required=False,
           help='filter against a release state')
def do_list(cc, args):
    """List the metapackages releases"""
    resp, data = cc.metapackage.list(args)
    if args.debug:
        utils.print_result_debug(resp, data)

    rc = utils.check_rc(resp, data)
    if rc == 0:
        header_data_list = {"Release": "release_id", "Version": "sw_version",
                            "RR": "reboot_required", "State": "state"}
        sorted_data = sorted(data, key=lambda x: (x["sw_version"], x["release_id"].translate(
            dict.fromkeys(map(ord, "-_."), "-"))))
        utils.display_result_list(header_data_list, sorted_data)
    else:
        utils.display_info(resp)

    return rc
