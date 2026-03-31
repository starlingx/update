#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from software_client.common import utils


@utils.arg('release_id',
           help='Release ID to initialize the system deploy for')
@utils.arg('--kube-version',
           dest='kube_version',
           default=None,
           required=False,
           help='Target Kubernetes version for the upgrade')
def do_init(cc, args):
    """Initialize a system deploy for the given release"""
    resp, data = cc.system_deploy.init(args)
    if args.debug:
        utils.print_result_debug(resp, data)

    utils.display_info(resp)
    return utils.check_rc(resp, data)
