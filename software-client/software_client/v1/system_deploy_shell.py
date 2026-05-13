#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import re

from software_client.common import utils

KUBE_VERSION_RE = re.compile(r'^v?\d{1,2}\.\d{1,2}\.\d{1,2}$')


@utils.arg('release_id',
           help='Release ID to initialize the system deploy for')
@utils.arg('--kube-version',
           dest='kube_version',
           default=None,
           required=False,
           help='Target Kubernetes version for the upgrade')
def do_init(cc, args):
    """Initialize a system deploy for the given release"""
    if args.kube_version and not KUBE_VERSION_RE.match(args.kube_version):
        print("Error:\nInvalid kube_version '%s': must match '[v]n.n.n'" % args.kube_version)
        return 1

    resp, data = cc.system_deploy.init(args)
    if args.debug:
        utils.print_result_debug(resp, data)

    utils.display_info(resp)
    return utils.check_rc(resp, data)


def do_show(cc, args):
    """Show the current system deploy state"""
    resp, data = cc.system_deploy.show(args)
    if args.debug:
        utils.print_result_debug(resp, data)

    rc = utils.check_rc(resp, data)

    if rc == 0:
        if len(data) == 0:
            print("No system deploy in progress.")
        else:
            header_data_list = {
                "System Deploy ID": "id",
                "To Release": "to_release",
                "To K8S Release": "to_k8s_version",
                "State": "state"}
            utils.display_result_list(header_data_list, data)

    return rc


def do_delete(cc, args):
    """Delete the system deploy"""
    resp, data = cc.system_deploy.delete(args)

    if args.debug:
        utils.print_result_debug(resp, data)

    utils.display_info(resp)

    return utils.check_rc(resp, data)
