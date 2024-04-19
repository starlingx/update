#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from software_client.common import utils


# --deployment is an optional argument
@utils.arg('--deployment',
           required=False,
           help='List the deployment specified')
# --state is an optional argument.
# default: "all"
# acceptable values: inactive, active, prestaging, prestaged, all
@utils.arg('--state',
           choices=['inactive', 'active', 'prestaging', 'prestaged', 'all'],
           default="all",
           required=False,
           help="List all deployments that have this state")
def do_show(cc, args):
    """Show the software deployments states"""
    resp, data = cc.deploy.show()
    if args.debug:
        utils.print_result_debug(resp, data)
    else:
        header_data_list = {"From Release": "from_release", "To Release": "to_release", "RR": "reboot_required", "State": "state"}
        utils.display_result_list(header_data_list, data)

    return utils.check_rc(resp, data)


def do_host_list(cc, args):
    """List of hosts for software deployment """
    resp, data = cc.deploy.host_list()
    if args.debug:
        utils.print_result_debug(resp, data)
    else:
        header_data_list = {"Host": "hostname", "From Release": "software_release", "To Release": "target_release", "RR": "reboot_required", "State": "host_state"}
        utils.display_result_list(header_data_list, data)

    return utils.check_rc(resp, data)


@utils.arg('deployment',
           help='Verify if prerequisites are met for this Deployment ID')
@utils.arg('-f',
           '--force',
           action='store_true',
           required=False,
           help='Allow bypassing non-critical checks')
@utils.arg('--region_name',
           default='RegionOne',
           required=False,
           help='Run precheck against a subcloud')
def do_precheck(cc, args):
    """Verify whether prerequisites for installing the software deployment are satisfied"""
    req, data = cc.deploy.precheck(args)
    if args.debug:
        utils.print_result_debug(req, data)
    else:
        utils.print_software_op_result(req, data)

    return utils.check_rc(req, data)


@utils.arg('deployment',
           help='Deployment ID to start')
@utils.arg('-f',
           '--force',
           action='store_true',
           required=False,
           help='Allow bypassing non-critical checks')
def do_start(cc, args):
    """Start the software deployment"""
    resp, data = cc.deploy.start(args)
    if args.debug:
        utils.print_result_debug(resp, data)
    else:
        utils.display_info(resp)

    return utils.check_rc(resp, data)


@utils.arg('host',
           help="Name of the host that the deploy is triggered")
@utils.arg('-f',
           '--force',
           action='store_true',
           required=False,
           help="Force deploy host")
def do_host(cc, args):
    """Deploy prestaged software deployment to the host"""
    return cc.deploy.host(args)


def do_activate(cc, args):
    """Activate the software deployment"""
    req, data = cc.deploy.activate(args)
    if args.debug:
        utils.print_result_debug(req, data)
    else:
        utils.print_software_op_result(req, data)

    return utils.check_rc(req, data)

def do_complete(cc, args):
    """Complete the software deployment"""
    req, data = cc.deploy.complete(args)
    if args.debug:
        utils.print_result_debug(req, data)
    else:
        utils.print_software_op_result(req, data)

    return utils.check_rc(req, data)