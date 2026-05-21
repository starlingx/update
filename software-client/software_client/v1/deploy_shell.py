#
# Copyright (c) 2024-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from software_client.common import utils


def do_show(cc, args):
    """Show the software deployments states"""
    resp, data = cc.deploy.show()
    if args.debug:
        utils.print_result_debug(resp, data)

    rc = utils.check_rc(resp, data)
    if rc == 0:
        if len(data) == 0:
            print("No deploy in progress")
        else:
            header_data_list = {"From Release": "from_release",
                                "To Release": "to_release",
                                "RR": "reboot_required",
                                "State": "state"}
            utils.format_data(data, header="state", format_func=lambda x: f"deploy-{x}")
            utils.display_result_list(header_data_list, data)
    else:
        utils.display_info(resp)

    return rc


def do_host_list(cc, args):
    """List of hosts for software deployment """
    resp, data = cc.deploy.host_list()
    if args.debug:
        utils.print_result_debug(resp, data)

    rc = utils.check_rc(resp, data)
    if rc == 0:
        if len(data) == 0:
            print("No deploy in progress")
        else:
            header_data_list = {"Host": "hostname", "From Release": "software_release",
                                "To Release": "target_release", "RR": "reboot_required",
                                "State": "host_state"}
            utils.format_data(data, header="host_state", format_func=lambda x: f"deploy-host-{x}")
            utils.display_result_list(header_data_list, data)
    else:
        utils.display_info(resp)

    return rc


@utils.arg('releases',
           nargs='+',
           help='List of releases (metapackages or product) to select for deployment')
@utils.arg('--pre-upgrade-deploy',
           default=False,
           required=False,
           action='store_true',
           help='Select metapackages required to deploy before upgrading to the specified release')
def do_select(cc, args):
    """Select metapackages to deploy"""
    resp, data = cc.deploy.select(args)
    if args.debug:
        utils.print_result_debug(resp, data)

    utils.display_info(resp)

    return utils.check_rc(resp, data)


@utils.arg('releases',
           nargs='*',
           default=None,
           help='List of releases (metapackages or product) to unselect for deployment')
@utils.arg('--all',
           default=False,
           required=False,
           action='store_true',
           help='Unselect all selected metapackages')
def do_unselect(cc, args):
    """Unselect metapackages to deploy"""
    resp, data = cc.deploy.unselect(args)
    if args.debug:
        utils.print_result_debug(resp, data)

    utils.display_info(resp)

    return utils.check_rc(resp, data)


@utils.arg('releases',
           nargs='*',
           default=None,
           help='Releases IDs. '
           'Can assume an empty value, a list of metapackage releases or '
           'a single product release. If empty, it checks the system-deploy '
           'entity or the selected metapackage releases')
@utils.arg('--pre-upgrade-deploy',
           action='store_true',
           required=False,
           help='Run precheck only in the metapackages required to deploy '
           'before upgrading to the specified product release')
@utils.arg('-f',
           '--force',
           action='store_true',
           required=False,
           help='Allow bypassing non-critical checks')
@utils.arg('--region_name',
           default=None,
           required=False,
           help='Run precheck against a subcloud')
@utils.arg('-o',
           '--options',
           action='append',
           required=False,
           help='Additional parameters in key=value format.')
def do_precheck(cc, args):
    """Verify whether prerequisites for installing the software deployment are satisfied"""
    resp, data = cc.deploy.precheck(args)
    if args.debug:
        utils.print_result_debug(resp, data)

    rc = utils.check_rc(resp, data)
    if rc == 0:
        if data.get("error"):
            rc = 1

    utils.display_info(resp)
    return rc


@utils.arg('deployment',
           nargs='?',
           default=None,
           help='Deployment ID to start (Optional when system deploy in progress)')
@utils.arg('-f',
           '--force',
           action='store_true',
           required=False,
           help='Allow bypassing non-critical checks')
@utils.arg('-o',
           '--options',
           action='append',
           required=False,
           help='Additional parameters in key=value format.')
def do_start(cc, args):
    """Start the software deployment"""
    resp, data = cc.deploy.start(args)
    if args.debug:
        utils.print_result_debug(resp, data)

    rc = utils.check_rc(resp, data)
    if rc == 0:
        if "system_healthy" in data and data["system_healthy"] is False:
            print("System is unhealthy for deploy")
            rc = 1

    utils.display_info(resp)
    return rc


@utils.arg('host',
           help="Name of the host that the deploy is triggered")
@utils.arg('-f',
           '--force',
           action='store_true',
           required=False,
           help="Force deploy host")
def do_host(cc, args):
    """Deploy prestaged software deployment to the host"""
    resp, data = cc.deploy.host(args)

    if args.debug:
        utils.print_result_debug(resp, data)

    utils.display_info(resp)

    return utils.check_rc(resp, data)


@utils.arg('host',
           help="Name of the host that the deploy is triggered")
@utils.arg('-f',
           '--force',
           action='store_true',
           required=False,
           help="Force deploy host")
def do_host_rollback(cc, args):
    """Deploy prestaged software deployment to the host"""
    resp, data = cc.deploy.host_rollback(args)

    if args.debug:
        utils.print_result_debug(resp, data)

    utils.display_info(resp)

    return utils.check_rc(resp, data)


def do_abort(cc, args):
    """Abort the software deployment"""
    resp, data = cc.deploy.abort(args)

    if args.debug:
        utils.print_result_debug(resp, data)

    utils.display_info(resp)

    return utils.check_rc(resp, data)


def do_activate(cc, args):
    """Activate the software deployment"""
    resp, data = cc.deploy.activate(args)
    if args.debug:
        utils.print_result_debug(resp, data)

    utils.display_info(resp)

    return utils.check_rc(resp, data)


def do_activate_rollback(cc, args):
    """Rolls back the activate of software deployment"""
    resp, data = cc.deploy.activate_rollback(args)
    if args.debug:
        utils.print_result_debug(resp, data)

    utils.display_info(resp)

    return utils.check_rc(resp, data)


def do_complete(cc, args):
    """Complete the software deployment"""
    resp, data = cc.deploy.complete(args)

    if args.debug:
        utils.print_result_debug(resp, data)

    utils.display_info(resp)

    return utils.check_rc(resp, data)


def do_delete(cc, args):
    """Delete the software deployment"""
    resp, data = cc.deploy.delete(args)

    if args.debug:
        utils.print_result_debug(resp, data)

    utils.display_info(resp)

    return utils.check_rc(resp, data)
