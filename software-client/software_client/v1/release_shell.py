#
# Copyright (c) 2015-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from software_client.common import utils


# --release is an optional argument
@utils.arg('--release',
           required=False,
           help='filter against a release ID')
# --state is an optional argument. default: "all"
@utils.arg('--state',
           default="all",
           required=False,
           help='filter against a release state')
def do_list(cc, args):
    """List the software releases"""
    req, data = cc.release.list(args)
    if args.debug:
        utils.print_result_debug(req, data)
    else:
        header_data_list = ["Release", "RR", "State"]
        data_list = [(k, v["reboot_required"], v["state"]) for k, v in data["sd"].items()]
        has_error = 'error' in data and data["error"]
        utils.print_result_list(header_data_list, data_list, has_error)

    return utils.check_rc(req, data)


@utils.arg('release',
           nargs="+",  # accepts a list
           help='Release ID to print detailed information')
@utils.arg('--packages',
           required=False,
           default=False,
           action='store_true',
           help='list packages contained in the release')
def do_show(cc, args):
    """Show the software release"""
    list_packages = args.packages
    req, data = cc.release.show(args)
    if args.debug:
        utils.print_result_debug(req, data)
    else:
        utils.print_release_show_result(req, data, list_packages=list_packages)

    return utils.check_rc(req, data)


@utils.arg('patch',
           nargs="+",  # accepts a list
           help='Patch ID/s to commit')
# --dry-run is an optional argument
@utils.arg('--dry-run',
           action='store_true',
           required=False,
           help='Check the space savings without committing the patch')
# --all is an optional argument
@utils.arg('--all',
           action='store_true',
           required=False,
           help='Commit all the applied patches')
# --sw-version is an optional argument
@utils.arg('--sw-version',
           required=False,
           help='Software release version')
def do_commit_patch(cc, args):
    """Commit patches to free disk space. WARNING: This action is irreversible!"""
    return cc.release.commit_patch(args)


def do_install_local(cc, args):
    """ Trigger patch install/remove on the local host.
        This command can only be used for patch installation
        prior to initial configuration."""
    req, data = cc.release.install_local()
    if args.debug:
        utils.print_result_debug(req, data)
    else:
        utils.print_software_op_result(req, data)

    return utils.check_rc(req, data)


@utils.arg('release',
           nargs="+",  # accepts a list
           help='List of releases')
def do_is_available(cc, args):
    """Query Available state for list of releases.
       Returns True if all are Available, False otherwise."""
    req, result = cc.release.is_available(args.release)
    rc = 1
    if req.status_code == 200:
        print(result)
        if result is True:
            rc = 0
    elif req.status_code == 500:
        print("An internal error has occurred. Please check /var/log/software.log for details")
    else:
        print("Error: %s has occurred. %s" % (req.status_code, req.reason))
    return rc


@utils.arg('release',
           nargs="+",  # accepts a list
           help='List of releases')
def do_is_deployed(cc, args):
    """Query Deployed state for list of releases.
       Returns True if all are Deployed, False otherwise."""
    req, result = cc.release.is_deployed(args.release)
    rc = 1
    if req.status_code == 200:
        print(result)
        if result is True:
            rc = 0
    elif req.status_code == 500:
        print("An internal error has occurred. Please check /var/log/software.log for details")
    else:
        print("Error: %s has occurred. %s" % (req.status_code, req.reason))
    return rc


@utils.arg('release',
           nargs="+",  # accepts a list
           help='List of releases')
def do_is_committed(cc, args):
    """Query Committed state for list of releases.
       Returns True if all are Committed, False otherwise."""
    req, result = cc.release.is_committed(args.release)
    rc = 1
    if req.status_code == 200:
        print(result)
        if result is True:
            rc = 0
    elif req.status_code == 500:
        print("An internal error has occurred. Please check /var/log/software.log for details")
    else:
        print("Error: %s has occurred. %s" % (req.status_code, req.reason))
    return rc


@utils.arg('release',
           metavar='(iso + sig) | patch',
           nargs="+",  # accepts a list
           help=('pair of install iso and sig files for major release '
                 '(GA or patched) and/or one or more files containing a '
                 'patch release. NOTE: specify at most ONE pair of (iso + sig)'))
@utils.arg('--local',
           required=False,
           default=False,
           action='store_true')
def do_upload(cc, args):
    """Upload a software release"""
    req, data = cc.release.upload(args)
    if args.debug:
        utils.print_result_debug(req, data)
    else:
        utils.print_software_op_result(req, data)
        data_list = [(k, v["id"])
                     for d in data["upload_info"] for k, v in d.items()
                     if not k.endswith(".sig")]

        header_data_list = ["Uploaded File", "Id"]
        has_error = 'error' in data and data["error"]
        utils.print_result_list(header_data_list, data_list, has_error)
    rc = 0
    if utils.check_rc(req, data) != 0:
        # We hit a failure.  Update rc but keep looping
        rc = 1
    return rc


@utils.arg('release',
           metavar='directory',
           nargs="+",  # accepts a list
           help=('directory containing software releases files to upload. '
                 'The release files may be either a pair of install iso and '
                 'sig files for major release (GA or patched) and/or one or '
                 'more files containing a patch release. NOTE: specify at most '
                 'ONE pair of (iso + sig)'))
def do_upload_dir(cc, args):
    """Upload a software release dir"""
    return cc.release.upload_dir(args)


@utils.arg('release',
           nargs="+",  # accepts a list
           help='Release ID to delete')
def do_delete(cc, args):
    """Delete the software release"""
    resp, body = cc.release.release_delete(args.release)
    if args.debug:
        utils.print_result_debug(resp, body)
    else:
        utils.print_software_op_result(resp, body)

    return utils.check_rc(resp, body)
