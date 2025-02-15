#
# Copyright (c) 2015-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import sys
import threading
import time

from software_client.common import utils


# --release is an optional argument
@utils.arg('--release',
           required=False,
           help='filter against a release ID')
# --state is an optional argument. default: "all"
@utils.arg('--state',
           default=None,
           required=False,
           help='filter against a release state')
def do_list(cc, args):
    """List the software releases"""
    resp, data = cc.release.list(args)
    if args.debug:
        utils.print_result_debug(resp, data)

    rc = utils.check_rc(resp, data)
    if rc == 0:
        header_data_list = {"Release": "release_id", "RR": "reboot_required", "State": "state"}
        sorted_data = sorted(data, key=lambda x: x['release_id'].translate(
            dict.fromkeys(map(ord, "-_."), "-")))
        utils.display_result_list(header_data_list, sorted_data)
    else:
        utils.display_info(resp)

    return rc


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
    resp, data = cc.release.show(args)
    if args.debug:
        utils.print_result_debug(resp, data)

    rc = utils.check_rc(resp, data)
    if rc == 0:
        if not args.packages and 'packages' in data:
            del data['packages']
        utils.display_detail_result(data)
    else:
        utils.display_info(resp)

    return rc


@utils.arg('--delete',
           required=False,
           action='store_true',
           help='Delete patch install/remove on the localhost mode')
def do_install_local(cc, args):
    """Set patch install/remove on the local host.
        This command can only be used for patch installation.
    """
    resp, data = cc.release.install_local(args.delete)
    if args.debug:
        utils.print_result_debug(resp, data)

    utils.display_info(resp)

    return utils.check_rc(resp, data)


# NOTE (bqian) verify this CLI is needed
@utils.arg('release',
           nargs="+",  # accepts a list
           help='List of releases')
def do_is_available(cc, args):
    """Query Available state for list of releases.
       Returns True if all are Available, False otherwise.
    """
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


# NOTE (bqian) verify this CLI is needed
@utils.arg('release',
           nargs="+",  # accepts a list
           help='List of releases')
def do_is_deployed(cc, args):
    """Query Deployed state for list of releases.
       Returns True if all are Deployed, False otherwise.
    """
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


# NOTE (bqian) verify this CLI is needed
@utils.arg('release',
           nargs="+",  # accepts a list
           help='List of releases')
def do_is_committed(cc, args):
    """Query Committed state for list of releases.
       Returns True if all are Committed, False otherwise.
    """
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


def _print_upload_result(resp, data, debug):
    if debug:
        utils.print_result_debug(resp, data)

    rc = utils.check_rc(resp, data)

    utils.display_info(resp)
    if rc == 0:
        if data["upload_info"]:
            upload_info = data["upload_info"]
            data_list = [{"file": k, "release": v["id"]}
                         for d in upload_info for k, v in d.items()
                         if not k.endswith(".sig")]

            header_data_list = {"Uploaded File": "file", "Release": "release"}
            utils.display_result_list(header_data_list, data_list)
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
           action='store_true',
           help=("Upload the release locally from active controller. "
                 "To use this option, first upload the .iso,.sig and/or .patch "
                 "files to active controller and then specify the absolute path of "
                 "each file."))
def do_upload(cc, args):
    """Upload a software release."""
    try:
        print("This operation will take a while. Please wait.")
        wait_task = WaitThread()
        wait_task.start()
        result = cc.release.upload(args)
        wait_task.join()
    except Exception as e:
        wait_task.join()
        raise Exception("Upload failed. Reason: %s" % e)

    if isinstance(result, int):
        return result
    else:
        resp, data = result[0], result[1]
    _print_upload_result(resp, data, args.debug)

    return utils.check_rc(resp, data)


@utils.arg('release',
           metavar='directory',
           nargs="+",  # accepts a list
           help=('directory containing software releases files to upload. '
                 'The release files may be either a pair of install iso and '
                 'sig files for major release (GA or patched) and/or one or '
                 'more files containing a patch release. NOTE: specify at most '
                 'ONE pair of (iso + sig)'))
def do_upload_dir(cc, args):
    """Upload a software release directory."""
    try:
        print("This operation will take a while. Please wait.")
        wait_task = WaitThread()
        wait_task.start()
        resp, data = cc.release.upload_dir(args)
        wait_task.join()
    except Exception as e:
        wait_task.join()
        raise Exception("Upload directory failed. Reason: %s" % e)
    _print_upload_result(resp, data, args.debug)

    return utils.check_rc(resp, data)


# --all is an optional argument
@utils.arg('--all',
           action='store_true',
           required=False,
           help='Delete all patches and major releases related '
                'to the given major release ID')
@utils.arg('release',
           nargs="+",  # accepts a list
           help='Release ID to delete')
def do_delete(cc, args):
    """Delete the software release"""
    resp, data = cc.release.release_delete(args.release, args.all)
    if args.debug:
        utils.print_result_debug(resp, data)

    utils.display_info(resp)
    return utils.check_rc(resp, data)


class WaitThread(threading.Thread):
    """Thread to show progress indication."""
    def __init__(self):
        super(WaitThread, self).__init__()
        self.stop = threading.Event()

    def run(self):
        """Run the progress indication."""
        while not self.stop.is_set():
            sys.stdout.write(".")
            sys.stdout.flush()
            time.sleep(10)

    def join(self, timeout=None):
        """Stop the progress indication and join the thread."""
        self.stop.set()
        super(WaitThread, self).join(timeout)
        sys.stdout.write("\n")
        sys.stdout.flush()
