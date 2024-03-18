#
# Copyright (c) 2015-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import json
import os
import signal
import sys
import textwrap

from requests_toolbelt import MultipartEncoder
from tsconfig.tsconfig import SW_VERSION as RUNNING_SW_VERSION

from software_client.common import base
from software_client.common import utils
from software_client import constants


class Release(base.Resource):
    def __repr__(self):
        return "<release %s>" % self._info


class ReleaseManager(base.Manager):
    resource_class = Release

    def list(self, args):
        state = args.state  # defaults to "all"
        extra_opts = ""
        if args.release:
            extra_opts = "&release=%s" % args.release
        path = "/v1/software/query?show=%s%s" % (state, extra_opts)
        return self._list(path, "")

    def is_available(self, release):
        releases = "/".join(release)
        path = '/v1/software/is_available/%s' % (releases)
        return self._create(path, body={})

    def is_deployed(self, release):
        releases = "/".join(release)
        path = '/v1/software/is_deployed/%s' % (releases)
        return self._create(path, body={})

    def is_committed(self, release):
        releases = "/".join(release)
        path = '/v1/software/is_committed/%s' % (releases)
        return self._create(path, body={})

    def upload(self, args):
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
        invalid_files = [os.path.abspath(software_file) for software_file in releases
                         if os.path.abspath(software_file) not in valid_files]

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

        path = '/v1/software/upload'
        if is_local:
            to_upload_filenames = valid_files
            headers = {'Content-Type': 'text/plain'}
            return self._create(path, body=to_upload_filenames, headers=headers)
        else:
            for software_file in valid_files:
                with open(software_file, 'rb') as file:
                    data_content = file.read()
                to_upload_files[software_file] = (software_file, data_content)

            encoder = MultipartEncoder(fields=to_upload_files)
            headers = {'Content-Type': encoder.content_type}
            return self._create_multipart(path, body=encoder, headers=headers)

    def upload_dir(self, args):
        # arg.release is a list
        release_dirs = args.release

        # Ignore interrupts during this function
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        to_upload_files = {}
        all_raw_files = []

        # Find all files that need to be uploaded in given directories
        for release_dir in release_dirs:
            if os.path.isdir(release_dir):
                raw_files = [f for f in os.listdir(release_dir)
                             if os.path.isfile(os.path.join(release_dir, f))]

                # Get absolute path of files
                raw_files = [os.path.abspath(os.path.join(release_dir, f)) for f in raw_files]

                # Append files from directory into the full list
                all_raw_files.extend(raw_files)
            else:
                print("Skipping invalid directory: %s" % release_dir, file=sys.stderr)

        if len(all_raw_files) == 0:
            print("No file to upload")
            return 0

        temp_iso_files = [f for f in all_raw_files if f.endswith(constants.ISO_EXTENSION)]
        if len(temp_iso_files) > 1:  # Verify that only one ISO file is being uploaded
            print("Only one ISO file can be uploaded at a time. Found: %s" %
                  temp_iso_files, file=sys.stderr)
            return 1

        temp_sig_files = [f for f in all_raw_files if f.endswith(constants.SIG_EXTENSION)]
        if len(temp_sig_files) > 1:  # Verify that only one SIG file is being uploaded
            print("Only one SIG file can be uploaded at a time. Found: %s" %
                  temp_sig_files, file=sys.stderr)
            return 1


        for software_file in sorted(set(all_raw_files)):
            _, ext = os.path.splitext(software_file)
            if ext in constants.SUPPORTED_UPLOAD_FILE_EXT:
                to_upload_files[software_file] = (software_file, open(software_file, 'rb'))
            else:
                print("Skipping unsupported file: %s" % software_file, file=sys.stderr)

        encoder = MultipartEncoder(fields=to_upload_files)
        headers = {'Content-Type': encoder.content_type}
        path = '/v1/software/upload'
        req, data = self._create_multipart(path, body=encoder, headers=headers)
        if args.debug:
            utils.print_result_debug(req, data)
        else:
            utils.print_software_op_result(req, data)
            data = json.loads(req.text)
            data_list = [(lambda key, value: (key, value["id"]))(k, v)
                         for d in data["upload_info"]
                         for k, v in d.items()
                         if not k.endswith(".sig")]

            header_data_list = ["Uploaded File", "Id"]
            has_error = 'error' in data and data["error"]
            utils.print_result_list(header_data_list, data_list, has_error)
        return utils.check_rc(req, data)

    def commit_patch(self, args):
        # Ignore interrupts during this function
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        # Default to running release
        # this all needs to be changed
        relopt = RUNNING_SW_VERSION

        # append_auth_token_if_required(headers)
        if args.sw_version and not args.all:
            # Disallow
            print("Use of --sw-version option requires --all")
            return 1
        elif args.all:
            # Get a list of all patches
            extra_opts = "&release=%s" % relopt
            url = "/v1/software/query?show=patch%s" % (extra_opts)

            resp, body = self._list(url, "")

            patch_list = []
            if resp.status_code == 200:
                data = body

                if 'sd' in data:
                    patch_list = sorted(list(data['sd']))
            elif resp.status_code == 500:
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
            url = "/v1/software/query_dependencies/%s?recursive=yes" % (patches)

            resp, body = self._list(url, "")

            if resp.status_code == 200:
                data = body

                if 'patches' in data:
                    print("The following patches will be committed:")
                    for release_id in sorted(data['patches']):
                        print("    %s" % release_id)
                    print()
                else:
                    print("No patches found to commit")
                    return 1

            elif resp.status_code == 500:
                print("An internal error has occurred. Please check /var/log/software.log for details")
                return 1

        # Run dry-run
        url = "/v1/software/commit_dry_run/%s" % (patches)

        resp, body = self._create(url, body={})
        utils.print_software_op_result(resp, body)

        if utils.check_rc(resp, body) != 0:
            print("Aborting...")
            return 1

        if args.dry_run:
            return 0

        print()
        commit_warning = "WARNING: Committing a patch is an irreversible operation. " + \
            "Committed patches cannot be removed."
        print(textwrap.fill(commit_warning, width=utils.TERM_WIDTH, subsequent_indent=' ' * 9))
        print()

        user_input = input("Would you like to continue? [y/N]: ")
        if user_input.lower() != 'y':
            print("Aborting...")
            return 1

        url = "/v1/software/commit_patch/%s" % (patches)
        req = self._create(url, body={})

        if args.debug:
            utils.print_result_debug(req)
        else:
            utils.print_software_op_result(req)
        return

    def install_local(self):
        # Ignore interrupts during this function
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        path = "/v1/software/install_local"
        return self._list(path, "")

    def show(self, args):
        releases = "/".join(args.release)

        path = "/v1/software/show/%s" % (releases)
        return self._create(path, body={})

    def release_delete(self, release_id):
        release_ids = "/".join(release_id)
        path = '/v1/software/delete/%s' % release_ids
        return self._create(path, body={})
