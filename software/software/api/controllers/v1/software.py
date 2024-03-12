"""
Copyright (c) 2023-2024 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import cgi
import json
import logging
import os
from pecan import expose
from pecan import request
import shutil

from software import constants
from software.exceptions import SoftwareError
from software.exceptions import SoftwareServiceError
from software.release_data import reload_release_data
from software.software_controller import sc
from software import utils


LOG = logging.getLogger('main_logger')


class SoftwareAPIController(object):

    @expose('json')
    def commit_patch(self, *args):
        reload_release_data()
        result = sc.patch_commit(list(args))
        sc.software_sync()

        return result

    @expose('json')
    def commit_dry_run(self, *args):
        reload_release_data()
        result = sc.patch_commit(list(args), dry_run=True)
        return result

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def delete(self, *args):
        reload_release_data()
        result = sc.software_release_delete_api(list(args))
        sc.software_sync()

        return result

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def deploy_activate(self):
        reload_release_data()

        result = sc.software_deploy_activate_api()
        sc.software_sync()
        return result

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def deploy_complete(self):
        reload_release_data()

        result = sc.software_deploy_complete_api()
        sc.software_sync()
        return result

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def deploy_host(self, *args):
        reload_release_data()
        if len(list(args)) == 0:
            return dict(error="Host must be specified for install")
        force = False
        if len(list(args)) > 1 and 'force' in list(args)[1:]:
            force = True

        result = sc.software_deploy_host_api(list(args)[0], force, async_req=True)

        return result

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def deploy_precheck(self, *args, **kwargs):
        reload_release_data()
        force = False
        if 'force' in list(args):
            force = True

        result = sc.software_deploy_precheck_api(list(args)[0], force, **kwargs)

        return result

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def deploy_start(self, *args, **kwargs):
        reload_release_data()
        # if --force is provided
        force = 'force' in list(args)

        if sc.any_patch_host_installing():
            raise SoftwareServiceError(error="Rejected: One or more nodes are installing a release.")

        result = sc.software_deploy_start_api(list(args)[0], force, **kwargs)

        sc.send_latest_feed_commit_to_agent()
        sc.software_sync()

        return result

    @expose('json', method="GET")
    def deploy(self):
        reload_release_data()
        from_release = request.GET.get("from_release")
        to_release = request.GET.get("to_release")
        result = sc.software_deploy_show_api(from_release, to_release)
        return result

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def install_local(self):
        reload_release_data()
        result = sc.software_install_local_api()

        return result

    @expose('json')
    def is_available(self, *args):
        reload_release_data()
        return sc.is_available(list(args))

    @expose('json')
    def is_committed(self, *args):
        reload_release_data()
        return sc.is_committed(list(args))

    @expose('json')
    def is_deployed(self, *args):
        reload_release_data()
        return sc.is_deployed(list(args))

    @expose('json')
    @expose('show.xml', content_type='application/xml')
    def show(self, *args):
        reload_release_data()
        result = sc.software_release_query_specific_cached(list(args))

        return result

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def upload(self):
        reload_release_data()
        is_local = False
        temp_dir = None
        uploaded_files = []
        request_data = []
        local_files = []

        # --local option only sends a list of file names
        if (request.content_type == "text/plain"):
            local_files = list(json.loads(request.body))
            is_local = True
        else:
            request_data = list(request.POST.items())
            temp_dir = os.path.join(constants.SCRATCH_DIR, 'upload_files')

        try:
            if len(request_data) == 0 and len(local_files) == 0:
                raise SoftwareError("No files uploaded")

            if is_local:
                uploaded_files = local_files
                LOG.info("Uploaded local files: %s", uploaded_files)
            else:
                # Protect against duplications
                uploaded_files = sorted(set(request_data))
                # Save all uploaded files to /scratch/upload_files dir
                for file_item in uploaded_files:
                    assert isinstance(file_item[1], cgi.FieldStorage)
                    utils.save_temp_file(file_item[1], temp_dir)

                # Get all uploaded files from /scratch dir
                uploaded_files = utils.get_all_files(temp_dir)
                LOG.info("Uploaded files: %s", uploaded_files)

            # Process uploaded files
            return sc.software_release_upload(uploaded_files)

        finally:
            # Remove all uploaded files from /scratch dir
            sc.software_sync()
            if temp_dir:
                shutil.rmtree(temp_dir, ignore_errors=True)

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def query(self, **kwargs):
        reload_release_data()
        sd = sc.software_release_query_cached(**kwargs)
        return sd

    @expose('json', method="GET")
    def host_list(self):
        reload_release_data()
        result = sc.deploy_host_list()
        return result

    @expose(method='GET', template='json')
    def in_sync_controller(self):
        return sc.in_sync_controller_api()

    @expose(method='GET', template='json')
    def software_upgrade(self):
        return sc.get_software_upgrade()

    @expose(method='GET', template='json')
    def software_host_upgrade(self, *args):
        args_list = list(args)
        if not args_list:
            return sc.get_all_software_host_upgrade()

        hostname = args_list[0]
        return sc.get_one_software_host_upgrade(hostname)
