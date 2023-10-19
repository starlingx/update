"""
Copyright (c) 2023 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import cgi
import glob
import os
from oslo_log import log
from pecan import expose
from pecan import request
import shutil

from software.exceptions import SoftwareError
from software.software_controller import sc
import software.utils as utils
import software.constants as constants

LOG = log.getLogger(__name__)


class SoftwareAPIController(object):

    @expose('json')
    def commit_patch(self, *args):
        try:
            result = sc.patch_commit(list(args))
        except SoftwareError as e:
            return dict(error=str(e))

        sc.software_sync()

        return result

    @expose('json')
    def commit_dry_run(self, *args):
        try:
            result = sc.patch_commit(list(args), dry_run=True)
        except SoftwareError as e:
            return dict(error=str(e))

        return result

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def delete(self, *args):
        try:
            result = sc.software_release_delete_api(list(args))
        except SoftwareError as e:
            return dict(error="Error: %s" % str(e))

        sc.software_sync()

        return result

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def deploy_activate(self, *args):
        if sc.any_patch_host_installing():
            return dict(error="Rejected: One or more nodes are installing a release.")

        try:
            result = sc.software_deploy_activate_api(list(args)[0])
        except SoftwareError as e:
            return dict(error="Error: %s" % str(e))

        sc.software_sync()
        return result

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def deploy_complete(self, *args):
        if sc.any_patch_host_installing():
            return dict(error="Rejected: One or more nodes are installing a release.")

        try:
            result = sc.software_deploy_complete_api(list(args)[0])
        except SoftwareError as e:
            return dict(error="Error: %s" % str(e))

        sc.software_sync()
        return result

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def deploy_host(self, *args):
        if len(list(args)) == 0:
            return dict(error="Host must be specified for install")
        force = False
        if len(list(args)) > 1 and 'force' in list(args)[1:]:
            force = True

        try:
            result = sc.software_deploy_host_api(list(args)[0], force, async_req=True)
        except SoftwareError as e:
            return dict(error="Error: %s" % str(e))

        return result

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def deploy_precheck(self, *args, **kwargs):
        try:
            result = sc.software_deploy_precheck_api(list(args)[0], **kwargs)
        except SoftwareError as e:
            return dict(error="Error: %s" % str(e))

        return result

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def deploy_start(self, *args, **kwargs):
        if sc.any_patch_host_installing():
            return dict(error="Rejected: One or more nodes are installing releases.")

        try:
            result = sc.software_deploy_start_api(list(args)[0], **kwargs)
        except SoftwareError as e:
            return dict(error="Error: %s" % str(e))

        sc.send_latest_feed_commit_to_agent()
        sc.software_sync()

        return result

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def install_local(self):
        try:
            result = sc.software_install_local_api()
        except SoftwareError as e:
            return dict(error="Error: %s" % str(e))

        return result

    @expose('json')
    def is_available(self, *args):
        return sc.is_available(list(args))

    @expose('json')
    def is_committed(self, *args):
        return sc.is_committed(list(args))

    @expose('json')
    def is_deployed(self, *args):
        return sc.is_deployed(list(args))

    @expose('json')
    @expose('show.xml', content_type='application/xml')
    def show(self, *args):
        try:
            result = sc.software_release_query_specific_cached(list(args))
        except SoftwareError as e:
            return dict(error="Error: %s" % str(e))

        return result

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def upload(self):
        request_data = list(request.POST.items())
        temp_dir = os.path.join(constants.SCRATCH_DIR, 'upload_files')

        try:
            if len(request_data) == 0:
                raise SoftwareError("No files uploaded")
            # Protect against duplications
            uploaded_files = sorted(set(request_data))
            # Save all uploaded files to /scratch dir
            for file_item in uploaded_files:
                assert isinstance(file_item[1], cgi.FieldStorage)
                utils.save_temp_file(file_item[1], temp_dir)

            # Get all uploaded files from /scratch dir
            uploaded_files = utils.get_all_files(temp_dir)
            # Process uploaded files
            return sc.software_release_upload(uploaded_files)

        except Exception as e:
            return dict(error=str(e))
        finally:
            # Remove all uploaded files from /scratch dir
            sc.software_sync()
            shutil.rmtree(temp_dir, ignore_errors=True)

    @expose('json')
    def upload_dir(self, **kwargs):
        # todo(abailey): extensions should be configurable or
        # registered in setup.cfg
        extensions = ['*.patch', '*.tar', '*.iso']
        files = []
        # todo(abailey): investigate an alternative to glob
        for path in kwargs.values():
            LOG.info("upload-dir: Uploading software from: %s", path)
            for ext in extensions:
                for f in glob.glob(path + "/" + ext):
                    if os.path.isfile(f):
                        LOG.info("upload-dir: Uploading : %s", f)
                        files.append(f)

        if len(files) == 0:
            return dict(error="No software found matching %s" % extensions)

        try:
            result = sc.software_release_upload(sorted(files))
        except SoftwareError as e:
            return dict(error=str(e))
        sc.software_sync()
        return result

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def query(self, **kwargs):
        try:
            sd = sc.software_release_query_cached(**kwargs)
        except SoftwareError as e:
            return dict(error="Error: %s" % str(e))

        return dict(sd=sd)

    @expose('json')
    @expose('query_hosts.xml', content_type='application/xml')
    def query_hosts(self, *args):  # pylint: disable=unused-argument
        return dict(data=sc.query_host_cache())


class RootController:
    """pecan REST API root"""

    @expose()
    @expose('json')
    def index(self):
        """index for the root"""
        return "Unified Software Management API, Available versions: /v1"

    software = SoftwareAPIController()
    v1 = SoftwareAPIController()
