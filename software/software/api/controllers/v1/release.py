"""
Copyright (c) 2024 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import cgi
import json
import logging
import os
from pecan import expose
from pecan import request
from pecan.rest import RestController
import shutil
import webob

from software import constants
from software.exceptions import SoftwareServiceError
from software.release_data import reload_release_data
from software.software_controller import sc
from software import utils


LOG = logging.getLogger('main_logger')


class ReleaseController(RestController):
    _custom_actions = {
        'commit': ['POST'],
        'commit_dry_run': ['POST'],
        'is_available': ['GET'],
        'is_committed': ['GET'],
        'is_deployed': ['GET'],
    }

    @expose(method='GET', template='json')
    def get_all(self, **kwargs):
        reload_release_data()
        sd = sc.software_release_query_cached(**kwargs)
        return sd

    @expose(method='GET', template='json')
    def get_one(self, release):
        reload_release_data()
        result = sc.software_release_query_specific_cached([release])
        if len(result) == 1:
            return result[0]
        msg = f"Release {release} not found"
        raise webob.exc.HTTPNotFound(msg)

    @expose(method='POST', template='json')
    def post(self):
        reload_release_data()
        is_local = False
        temp_dir = None
        uploaded_files = []
        request_data = []
        local_files = []

        # --local option only sends a list of file names
        if (request.content_type == "text/plain"):
            body = request.body
            if isinstance(body, bytes):
                body = body.decode('utf-8')
            local_files = list(json.loads(body))
            is_local = True
        else:
            request_data = list(request.POST.items())
            temp_dir = os.path.join(constants.SCRATCH_DIR, 'upload_files')

        try:
            if len(request_data) == 0 and len(local_files) == 0:
                raise SoftwareServiceError(error="No files uploaded")

            if is_local:
                missing_files = [f for f in local_files if not os.path.isfile(f)]
                if missing_files:
                    raise SoftwareServiceError(
                        error=f"File(s) not found on the active controller: {', '.join(missing_files)}")

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
            return sc.software_release_upload_api(uploaded_files)

        finally:
            # Remove all uploaded files from /scratch dir
            sc.software_sync()
            if temp_dir:
                shutil.rmtree(temp_dir, ignore_errors=True)

    @expose(method='DELETE', template='json')
    def delete(self, *args):
        reload_release_data()
        ids = list(args)
        ids = [id for id in ids if id]
        result = sc.software_release_delete_api(ids)
        sc.software_sync()
        return result

    @expose(method='POST', template='json')
    def commit(self, *args):
        reload_release_data()
        result = sc.patch_commit(list(args))
        sc.software_sync()

        return result

    @expose(method='POST', template='json')
    def commit_dry_run(self, *args):
        reload_release_data()
        result = sc.patch_commit(list(args), dry_run=True)
        return result

    @expose(method='GET', template='json')
    def is_available(self, *args):
        reload_release_data()
        return sc.is_available(list(args))

    @expose(method='GET', template='json')
    def is_committed(self, *args):
        reload_release_data()
        return sc.is_committed(list(args))

    @expose(method='GET', template='json')
    def is_deployed(self, *args):
        reload_release_data()
        return sc.is_deployed(list(args))
