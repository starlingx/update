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

# todo(abailey): rename PatchError to SoftwareError
from software.exceptions import PatchError
from software.software_controller import sc

# Copies file in 64K chunk size
# A larger chunk size can be used to improve the copy speed
CHUNK_SIZE = 64

LOG = log.getLogger(__name__)


class SoftwareAPIController(object):

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def delete(self, *args):
        try:
            result = sc.software_release_delete_api(list(args))
        except PatchError as e:
            return dict(error="Error: %s" % str(e))

        sc.software_sync()

        return result

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def deploy_create(self, *args, **kwargs):
        if sc.any_patch_host_installing():
            return dict(error="Rejected: One or more nodes are installing patches.")

        try:
            result = sc.software_deploy_create_api(list(args), **kwargs)
        except PatchError as e:
            return dict(error="Error: %s" % str(e))

        sc.send_latest_feed_commit_to_agent()

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
        except PatchError as e:
            return dict(error="Error: %s" % str(e))

        return result

    @expose('json')
    def is_applied(self, *args):
        return sc.is_applied(list(args))

    @expose('json')
    def is_available(self, *args):
        return sc.is_available(list(args))

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def query(self, **kwargs):
        try:
            pd = sc.software_release_query_cached(**kwargs)
        except PatchError as e:
            return dict(error="Error: %s" % str(e))

        return dict(pd=pd)

    @expose('json')
    @expose('show.xml', content_type='application/xml')
    def show(self, *args):
        try:
            result = sc.software_release_query_specific_cached(list(args))
        except PatchError as e:
            return dict(error="Error: %s" % str(e))

        return result

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def upload(self):
        assert isinstance(request.POST['file'], cgi.FieldStorage)
        fileitem = request.POST['file']
        if not fileitem.filename:
            return dict(error="Error: No file uploaded")

        fn = '/scratch/' + os.path.basename(fileitem.filename)
        fdst = open(fn, 'wb')
        shutil.copyfileobj(fileitem.file, fdst, CHUNK_SIZE)
        fdst.close()

        try:
            result = sc.software_release_upload([fn])
        except PatchError as e:
            os.remove(fn)
            return dict(error=str(e))
        os.remove(fn)
        sc.software_sync()
        return result

    @expose('json')
    @expose('query_hosts.xml', content_type='application/xml')
    def query_hosts(self, *args):  # pylint: disable=unused-argument
        return dict(data=sc.query_host_cache())

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
        except PatchError as e:
            return dict(error=str(e))
        sc.software_sync()
        return result


class RootController:
    """pecan REST API root"""

    @expose()
    @expose('json')
    def index(self):
        """index for the root"""
        return "Unified Software Management API, Available versions: /v1"

    software = SoftwareAPIController()
    v1 = SoftwareAPIController()
