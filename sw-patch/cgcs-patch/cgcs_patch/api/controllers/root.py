"""
Copyright (c) 2014-2019 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import os
from pecan import expose
from pecan import request
import cgi
import glob
import shutil

from cgcs_patch.exceptions import PatchError
from cgcs_patch.patch_controller import pc

from cgcs_patch.patch_functions import LOG


class PatchAPIController(object):

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def index(self):
        return self.query()

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def query(self, **kwargs):
        try:
            pd = pc.patch_query_cached(**kwargs)
        except PatchError as e:
            return dict(error="Error: %s" % str(e))

        return dict(pd=pd)

    @expose('json')
    @expose('show.xml', content_type='application/xml')
    def show(self, *args):
        try:
            result = pc.patch_query_specific_cached(list(args))
        except PatchError as e:
            return dict(error="Error: %s" % str(e))

        return result

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def apply(self, *args, **kwargs):
        if pc.any_patch_host_installing():
            return dict(error="Rejected: One or more nodes are installing patches.")

        try:
            result = pc.patch_apply_api(list(args), **kwargs)
        except PatchError as e:
            return dict(error="Error: %s" % str(e))

        pc.send_latest_feed_commit_to_agent()

        pc.patch_sync()

        return result

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def remove(self, *args, **kwargs):
        if pc.any_patch_host_installing():
            return dict(error="Rejected: One or more nodes are installing patches.")

        try:
            result = pc.patch_remove_api(list(args), **kwargs)
        except PatchError as e:
            return dict(error="Error: %s" % str(e))

        pc.send_latest_feed_commit_to_agent()

        pc.patch_sync()

        return result

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def delete(self, *args):
        try:
            result = pc.patch_delete_api(list(args))
        except PatchError as e:
            return dict(error="Error: %s" % str(e))

        pc.patch_sync()

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
        # Copies file in 64K chunk size. A larger chunk size
        # can be used to improve the copy speed.
        shutil.copyfileobj(fileitem.file, fdst, 64)
        fdst.close()

        try:
            result = pc.patch_import_api([fn])
        except PatchError as e:
            os.remove(fn)
            return dict(error=str(e))

        os.remove(fn)

        pc.patch_sync()

        return result

    @expose('json')
    def upload_dir(self, **kwargs):
        files = []
        for path in kwargs.values():
            LOG.info("upload-dir: Retrieving patches from %s", path)
            for f in glob.glob(path + '/*.patch'):
                if os.path.isfile(f):
                    files.append(f)

        if len(files) == 0:
            return dict(error="No patches found")

        try:
            result = pc.patch_import_api(sorted(files))
        except PatchError as e:
            return dict(error=str(e))

        pc.patch_sync()

        return result

    @expose('json')
    def init_release(self, *args):
        if len(list(args)) == 0:
            return dict(error="Release must be specified")

        try:
            result = pc.patch_init_release_api(list(args)[0])
        except PatchError as e:
            return dict(error=str(e))

        pc.patch_sync()

        return result

    @expose('json')
    def del_release(self, *args):
        if len(list(args)) == 0:
            return dict(error="Release must be specified")

        try:
            result = pc.patch_del_release_api(list(args)[0])
        except PatchError as e:
            return dict(error=str(e))

        pc.patch_sync()

        return result

    @expose('json')
    @expose('query_hosts.xml', content_type='application/xml')
    def query_hosts(self, *args):  # pylint: disable=unused-argument
        return dict(data=pc.query_host_cache())

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def what_requires(self, *args):
        try:
            result = pc.patch_query_what_requires(list(args))
        except PatchError as e:
            return dict(error="Error: %s" % str(e))

        return result

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def host_install(self, *args):  # pylint: disable=unused-argument
        return dict(error="Deprecated: Use host_install_async")

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def host_install_async(self, *args):
        if len(list(args)) == 0:
            return dict(error="Host must be specified for install")
        force = False
        if len(list(args)) > 1 and 'force' in list(args)[1:]:
            force = True

        try:
            result = pc.patch_host_install(list(args)[0], force, async_req=True)
        except PatchError as e:
            return dict(error="Error: %s" % str(e))

        return result

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def drop_host(self, *args):
        if len(list(args)) == 0:
            return dict(error="Host must be specified")

        try:
            result = pc.drop_host(list(args)[0])
        except PatchError as e:
            return dict(error="Error: %s" % str(e))

        return result

    @expose('json')
    def query_dependencies(self, *args, **kwargs):
        try:
            result = pc.patch_query_dependencies(list(args), **kwargs)
        except PatchError as e:
            return dict(error=str(e))

        return result

    @expose('json')
    def commit(self, *args):
        try:
            result = pc.patch_commit(list(args))
        except PatchError as e:
            return dict(error=str(e))

        pc.patch_sync()

        return result

    @expose('json')
    def commit_dry_run(self, *args):
        try:
            result = pc.patch_commit(list(args), dry_run=True)
        except PatchError as e:
            return dict(error=str(e))

        return result

    @expose('json')
    def is_applied(self, *args):
        return pc.is_applied(list(args))

    @expose('json')
    def is_available(self, *args):
        return pc.is_available(list(args))

    @expose('json')
    def report_app_dependencies(self, *args, **kwargs):
        try:
            result = pc.report_app_dependencies(list(args), **kwargs)
        except PatchError as e:
            return dict(status=500, error=str(e))

        pc.patch_sync()

        return result

    @expose('json')
    def query_app_dependencies(self):
        return pc.query_app_dependencies()


class RootController(object):

    @expose()
    @expose('json')
    def index(self):
        return "Titanium Cloud Patching API, Available versions: /v1"

    patch = PatchAPIController()
    v1 = PatchAPIController()
