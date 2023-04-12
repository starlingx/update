"""
Copyright (c) 2023 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
from pecan import expose

from software.exceptions import PatchError
from software.software_controller import pc


class PatchAPIController(object):

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
    def is_applied(self, *args):
        return pc.is_applied(list(args))

    @expose('json')
    def is_available(self, *args):
        return pc.is_available(list(args))


class RootController:
    """pecan REST API root"""

    @expose()
    @expose('json')
    def index(self):
        """index for the root"""
        return "Unified Software Management API, Available versions: /v1"

    patch = PatchAPIController()
    v1 = PatchAPIController()
