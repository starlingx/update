"""
Copyright (c) 2024-2026 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import logging

from pecan.rest import RestController
from pecan import expose
from pecan import request
from pecan import response

from software.exceptions import SoftwareServiceError
from software.release_data import reload_release_data
from software.software_controller import sc


LOG = logging.getLogger('main_logger')


class DeployController(RestController):
    _custom_actions = {
        'abort': ['POST'],
        'activate': ['POST'],
        'activate_rollback': ['POST'],
        'precheck': ['POST'],
        'start': ['POST'],
        'complete': ['POST'],
        'delete': ['DELETE'],
        'software_upgrade': ['GET'],
        'software_sync': ['POST'],
        'select': ['POST'],
        'unselect': ['POST'],
    }

    @expose(method='POST', template='json')
    def abort(self):
        reload_release_data()

        result = sc.software_deploy_abort_api()
        sc.software_sync()
        return result

    @expose(method='POST', template='json')
    def activate(self):
        reload_release_data()

        result = sc.software_deploy_activate_api()
        sc.software_sync()
        return result

    @expose(method='POST', template='json')
    def activate_rollback(self):
        reload_release_data()

        result = sc.software_deploy_activate_rollback_api()
        sc.software_sync()
        return result

    @expose(method='POST', template='json')
    def complete(self):
        reload_release_data()

        result = sc.software_deploy_complete_api()
        sc.software_sync()
        return result

    @expose(method='DELETE', template='json')
    def delete(self):
        reload_release_data()

        result = sc.software_deploy_delete_api()
        sc.software_sync()
        return result

    @expose(method='POST', template='json')
    def precheck(self, **kwargs):
        reload_release_data()

        result = sc.software_deploy_precheck_api(**kwargs)
        if result["error"]:
            response.status = 406

        return result

    @expose(method='POST', template='json')
    def start(self, releases=None, force=None, **kwargs):
        reload_release_data()
        _force = force is not None

        if sc.any_patch_host_installing():
            raise SoftwareServiceError(error="Rejected: One or more nodes are installing a release.")

        if releases:
            releases = releases.split(",")
        result = sc.software_deploy_start_api(releases, _force, **kwargs)

        if result and 'error' in result and result["error"] != "":
            response.status = 406

        return result

    @expose(method='GET', template='json')
    def get_all(self):
        reload_release_data()
        from_release = request.GET.get("from_release")
        to_release = request.GET.get("to_release")
        result = sc.software_deploy_show_api(from_release, to_release)
        return result

    @expose(method='GET', template='json')
    def software_upgrade(self):
        return sc.get_software_upgrade()

    @expose(method='POST', template='json')
    def software_sync(self):
        reload_release_data()
        result = sc.software_sync()
        return {"result": result}

    @expose(method='POST', template='json')
    def select(self, **kwargs):
        reload_release_data()
        result = sc.software_deploy_select_api(**kwargs)
        sc.software_sync()
        return result

    @expose(method='POST', template='json')
    def unselect(self, **kwargs):
        reload_release_data()
        result = sc.software_deploy_unselect_api(**kwargs)
        sc.software_sync()
        return result
