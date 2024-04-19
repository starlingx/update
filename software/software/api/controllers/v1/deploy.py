"""
Copyright (c) 2024 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import logging
from pecan import expose
from pecan import request
from pecan.rest import RestController

from software.exceptions import SoftwareServiceError
from software.release_data import reload_release_data
from software.software_controller import sc


LOG = logging.getLogger('main_logger')


class DeployController(RestController):
    _custom_actions = {
        'activate': ['POST'],
        'precheck': ['POST'],
        'start': ['POST'],
        'complete': ['POST'],
        'is_sync_controller': ['GET'],
        'software_upgrade': ['GET'],
    }

    @expose(method='POST', template='json')
    def activate(self):
        reload_release_data()

        result = sc.software_deploy_activate_api()
        sc.software_sync()
        return result

    @expose(method='POST', template='json')
    def complete(self):
        reload_release_data()

        result = sc.software_deploy_complete_api()
        sc.software_sync()
        return result

    @expose(method='POST', template='json')
    def precheck(self, release, force=None, region_name=None):
        _force = force is not None
        reload_release_data()

        result = sc.software_deploy_precheck_api(release, _force, region_name)
        return result

    @expose(method='POST', template='json')
    def start(self, release, force=None):
        reload_release_data()
        _force = force is not None

        if sc.any_patch_host_installing():
            raise SoftwareServiceError(error="Rejected: One or more nodes are installing a release.")

        result = sc.software_deploy_start_api(release, _force)

        sc.send_latest_feed_commit_to_agent()
        sc.software_sync()

        return result

    @expose(method='GET', template='json')
    def get_all(self):
        reload_release_data()
        from_release = request.GET.get("from_release")
        to_release = request.GET.get("to_release")
        result = sc.software_deploy_show_api(from_release, to_release)
        return result

    @expose(method='GET', template='json')
    def in_sync_controller(self):
        return sc.in_sync_controller_api()

    @expose(method='GET', template='json')
    def software_upgrade(self):
        return sc.get_software_upgrade()
