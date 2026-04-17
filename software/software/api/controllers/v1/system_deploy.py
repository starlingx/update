"""
Copyright (c) 2025-2026 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import logging

from pecan.rest import RestController
from pecan import expose
from pecan import response

from software.software_controller import sc


LOG = logging.getLogger('main_logger')


class SystemDeployController(RestController):
    _custom_actions = {
        'init': ['POST'],
    }

    @expose(method='POST', template='json')
    def init(self, release_id, kube_version=None):
        kube_ver = kube_version if kube_version else ""

        result = sc.software_system_deploy_init_api(release_id, kube_version=kube_ver)
        if result and 'error' in result and result['error'] != '':
            response.status = 406
        return result

    @expose(method='GET', template='json')
    def get_all(self):
        result = sc.software_system_deploy_show_api()
        return result
