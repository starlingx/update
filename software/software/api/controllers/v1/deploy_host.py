"""
Copyright (c) 2024 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import logging
from pecan import expose
from pecan.rest import RestController

from software.release_data import reload_release_data
from software.software_controller import sc


LOG = logging.getLogger('main_logger')


class DeployHostController(RestController):
    _custom_actions = {
        'install_local': ['POST'],
    }

    @expose(method='GET', template='json')
    def get_all(self):
        reload_release_data()
        result = sc.deploy_host_list()
        return result

    @expose(method='POST', template='json')
    def post(self, *args):
        reload_release_data()
        if len(list(args)) == 0:
            return dict(error="Host must be specified for install")

        force = False
        if len(list(args)) > 1 and 'force' in list(args)[1:]:
            force = True

        rollback = False
        if len(list(args)) > 1 and 'rollback' in list(args[1:]):
            rollback = True

        if rollback:
            result = sc.software_deploy_host_rollback_api(list(args)[0], force,
                                                          async_req=True)
        else:
            result = sc.software_deploy_host_api(list(args)[0], force,
                                                 async_req=True)

        return result

    @expose(method='POST', template='json')
    def install_local(self, delete):
        reload_release_data()
        result = sc.software_install_local_api(delete)
        return result
