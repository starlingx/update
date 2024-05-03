"""
Copyright (c) 2023-2024 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import logging
from pecan import expose
from pecan.rest import RestController

from software.software_controller import sc

LOG = logging.getLogger('main_logger')


class SoftwareAPIController(RestController):
    _custom_actions = {
        "in_sync_controller": ["GET"],
    }

    @expose(method='GET', template='json')
    def in_sync_controller(self):
        return sc.in_sync_controller_api()
