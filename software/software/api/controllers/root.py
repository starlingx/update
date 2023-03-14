"""
Copyright (c) 2023 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
from pecan import expose


class RootController:
    """pecan REST API root"""

    @expose()
    @expose('json')
    def index(self):
        """index for the root"""
        return {}
