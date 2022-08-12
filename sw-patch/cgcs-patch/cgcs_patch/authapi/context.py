#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_context import context


# Patching calls into fault. so only FM service type
# needs to be preserved in the service catalog
REQUIRED_SERVICE_TYPES = ('faultmanagement',)


class RequestContext(context.RequestContext):
    """Extends security contexts from the OpenStack common library."""

    def __init__(self, is_public_api=False, service_catalog=None, **kwargs):
        """Stores several additional request parameters:
        """
        super(RequestContext, self).__init__(**kwargs)
        self.is_public_api = is_public_api
        if service_catalog:
            # Only include required parts of service_catalog
            self.service_catalog = [s for s in service_catalog
                                    if s.get('type') in REQUIRED_SERVICE_TYPES]
        else:
            # if list is empty or none
            self.service_catalog = []

    def to_dict(self):
        value = super(RequestContext, self).to_dict()
        value.update({'is_public_api': self.is_public_api,
                      'service_catalog': self.service_catalog})
        return value


def make_context(*args, **kwargs):
    return RequestContext(*args, **kwargs)
