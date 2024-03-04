"""
Copyright (c) 2023-2024 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

# Pecan Application Configurations
app = {
    'root': 'software.api.controllers.root.RootController',
    'modules': ['software.api'],
    'static_root': '%(confdir)s/public',
    'template_path': '%(confdir)s/../templates',
    'debug': False,
    'enable_acl': True,
    'acl_public_routes': [],
}
