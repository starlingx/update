#
# Copyright (c) 2013-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

try:
    import software_client.client
    Client = software_client.client.Client
except ImportError:
    import warnings
    warnings.warn("Could not import software_client.client", ImportWarning)

__version__ = "1.0.0"
