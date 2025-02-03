#
# Copyright (c) 2023-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# Hostnames
CONTROLLER = 'controller'
CONTROLLER_0_HOSTNAME = 'controller-0'
CONTROLLER_1_HOSTNAME = 'controller-1'

# System type
DUPLEX = 'duplex'
SIMPLEX = 'simplex'

# SW_VERSION should be built-in from build-tools
SW_VERSION = 'xxxPLATFORM_RELEASExxx'

DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER = 'systemcontroller'
SERVICE_TYPE_IDENTITY = 'identity'
WORKER = 'worker'

# Platform path
PLATFORM_PATH = "/opt/platform"
PLATFORM_CONFIG_PATH = PLATFORM_PATH + "/config/" + SW_VERSION + "/"
PLATFORM_CONF_FILE = PLATFORM_CONFIG_PATH + "/platform.conf"
CONFIG_PATH = PLATFORM_PATH + "/config/" + SW_VERSION + "/"
PLATFORM_CONFIG_PERMDIR = CONFIG_PATH

# Puppet path
PUPPET_PATH = PLATFORM_PATH + "/puppet/" + SW_VERSION + "/"
HIERADATA_PERMDIR = PUPPET_PATH + 'hieradata'

# Keyring path
KEYRING_WORKDIR = '/tmp/python_keyring'
KEYRING_DIR_PATH = PLATFORM_PATH + "/.keyring"
KEYRING_PATH = PLATFORM_PATH + "/.keyring/" + SW_VERSION
KEYRING_PERMDIR = KEYRING_PATH

# Kubernetes path
KUBERNETES_CONF_PATH = "/etc/kubernetes"
KUBERNETES_ADMIN_CONF_FILE = "admin.conf"

VOLATILE_PXEBOOT_PATH = "/var/pxeboot"
