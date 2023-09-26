#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# SW_VERSION should be built-in from build-tools
SW_VERSION = 'xxxPLATFORM_RELEASExxx'

DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER = 'systemcontroller'
WORKER = 'worker'
SERVICE_TYPE_IDENTITY = 'identity'

PLATFORM_PATH = "/opt/platform"
PLATFORM_CONFIG_PATH = PLATFORM_PATH + "/config/" + SW_VERSION + "/"
PLATFORM_CONF_FILE = PLATFORM_CONFIG_PATH + "/platform.conf"
CONFIG_PATH = PLATFORM_PATH + "/config/" + SW_VERSION + "/"
PLATFORM_CONFIG_PERMDIR = CONFIG_PATH

PUPPET_PATH = PLATFORM_PATH + "/puppet/" + SW_VERSION + "/"
HIERADATA_PERMDIR = PUPPET_PATH + 'hieradata'

KEYRING_WORKDIR = '/tmp/python_keyring'
KEYRING_PATH = PLATFORM_PATH + "/.keyring/" + SW_VERSION
KEYRING_PERMDIR = KEYRING_PATH

VOLATILE_PXEBOOT_PATH = "/var/pxeboot"

KUBERNETES_CONF_PATH = "/etc/kubernetes"
KUBERNETES_ADMIN_CONF_FILE = "admin.conf"

CONTROLLER = 'controller'
CONTROLLER_0_HOSTNAME = 'controller-0'
CONTROLLER_1_HOSTNAME = 'controller-1'

SIMPLEX = 'simplex'
DUPLEX = 'duplex'
