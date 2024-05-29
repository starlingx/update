"""
Copyright (c) 2023-2024 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

from enum import Enum
import os

from software.constants import SOFTWARE_STORAGE_DIR


# TODO(lbonatti) Remove this diagram once it is mapped in the documentation
# software release life cycle
# (fresh install) -> deployed -> (upgrade to next version and deploy complete) -> unavailable -> (delete)
#                      ^
#                      |---------------------------------------------------------
#                                                                               ^
#                                                                               |
# (upload) -> available ->(deploy start) -> deploying -> (deploy complete) -> deployed
#               \---> (delete)
#
# =================================================================================================
#
# deploy life cycle
# (deploy-start)
#     |
#     V
# deploy-start
#     |
#     V
# start-done -> deploy-host -> deploy-activate -> deploy-activate-done -> deploy-complete -> (delete)
#     \              \            \                  \                      \
#      \-> (delete)   \-> (deploy abort) -> deploy-host-rollback -> deploy-host-done -> (delete)
#                                   \------------------\----------------------\-> (deploy abort) -> deploy-activate-rollback -\
#                                                       ^                                                                      \
#                                                        \----------------------------------------------------------------------\
#
# =================================================================================================
#
# deploy host life cycle
#                      /----(deploy abort/reverse deploy)---
#                     /                                     |
#                    /                                      V
# (deploy-start) -> pending -> deploying -------------> deployed --------(deploy-complete) -> (deleted)
#                     ^                           \---------> (deploy abort/reverse deploy)
#                     |                                            /
#                     |-------------------------------------------/


# Release states
AVAILABLE_DIR = os.path.join(SOFTWARE_STORAGE_DIR, "metadata/available")
UNAVAILABLE_DIR = os.path.join(SOFTWARE_STORAGE_DIR, "metadata/unavailable")
DEPLOYING_DIR = os.path.join(SOFTWARE_STORAGE_DIR, "metadata/deploying")
DEPLOYED_DIR = os.path.join(SOFTWARE_STORAGE_DIR, "metadata/deployed")
REMOVING_DIR = os.path.join(SOFTWARE_STORAGE_DIR, "metadata/removing")
COMMITTED_DIR = os.path.join(SOFTWARE_STORAGE_DIR, "metadata/committed")

DEPLOY_STATE_METADATA_DIR = [
    AVAILABLE_DIR,
    UNAVAILABLE_DIR,
    DEPLOYING_DIR,
    DEPLOYED_DIR,
    REMOVING_DIR,
    COMMITTED_DIR,
]

# new release state needs to be added to VALID_RELEASE_STATES list
AVAILABLE = 'available'
UNAVAILABLE = 'unavailable'
DEPLOYING = 'deploying'
DEPLOYED = 'deployed'
REMOVING = 'removing'
COMMITTED = 'committed'

VALID_RELEASE_STATES = [AVAILABLE, UNAVAILABLE, DEPLOYING, DEPLOYED,
                        REMOVING, COMMITTED]

RELEASE_STATE_TO_DIR_MAP = {AVAILABLE: AVAILABLE_DIR,
                            UNAVAILABLE: UNAVAILABLE_DIR,
                            DEPLOYING: DEPLOYING_DIR,
                            DEPLOYED: DEPLOYED_DIR,
                            REMOVING: REMOVING_DIR,
                            COMMITTED: COMMITTED_DIR}

DELETABLE_STATE = [AVAILABLE, UNAVAILABLE]

# valid release state transition below could still be changed as
# development continue
RELEASE_STATE_VALID_TRANSITION = {
    AVAILABLE: [DEPLOYING],
    DEPLOYING: [DEPLOYED, AVAILABLE],
    DEPLOYED: [REMOVING, UNAVAILABLE]
}

VALID_DEPLOY_START_STATES = [
    AVAILABLE,
    DEPLOYED,
]


# deploy states
class DEPLOY_STATES(Enum):
    START = 'start'
    START_DONE = 'start-done'
    START_FAILED = 'start-failed'

    HOST = 'host'
    HOST_DONE = 'host-done'
    HOST_FAILED = 'host-failed'

    HOST_ROLLBACK = 'host-rollback'
    HOST_ROLLBACK_DONE = 'host-rollback-done'
    HOST_ROLLBACK_FAILED = 'host-rollback-failed'

    ACTIVATE = 'activate'
    ACTIVATE_DONE = 'activate-done'
    ACTIVATE_FAILED = 'activate-failed'

    ACTIVATE_ROLLBACK = 'activate-rollback'
    ACTIVATE_ROLLBACK_FAILED = 'activate-rollback-failed'

    COMPLETED = 'completed'


# deploy host state
class DEPLOY_HOST_STATES(Enum):
    DEPLOYED = 'deployed'
    DEPLOYING = 'deploying'
    FAILED = 'failed'
    PENDING = 'pending'

    ROLLBACK_DEPLOYED = 'rollback-deployed'
    ROLLBACK_DEPLOYING = 'rollback-deploying'
    ROLLBACK_FAILED = 'rollback-failed'
    ROLLBACK_PENDING = 'rollback-pending'


VALID_HOST_DEPLOY_STATE = [
    DEPLOY_HOST_STATES.DEPLOYED,
    DEPLOY_HOST_STATES.DEPLOYING,
    DEPLOY_HOST_STATES.FAILED,
    DEPLOY_HOST_STATES.PENDING,
    DEPLOY_HOST_STATES.ROLLBACK_DEPLOYED,
    DEPLOY_HOST_STATES.ROLLBACK_DEPLOYING,
    DEPLOY_HOST_STATES.ROLLBACK_FAILED,
    DEPLOY_HOST_STATES.ROLLBACK_PENDING,
]
