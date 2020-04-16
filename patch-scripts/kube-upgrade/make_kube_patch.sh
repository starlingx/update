#!/bin/bash
#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# This builds 3 patches:
# PLATFORM_PATCH_1 contains sysinv and playbookconfig components
# KUBE_PATCH_1 contains kubeadm
# KUBE_PATCH_2 contains the remainder (node, client, master, etc..)

PATH=$MY_REPO/stx/update/extras/scripts:$PATH
SEMANTIC_PATH=`dirname "$0"`
DIR=${MY_WORKSPACE}/std/rpmbuild/RPMS

# Patch names
PLATFORM_PATCH_1=PLATFORM.1
KUBE_PATCH_1=KUBE.1
KUBE_PATCH_2=KUBE.2

# Add the following options to include restart scripts for sysinv:
# --controller ${DIR}/EXAMPLE_SYSINV-1.0-*.x86_64.rpm \
# --controller-worker ${DIR}/EXAMPLE_SYSINV-1.0-*.x86_64.rpm \
# --controller-worker-lowlatency ${DIR}/EXAMPLE_SYSINV-1.0-*.x86_64.rpm \
patch_build.sh \
    --id ${PLATFORM_PATCH_1} \
    --reboot-required=N \
    ${DIR}/sysinv-1.0-*.tis.x86_64.rpm \
    ${DIR}/playbookconfig-1.0-*.tis.x86_64.rpm

patch_build.sh \
    --id ${KUBE_PATCH_1} \
    --reboot-required=N \
    --pre-apply ${SEMANTIC_PATH}/KUBE.1.preapply   \
    --pre-remove ${SEMANTIC_PATH}/KUBE.1.preremove \
    --req ${PLATFORM_PATCH_1} \
    ${DIR}/kubernetes-kubeadm-1.18.1_upgrade-1.tis.*.x86_64.rpm

patch_build.sh \
    --id ${KUBE_PATCH_2} \
    --reboot-required=N \
    --pre-apply ${SEMANTIC_PATH}/KUBE.2.preapply   \
    --pre-remove ${SEMANTIC_PATH}/KUBE.2.preremove \
    --req ${KUBE_PATCH_1} \
    ${DIR}/kubernetes-node-1.18.1_upgrade-1.tis.*.x86_64.rpm \
    ${DIR}/kubernetes-client-1.18.1_upgrade-1.tis.*.x86_64.rpm \
    ${DIR}/kubernetes-1.18.1_upgrade-1.tis.*.x86_64.rpm \
    ${DIR}/kubernetes-master-1.18.1_upgrade-1.tis.*.x86_64.rpm
