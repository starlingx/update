#!/bin/bash
#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# This builds 3 patches:
# SYSINV.1 contains sysinv components
# KUBE.1 contains kubeadm
# KUBE.2 contains the remainder (node, client, master, etc..)

PATH=$MY_REPO/stx/stx-update/extras/scripts:$PATH
SYSINV_PATCH_1=SYSINV.1
KUBE_PATCH_1=KUBE.1
KUBE_PATCH_2=KUBE.2
SEMANTIC_PATH=`dirname "$0"`
DIR=${MY_WORKSPACE}/std/rpmbuild/RPMS
SYSINV_SUFFIX=1.0-342.tis.x86_64.rpm
KUBE_SUFFIX=1.16.2-1.tis.1.x86_64.rpm

patch_build.sh \
    --id ${SYSINV_PATCH_1} \
    --reboot-required=N \
    ${DIR}/sysinv-${SYSINV_SUFFIX}

patch_build.sh \
    --id ${KUBE_PATCH_1} \
    --reboot-required=N \
    --pre-apply ${SEMANTIC_PATH}/KUBE.1.preapply   \
    --pre-remove ${SEMANTIC_PATH}/KUBE.1.preremove \
    --req ${SYSINV_PATCH_1} \
    ${DIR}/kubernetes-kubeadm-${KUBE_SUFFIX}

patch_build.sh \
    --id ${KUBE_PATCH_2} \
    --reboot-required=N \
    --pre-apply ${SEMANTIC_PATH}/KUBE.2.preapply   \
    --pre-remove ${SEMANTIC_PATH}/KUBE.2.preremove \
    --req ${KUBE_PATCH_1} \
    ${DIR}/kubernetes-node-${KUBE_SUFFIX}    \
    ${DIR}/kubernetes-client-${KUBE_SUFFIX}  \
    ${DIR}/kubernetes-${KUBE_SUFFIX} \
    ${DIR}/kubernetes-master-${KUBE_SUFFIX}
