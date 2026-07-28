#!/bin/bash
#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Update cgroupRoot in kubelet-config ConfigMap during upgrade activate.
#

NAME=$(basename $0)
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

source /etc/platform/openrc 2>/dev/null

function log {
    echo "$(date -Iseconds | cut -d'+' -f1): ${NAME}[$$]: INFO: $*" >> "/var/log/software.log" 2>&1
}

log "Invoked from=$FROM_RELEASE to=$TO_RELEASE action=$ACTION"

if [[ "$ACTION" == "activate" ]]; then
    # Migrate cgroupRoot in kubelet-config ConfigMap (/k8s-infra -> /k8sinfra).
    # This is the source of truth for kubelet config. If not updated here,
    # any subsequent kubeadm operation (e.g., k8s upgrade) will regenerate
    # config.yaml with the old name, causing kubelet to fail.
    KUBECONFIG=/etc/kubernetes/admin.conf
    if kubectl --kubeconfig=$KUBECONFIG -n kube-system \
        get configmap kubelet-config -o yaml 2>/dev/null | grep -q '/k8s-infra'; then
        kubectl --kubeconfig=$KUBECONFIG -n kube-system \
            get configmap kubelet-config -o json | \
            sed 's|/k8s-infra|/k8sinfra|g' | \
            kubectl --kubeconfig=$KUBECONFIG apply -f -
        if [ $? -eq 0 ]; then
            log "Patched kubelet-config ConfigMap: cgroupRoot /k8s-infra -> /k8sinfra"
        else
            log "ERROR: Failed to patch kubelet-config ConfigMap."
        fi
    else
        log "kubelet-config ConfigMap already has /k8sinfra or not accessible."
    fi
fi

exit 0
