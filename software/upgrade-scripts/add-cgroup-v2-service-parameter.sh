#!/bin/bash
#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Adds cgroup_v2_enabled service parameter during upgrade activate.
# This runs after reboot when the system is fully up.
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
    # Detect cgroup version from mounted filesystem type
    # cgroup2fs = v2 unified, tmpfs = v1 legacy
    CGROUP_FSTYPE=$(stat -fc %T /sys/fs/cgroup)
    if [[ "$CGROUP_FSTYPE" == "cgroup2fs" ]]; then
        CGROUP_V2=true
    else
        CGROUP_V2=false
    fi
    log "Detected cgroup v2=$CGROUP_V2 (fstype=$CGROUP_FSTYPE)"

    if system service-parameter-list --service platform --section config 2>/dev/null | grep -q cgroup_v2_enabled; then
        log "cgroup_v2_enabled already exists. Skipping."
    else
        system service-parameter-add platform config cgroup_v2_enabled=$CGROUP_V2
        log "Added cgroup_v2_enabled=$CGROUP_V2."
    fi

    # Update kubelet cgroup service parameters to match 26.10 expectations.
    # cgroupRoot: always /k8sinfra (renamed from /k8s-infra in 25.09)
    # cgroupDriver: systemd for v2, cgroupfs for v1
    if [[ "$CGROUP_V2" == "true" ]]; then
        EXPECTED_DRIVER="systemd"
    else
        EXPECTED_DRIVER="cgroupfs"
    fi

    system service-parameter-modify kubernetes kubelet cgroupDriver="$EXPECTED_DRIVER"
    log "Set kubernetes/kubelet/cgroupDriver=$EXPECTED_DRIVER"

    system service-parameter-modify kubernetes kubelet cgroupRoot=/k8sinfra
    log "Set kubernetes/kubelet/cgroupRoot=/k8sinfra"

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
