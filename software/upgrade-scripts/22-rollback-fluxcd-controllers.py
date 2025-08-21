#!/usr/bin/python
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script rolls back flux controllers in the fluxcd-helm namespace

import json
import logging
import os
import re
import subprocess
import sys
import yaml

from sysinv.common import exception
from sysinv.common.retrying import retry
from sysinv.common.kubernetes import test_k8s_health

from software.utilities.utils import configure_logging

LOG = logging.getLogger('main_logger')

RELEASE_NAME = "fluxcd"
RELEASE_NAMESPACE = "flux-helm"
KUBECONFIG = "/etc/kubernetes/admin.conf"
TARGET_REVISION = "1"
KUBECTL_REQUEST_TIMEOUT = "60s"
BUCKETS_CRD = "buckets.source.toolkit.fluxcd.io"
LEGACY_CHART_DIRECTORY = "/usr/local/share/flux2-charts-legacy/"


def find_flux_chart():
    """ Find the Flux chart that corresponds to the target release for rollback.

    Returns:
        path: Absolute path to the chart tarball.
    """

    pattern = re.compile(r'^flux2-(\d+\.\d+\.\d+)\.tgz$')

    for filename in os.listdir(LEGACY_CHART_DIRECTORY):
        if pattern.match(filename):
            return os.path.join(LEGACY_CHART_DIRECTORY, filename)

    return None


def get_chart_version(tgz_path):
    """ Retrieve the version from a chart tarball

    Args:
        tgz_path (path): path to the chart tarball

    Returns:
        string: chart version.
    """

    try:
        result = subprocess.run(
            ["helm", "show", "chart", tgz_path],
            capture_output=True,
            text=True,
            check=True
        )
        chart_yaml = yaml.safe_load(result.stdout)
        return chart_yaml.get("version")
    except subprocess.CalledProcessError as e:
        print(f"Error while retrieving chart version: {e.stderr}")
    except Exception as e:
        raise exception.SysinvException(f"Cannot retrieve chart version: {e}")


def get_target_revision(history, target_version):
    """ Retrieve the target Helm release revision for rollback

    Args:
        history (list): list of records of the release history.
        target_version (string): target version for rollback.

    Returns:
        integer: Revision number.
    """

    for record in reversed(history[:-1]):
        if f"-{target_version}" in record["chart"]:
            return record["revision"]
    return None


def is_target_version_installed(history, target_version):
    """ Retrieve the target Helm release revision for rollback

    Args:
        history (list): list of records of the release history.
        target_version (string): target version for rollback.

    Returns:
        bool: True if the target release is installed. False otherwise.
    """

    if len(history) == 0:
        # This is ok for stx11 since it means that Flux hasn't been migrated over to
        # Helm when the activation process was interruped.
        # TODO(ipiresso): should return an error for releases after stx11 where it will be
        # always expected to have a Helm history during rollback.
        LOG.info("Flux not migrated over to Helm. Skipping.")
        return True
    elif f"-{target_version}" in history[-1]["chart"] and history[-1]["status"] == 'deployed':
        LOG.warning("Already running target Flux release. Skipping.")
        return True

    return False


def get_history():
    """ Retrieve the Helm history for the Flux release.

    Returns:
        list: Records of each revision of the fluxcd release.
    """

    try:
        result = subprocess.run(
            ["helm",
             "history", RELEASE_NAME,
             "-n", RELEASE_NAMESPACE,
             "--output", "json",
             "--kubeconfig", KUBECONFIG],
            check=True,
            capture_output=True,
            text=True
        )

        history = json.loads(result.stdout)
        return history
    except subprocess.CalledProcessError as e:
        if 'not found' in e.stderr:
            LOG.warning("Helm release %s not found in %s namespace",
                        RELEASE_NAME, RELEASE_NAMESPACE)
            return []
        raise exception.SysinvException("Error while attempting to retrieve Helm "
                                        f"release history: {e.stderr}")
    except Exception as e:
        raise exception.SysinvException(f"Cannot retrieve Helm release history: {e}")


@retry(retry_on_exception=lambda x: isinstance(x, exception.SysinvException),
       stop_max_attempt_number=3)
def delete_incompatible_crd():
    """ Delete buckets.source.toolkit.fluxcd.io CRD as manifests from
        versions 2.13 and 2.15 do not support straightforward rollback.
    """

    # First check if the CRD exists
    try:
        subprocess.run(
            ["kubectl", "get",
             "customresourcedefinitions.apiextensions.k8s.io",
             BUCKETS_CRD,
             f"--request-timeout={KUBECTL_REQUEST_TIMEOUT}",
             "--kubeconfig", KUBECONFIG],
            check=True,
            capture_output=True,
            text=True
        )
    except subprocess.CalledProcessError as e:
        if "not found" in e.stderr:
            LOG.warning("CRD %s not found for deletion", BUCKETS_CRD)
            return
        raise exception.SysinvException(f"Error while checking CRD: {e.stderr}")
    except Exception as e:
        raise exception.SysinvException(f"Cannot check if CRD exists: {e}")

    LOG.info("Deleting incompatible CRD %s", BUCKETS_CRD)

    try:
        subprocess.run(
            ["kubectl", "delete",
             "customresourcedefinitions.apiextensions.k8s.io",
             BUCKETS_CRD,
             f"--request-timeout={KUBECTL_REQUEST_TIMEOUT}",
             "--kubeconfig", KUBECONFIG],
            check=True,
            capture_output=True
        )
    except subprocess.CalledProcessError as e:
        raise exception.SysinvException(f"Error while deleting CRD: {e.stderr}")
    except Exception as e:
        raise exception.SysinvException(f"Cannot delete CRD: {e}")

    LOG.info("CRD successfully deleted")


@retry(retry_on_exception=lambda x: isinstance(x, exception.SysinvException),
       stop_max_attempt_number=3)
@test_k8s_health
def rollback_fluxcd_controllers(revision):
    """ Rollback flux controllers via 'helm rollback'

    Args:
        revision (integer): target revision number.
    """

    LOG.info("Rolling back Flux release to revision %s", revision)

    try:
        subprocess.run(
            ["helm", "rollback", RELEASE_NAME, str(revision),
             "-n", RELEASE_NAMESPACE,
             "--kubeconfig", KUBECONFIG,
             "--wait",
             "--wait-for-jobs"],
            check=True,
            capture_output=True
        )
    except subprocess.CalledProcessError as e:
        raise exception.SysinvException(f"Error while rolling back flux controllers: {e.stderr}")
    except Exception as e:
        raise exception.SysinvException(f"Cannot rollback flux controllers: {e}")

    LOG.info("Flux release successfully rolled back")


# Workaround for portieris issue when helm-controller is restarting
@test_k8s_health
def wait_helm_controller_pod_ready():
    """ Wait for helm-controller pod to be Ready
    """

    LOG.info("Waiting for helm-controller pod to be Ready")

    try:
        subprocess.run(
            ["kubectl", "wait", "--for=condition=Ready", "pods",
             "-l", "app=helm-controller",
             "-n", RELEASE_NAMESPACE,
             "--timeout=60s",
             "--kubeconfig", KUBECONFIG],
            check=True
        )
    except Exception as e:
        # Warning and proceeding with the rollback, as the issue might be fixed by it
        LOG.warning(f"Error waiting for helm-controller pod to be Ready: {e}")
    else:
        LOG.info("helm-controller pod is Ready. Proceeding.")


def main():

    action = None
    from_release = None
    to_release = None
    arg = 1
    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]
        elif arg == 3:
            action = sys.argv[arg]
        elif arg == 4:
            # Optional postgres port parameter for USM upgrade (not used
            # by this script).
            pass
        else:
            print(f"Invalid option {sys.argv[arg]}")
            return 1
        arg += 1
    configure_logging()

    LOG.info("%s invoked with from_release %s to_release %s and action %s",
             sys.argv[0], from_release, to_release, action)

    if action == 'activate-rollback':
        flux_chart = find_flux_chart()
        if flux_chart is None:
            LOG.error("Flux chart from previous version is not available")
            return 1

        try:
            previous_version = get_chart_version(flux_chart)
            history = get_history()

            # Rollback only if not already in the target version
            if not is_target_version_installed(history, previous_version):
                target_revision = get_target_revision(history, previous_version)

                if target_revision:
                    delete_incompatible_crd()
                    wait_helm_controller_pod_ready()
                    rollback_fluxcd_controllers(target_revision)
                else:
                    LOG.error("Version %s is not available in revision history", previous_version)
                    return 1

        except exception.SysinvException as e:
            LOG.exception(e)
            return 1
    else:
        LOG.info("Not an activate-rollback action. Skipping.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
