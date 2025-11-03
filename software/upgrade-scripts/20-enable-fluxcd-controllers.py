#!/usr/bin/python
# Copyright (c) 2022-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script install fluxcd controllers in the flux-helm namespace
# in kubernetes
#

import logging
import subprocess
import sys

from sysinv.common import exception
from sysinv.common.retrying import retry
from sysinv.common.kubernetes import test_k8s_health

from software.utilities.utils import configure_logging

LOG = logging.getLogger('main_logger')

FLUXCD_NAMESPACE = "flux-helm"
FLUXCD_HELM_RELEASE = "fluxcd"
KUBECONFIG = "/etc/kubernetes/admin.conf"
KUBECTL_REQUEST_TIMEOUT = "60s"


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
            # postgres_port = sys.argv[arg]
            pass
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1
    configure_logging()

    if action == "activate" and from_release >= "24.09":
        namespace_created = create_fluxcd_namespace()
        fluxcd_helm_release_not_installed = helm_release_not_exists()

        LOG.info(
            "%s invoked with from_release = %s to_release = %s "
            "action = %s" % (sys.argv[0], from_release, to_release, action)
        )
        enable_fluxcd_controllers(
            from_release, namespace_created, fluxcd_helm_release_not_installed
        )


def execute_command(
    cmd, success_message, error_message, return_type="exception", output_processor_fn=None
):
    """Generic function to execute commands and handle their output

    Args:
        cmd: Command to execute
        success_message: Message to log on success
        error_message: Error message prefix for failures
        return_type:
            - exception' (raise on error)
            - processed' (use output_processor_fn)
        output_processor_fn: Function to process command output (for return_type='processed')

    Returns:
        None (for 'exception') or processed result (for 'processed')
    """
    try:
        sub = subprocess.Popen(cmd, shell=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = sub.communicate()

        stdout = stdout.decode('utf-8').strip()
        stderr = stderr.decode('utf-8').strip()

        if sub.returncode != 0:
            if return_type == "exception":
                raise exception.SysinvException(
                    f"{error_message} via {cmd}, stderr: {stderr}"
                )
            elif return_type == "processed" and output_processor_fn:
                return output_processor_fn(stderr, returned_code=sub.returncode)

        LOG.info(f"{success_message} Output: {stdout}")

        if return_type == "processed" and output_processor_fn:
            return output_processor_fn(stdout)

    except Exception as e:
        LOG.error(f"Exception occurred while executing command '{cmd}': {e}")
        raise exception.SysinvException(f"{error_message} via {cmd}, reason: {e}")


@retry(
    retry_on_exception=lambda x: isinstance(x, exception.SysinvException),
    stop_max_attempt_number=3,
)
@test_k8s_health
def enable_fluxcd_controllers(from_release, namespace_created, fluxcd_helm_release_not_installed):
    """Run fluxcd_controllers ansible playbook to enable fluxcd controllers"""

    playbooks_root = "/usr/share/ansible/stx-ansible/playbooks"
    upgrade_script = "upgrade-fluxcd-controllers.yml"
    cmd = (
        f'ansible-playbook {playbooks_root}/{upgrade_script} '
        f'-e "upgrade_activate_from_release={from_release} '
        f'fluxcd_namespace_created={namespace_created} '
        f'fluxcd_helm_release_not_installed={fluxcd_helm_release_not_installed}"'
    )

    LOG.info("Enabling FluxCD controllers...")

    execute_command(
        cmd=cmd,
        success_message="FluxCD controllers enabled.",
        error_message="Error trying to enable fluxcd controllers",
        return_type="exception",
    )


@retry(
    retry_on_exception=lambda x: isinstance(x, exception.SysinvException),
    stop_max_attempt_number=3,
)
def create_fluxcd_namespace():
    """
    Creates the FluxCD namespace in the Kubernetes cluster if it does not already exist.
    This function attempts to create a namespace for FluxCD using kubectl. It checks the
    command output to determine if the namespace was created successfully or if it already
    exists, and logs the appropriate messages.

    Returns:
        bool: True if the namespace was created or already exists.

    Raises:
        SysinvException: If there is an unexpected error while trying to create the namespace.
    """

    def check_namespace_already_exists(output, returned_code=0):
        """
        Determines if the FluxCD namespace already exists based on
        command output and return code.
        """
        result = False
        if returned_code != 0 and "AlreadyExists" in output:
            LOG.info(f"{FLUXCD_NAMESPACE} namespace already exists.")
            result = True
        elif returned_code == 0:
            LOG.info(f"{FLUXCD_NAMESPACE} namespace created.")
            result = True
        else:
            LOG.error(f"Error trying to create {FLUXCD_NAMESPACE} namespace. Output: {output}")
            raise exception.SysinvException(
                f"Error trying to create {FLUXCD_NAMESPACE} namespace. Output: {output}"
            )

        return result

    cmd = f"kubectl create namespace {FLUXCD_NAMESPACE} --kubeconfig {KUBECONFIG} \
        --request-timeout={KUBECTL_REQUEST_TIMEOUT}"

    LOG.info(f"Creating {FLUXCD_NAMESPACE} namespace...")

    return execute_command(
        cmd=cmd,
        success_message=f"{FLUXCD_NAMESPACE} namespace created.",
        error_message=f"Error trying to create {FLUXCD_NAMESPACE} namespace",
        return_type="processed",
        output_processor_fn=check_namespace_already_exists
    )


@retry(
    retry_on_exception=lambda x: isinstance(x, exception.SysinvException),
    stop_max_attempt_number=3,
)
def helm_release_not_exists():
    """
    Checks whether a specific Helm release exists in a given namespace.

    This function constructs and executes a Helm command to check the status of a Helm release
    within a specified namespace using a provided kubeconfig. It processes the command output
    to determine if the release exists, does not exist, or if an error occurred during the check.

    Returns:
        bool: True if the Helm release does not exist, False if it exists.

    Raises:
        SysinvException: If an unexpected error occurs while checking the Helm release status.
    """

    def check_helm_status_output_was_not_found(output, returned_code=0):
        """Check if a Helm release is not found based on command output and return code."""

        result = False
        if returned_code != 0 and "release: not found" in output:
            LOG.info(
                f"Helm release {FLUXCD_HELM_RELEASE} not found in namespace {FLUXCD_NAMESPACE}.")
            result = True
        elif returned_code == 0:
            LOG.info(f"Helm release {FLUXCD_HELM_RELEASE} exists in namespace {FLUXCD_NAMESPACE}.")
            result = False
        else:
            LOG.error(
                f"Unexpected error while checking Helm release {FLUXCD_HELM_RELEASE} \
                    in namespace {FLUXCD_NAMESPACE}. Output: {output}"
                )
            raise exception.SysinvException(
                f"Error trying to check if Helm release {FLUXCD_HELM_RELEASE} \
                    exists in namespace {FLUXCD_NAMESPACE}."
            )
        return result

    cmd = f"helm status -n {FLUXCD_NAMESPACE} {FLUXCD_HELM_RELEASE} --kubeconfig {KUBECONFIG}"

    LOG.info(f"Checking if Helm release {FLUXCD_HELM_RELEASE} \
             exists in namespace {FLUXCD_NAMESPACE}...")

    return execute_command(
        cmd=cmd,
        success_message="Flux-helm release already exists.",
        error_message="Error trying to check if flux-helm release exists",
        return_type="processed",
        output_processor_fn=check_helm_status_output_was_not_found
    )


if __name__ == "__main__":
    sys.exit(main())
