#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for deploy_state and deploy_host_state logic.
"""

import unittest
from unittest import mock

from software.tests import base  # noqa: F401
from software.states import DEPLOY_HOST_STATES
from software.states import DEPLOY_STATES
from software.exceptions import InvalidOperation
from software.deploy_state import DeployState
from software.deploy_host_state import DeployHostState


class TestDeployStateTransform(unittest.TestCase):
    """Tests for DeployState.transform() — verifies actual state
    transitions update the DB and invoke callbacks.
    """

    def setUp(self):
        DeployState._instance = None
        DeployState._callbacks = []

    @mock.patch('software.deploy_state.get_instance')
    def test_transform_valid_updates_db(self, mock_db):
        """Valid transition calls update_deploy with target state."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'start'}
        ]
        ds = DeployState()
        ds.transform(DEPLOY_STATES.START_DONE)
        mock_db.return_value.update_deploy.assert_called_once_with(
            state=DEPLOY_STATES.START_DONE)

    @mock.patch('software.deploy_state.get_instance')
    def test_transform_invalid_raises(self, mock_db):
        """Invalid transition raises InvalidOperation."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'start'}
        ]
        ds = DeployState()
        with self.assertRaises(InvalidOperation) as ctx:
            ds.transform(DEPLOY_STATES.COMPLETED)
        self.assertIn("Can not transform", str(ctx.exception))

    @mock.patch('software.deploy_state.get_instance')
    def test_transform_invokes_callbacks(self, mock_db):
        """Transform calls registered callbacks with the new state."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'start'}
        ]
        callback_args = []
        DeployState.register_event_listener(
            callback_args.append)

        ds = DeployState()
        ds.transform(DEPLOY_STATES.START_DONE)
        self.assertEqual(callback_args, [DEPLOY_STATES.START_DONE])

    @mock.patch('software.deploy_state.get_instance')
    def test_transform_reentrant_does_not_raise(self, mock_db):
        """Reentrant state (START_DONE -> START_DONE) succeeds."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'start-done'}
        ]
        ds = DeployState()
        # Should not raise
        ds.transform(DEPLOY_STATES.START_DONE)
        mock_db.return_value.update_deploy.assert_called_once_with(
            state=DEPLOY_STATES.START_DONE)

    @mock.patch('software.deploy_state.get_instance')
    def test_transform_end_update_called_on_failure(self, mock_db):
        """end_update is called even when transition fails."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'start'}
        ]
        ds = DeployState()
        with self.assertRaises(InvalidOperation):
            ds.transform(DEPLOY_STATES.COMPLETED)
        mock_db.return_value.end_update.assert_called_once()


class TestDeployStateDeployHost(unittest.TestCase):
    """Tests for DeployState.deploy_host() branching logic."""

    def setUp(self):
        DeployState._instance = None
        DeployState._callbacks = []

    @mock.patch('software.deploy_state.get_instance')
    def test_deploy_host_from_start_done(self, mock_db):
        """From START_DONE, deploy_host transitions to HOST."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'start-done'}
        ]
        ds = DeployState()
        ds.deploy_host()
        mock_db.return_value.update_deploy.assert_called_once_with(
            state=DEPLOY_STATES.HOST)

    @mock.patch('software.deploy_state.get_instance')
    def test_deploy_host_from_rollback_done_goes_to_host_rollback(self, mock_db):
        """From ACTIVATE_ROLLBACK_DONE, deploy_host goes to HOST_ROLLBACK."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'activate-rollback-done'}
        ]
        ds = DeployState()
        ds.deploy_host()
        mock_db.return_value.update_deploy.assert_called_once_with(
            state=DEPLOY_STATES.HOST_ROLLBACK)

    @mock.patch('software.deploy_state.get_instance')
    def test_deploy_host_from_host_rollback_stays_rollback(self, mock_db):
        """From HOST_ROLLBACK, deploy_host stays HOST_ROLLBACK."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'host-rollback'}
        ]
        ds = DeployState()
        ds.deploy_host()
        mock_db.return_value.update_deploy.assert_called_once_with(
            state=DEPLOY_STATES.HOST_ROLLBACK)


class TestDeployStateDeployHostDone(unittest.TestCase):
    """Tests for DeployState.deploy_host_done() branching."""

    def setUp(self):
        DeployState._instance = None
        DeployState._callbacks = []

    @mock.patch('software.deploy_state.get_instance')
    def test_from_host_goes_to_host_done(self, mock_db):
        """From HOST state, deploy_host_done -> HOST_DONE."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'host'}
        ]
        ds = DeployState()
        ds.deploy_host_done()
        mock_db.return_value.update_deploy.assert_called_once_with(
            state=DEPLOY_STATES.HOST_DONE)

    @mock.patch('software.deploy_state.get_instance')
    def test_from_host_rollback_goes_to_host_rollback_done(self, mock_db):
        """From HOST_ROLLBACK, deploy_host_done -> HOST_ROLLBACK_DONE."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'host-rollback'}
        ]
        ds = DeployState()
        ds.deploy_host_done()
        mock_db.return_value.update_deploy.assert_called_once_with(
            state=DEPLOY_STATES.HOST_ROLLBACK_DONE)


class TestDeployStateDeployHostFailed(unittest.TestCase):
    """Tests for DeployState.deploy_host_failed() branching."""

    def setUp(self):
        DeployState._instance = None
        DeployState._callbacks = []

    @mock.patch('software.deploy_state.get_instance')
    def test_from_host_goes_to_host_failed(self, mock_db):
        """From HOST, deploy_host_failed -> HOST_FAILED."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'host'}
        ]
        ds = DeployState()
        ds.deploy_host_failed()
        mock_db.return_value.update_deploy.assert_called_once_with(
            state=DEPLOY_STATES.HOST_FAILED)

    @mock.patch('software.deploy_state.get_instance')
    def test_from_host_rollback_goes_to_host_rollback_failed(self, mock_db):
        """From HOST_ROLLBACK, deploy_host_failed -> HOST_ROLLBACK_FAILED."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'host-rollback'}
        ]
        ds = DeployState()
        ds.deploy_host_failed()
        mock_db.return_value.update_deploy.assert_called_once_with(
            state=DEPLOY_STATES.HOST_ROLLBACK_FAILED)

    @mock.patch('software.deploy_state.get_instance')
    def test_already_failed_does_not_transition(self, mock_db):
        """From HOST_FAILED, deploy_host_failed logs warning, no DB update."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'host-failed'}
        ]
        ds = DeployState()
        ds.deploy_host_failed()
        mock_db.return_value.update_deploy.assert_not_called()


class TestDeployStateAbort(unittest.TestCase):
    """Tests for DeployState.abort() branching."""

    def setUp(self):
        DeployState._instance = None
        DeployState._callbacks = []

    @mock.patch('software.deploy_state.get_instance')
    def test_abort_from_host_done_goes_to_host_rollback(self, mock_db):
        """Pre-activate abort goes to HOST_ROLLBACK."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'host-done'}
        ]
        ds = DeployState()
        ds.abort("feed_repo", "commit_abc")
        mock_db.return_value.update_deploy.assert_called_once_with(
            state=DEPLOY_STATES.HOST_ROLLBACK)
        mock_db.return_value.reverse_deploy.assert_called_once_with(
            "feed_repo", "commit_abc")

    @mock.patch('software.deploy_state.get_instance')
    def test_abort_from_activate_done_goes_to_rollback_pending(self, mock_db):
        """Post-activate abort goes to ACTIVATE_ROLLBACK_PENDING."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'activate-done'}
        ]
        ds = DeployState()
        ds.abort("feed_repo", "commit_abc")
        mock_db.return_value.update_deploy.assert_called_once_with(
            state=DEPLOY_STATES.ACTIVATE_ROLLBACK_PENDING)

    @mock.patch('software.deploy_state.get_instance')
    def test_abort_from_completed_goes_to_rollback_pending(self, mock_db):
        """Abort from COMPLETED goes to ACTIVATE_ROLLBACK_PENDING."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'completed'}
        ]
        ds = DeployState()
        ds.abort("feed_repo", "commit_abc")
        mock_db.return_value.update_deploy.assert_called_once_with(
            state=DEPLOY_STATES.ACTIVATE_ROLLBACK_PENDING)


class TestDeployHostStateTransform(unittest.TestCase):
    """Tests for DeployHostState.transform() — verifies DB update,
    InvalidOperation on bad transition, and callback invocation.
    """

    def setUp(self):
        DeployHostState._callbacks = []

    @mock.patch('software.deploy_host_state.get_instance')
    def test_transform_valid_updates_db(self, mock_db):
        """Valid transition updates the host state in DB."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'pending'
        }
        dhs = DeployHostState("controller-0")
        dhs.transform(DEPLOY_HOST_STATES.DEPLOYING)
        mock_db.return_value.update_deploy_host.assert_called_once_with(
            "controller-0", DEPLOY_HOST_STATES.DEPLOYING)

    @mock.patch('software.deploy_host_state.get_instance')
    def test_transform_invalid_raises(self, mock_db):
        """Invalid transition raises InvalidOperation."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'pending'
        }
        dhs = DeployHostState("controller-0")
        with self.assertRaises(InvalidOperation) as ctx:
            dhs.transform(DEPLOY_HOST_STATES.DEPLOYED)
        self.assertIn("can not transform", str(ctx.exception))

    @mock.patch('software.deploy_host_state.get_instance')
    def test_transform_invokes_callbacks(self, mock_db):
        """Transform calls registered callbacks with hostname and state."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'pending'
        }
        callback_args = []
        DeployHostState.register_event_listener(
            lambda h, s: callback_args.append((h, s)))

        dhs = DeployHostState("worker-0")
        dhs.transform(DEPLOY_HOST_STATES.DEPLOYING)
        self.assertEqual(callback_args,
                         [("worker-0", DEPLOY_HOST_STATES.DEPLOYING)])

    @mock.patch('software.deploy_host_state.get_instance')
    def test_transform_end_update_called_on_failure(self, mock_db):
        """end_update is always called, even on invalid transition."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'pending'
        }
        dhs = DeployHostState("controller-0")
        with self.assertRaises(InvalidOperation):
            dhs.transform(DEPLOY_HOST_STATES.DEPLOYED)
        mock_db.return_value.end_update.assert_called_once()


class TestDeployHostStateDeployStarted(unittest.TestCase):
    """Tests for DeployHostState.deploy_started() branching."""

    def setUp(self):
        DeployHostState._callbacks = []

    @mock.patch('software.deploy_host_state.get_instance')
    def test_from_pending_goes_to_deploying(self, mock_db):
        """PENDING -> DEPLOYING on deploy_started."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'pending'
        }
        dhs = DeployHostState("controller-0")
        dhs.deploy_started()
        mock_db.return_value.update_deploy_host.assert_called_once_with(
            "controller-0", DEPLOY_HOST_STATES.DEPLOYING)

    @mock.patch('software.deploy_host_state.get_instance')
    def test_from_failed_goes_to_deploying(self, mock_db):
        """FAILED -> DEPLOYING on deploy_started (retry)."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'failed'
        }
        dhs = DeployHostState("controller-0")
        dhs.deploy_started()
        mock_db.return_value.update_deploy_host.assert_called_once_with(
            "controller-0", DEPLOY_HOST_STATES.DEPLOYING)

    @mock.patch('software.deploy_host_state.get_instance')
    def test_from_rollback_pending_goes_to_rollback_deploying(self, mock_db):
        """ROLLBACK_PENDING -> ROLLBACK_DEPLOYING on deploy_started."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'rollback-pending'
        }
        dhs = DeployHostState("worker-0")
        dhs.deploy_started()
        mock_db.return_value.update_deploy_host.assert_called_once_with(
            "worker-0", DEPLOY_HOST_STATES.ROLLBACK_DEPLOYING)

    @mock.patch('software.deploy_host_state.get_instance')
    def test_from_rollback_failed_goes_to_rollback_deploying(self, mock_db):
        """ROLLBACK_FAILED -> ROLLBACK_DEPLOYING on deploy_started."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'rollback-failed'
        }
        dhs = DeployHostState("worker-0")
        dhs.deploy_started()
        mock_db.return_value.update_deploy_host.assert_called_once_with(
            "worker-0", DEPLOY_HOST_STATES.ROLLBACK_DEPLOYING)

    @mock.patch('software.deploy_host_state.get_instance')
    def test_from_deployed_logs_warning(self, mock_db):
        """DEPLOYED -> deploy_started logs warning, no transition."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'deployed'
        }
        dhs = DeployHostState("controller-0")
        dhs.deploy_started()
        mock_db.return_value.update_deploy_host.assert_not_called()


class TestDeployHostStateDeployed(unittest.TestCase):
    """Tests for DeployHostState.deployed() branching."""

    def setUp(self):
        DeployHostState._callbacks = []

    @mock.patch('software.deploy_host_state.get_instance')
    def test_from_deploying_goes_to_deployed(self, mock_db):
        """DEPLOYING -> DEPLOYED on success."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'deploying'
        }
        dhs = DeployHostState("controller-0")
        dhs.deployed()
        mock_db.return_value.update_deploy_host.assert_called_once_with(
            "controller-0", DEPLOY_HOST_STATES.DEPLOYED)

    @mock.patch('software.deploy_host_state.get_instance')
    def test_from_rollback_deploying_goes_to_rollback_deployed(self, mock_db):
        """ROLLBACK_DEPLOYING -> ROLLBACK_DEPLOYED on success."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'rollback-deploying'
        }
        dhs = DeployHostState("worker-0")
        dhs.deployed()
        mock_db.return_value.update_deploy_host.assert_called_once_with(
            "worker-0", DEPLOY_HOST_STATES.ROLLBACK_DEPLOYED)

    @mock.patch('software.deploy_host_state.get_instance')
    def test_from_pending_logs_warning(self, mock_db):
        """PENDING -> deployed() logs warning, no transition."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'pending'
        }
        dhs = DeployHostState("controller-0")
        dhs.deployed()
        mock_db.return_value.update_deploy_host.assert_not_called()


class TestDeployHostStateDeployFailed(unittest.TestCase):
    """Tests for DeployHostState.deploy_failed() branching."""

    def setUp(self):
        DeployHostState._callbacks = []

    @mock.patch('software.deploy_host_state.get_instance')
    def test_from_deploying_goes_to_failed(self, mock_db):
        """DEPLOYING -> FAILED on error."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'deploying'
        }
        dhs = DeployHostState("controller-0")
        dhs.deploy_failed()
        mock_db.return_value.update_deploy_host.assert_called_once_with(
            "controller-0", DEPLOY_HOST_STATES.FAILED)

    @mock.patch('software.deploy_host_state.get_instance')
    def test_from_rollback_deploying_goes_to_rollback_failed(self, mock_db):
        """ROLLBACK_DEPLOYING -> ROLLBACK_FAILED on error."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'rollback-deploying'
        }
        dhs = DeployHostState("worker-0")
        dhs.deploy_failed()
        mock_db.return_value.update_deploy_host.assert_called_once_with(
            "worker-0", DEPLOY_HOST_STATES.ROLLBACK_FAILED)

    @mock.patch('software.deploy_host_state.get_instance')
    def test_from_pending_logs_warning(self, mock_db):
        """PENDING -> deploy_failed() logs warning, no transition."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'pending'
        }
        dhs = DeployHostState("controller-0")
        dhs.deploy_failed()
        mock_db.return_value.update_deploy_host.assert_not_called()


class TestDeployHostStateAbort(unittest.TestCase):
    """Tests for DeployHostState.abort() branching."""

    def setUp(self):
        DeployHostState._callbacks = []

    @mock.patch('software.deploy_host_state.get_instance')
    def test_from_pending_goes_to_rollback_deployed(self, mock_db):
        """PENDING -> ROLLBACK_DEPLOYED on abort (skip deploying)."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'pending'
        }
        dhs = DeployHostState("worker-0")
        dhs.abort()
        mock_db.return_value.update_deploy_host.assert_called_once_with(
            "worker-0", DEPLOY_HOST_STATES.ROLLBACK_DEPLOYED)

    @mock.patch('software.deploy_host_state.get_instance')
    def test_from_deployed_goes_to_rollback_pending(self, mock_db):
        """DEPLOYED -> ROLLBACK_PENDING on abort."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'deployed'
        }
        dhs = DeployHostState("controller-0")
        dhs.abort()
        mock_db.return_value.update_deploy_host.assert_called_once_with(
            "controller-0", DEPLOY_HOST_STATES.ROLLBACK_PENDING)

    @mock.patch('software.deploy_host_state.get_instance')
    def test_from_failed_goes_to_rollback_pending(self, mock_db):
        """FAILED -> ROLLBACK_PENDING on abort."""
        mock_db.return_value.get_deploy_host_by_hostname.return_value = {
            'state': 'failed'
        }
        dhs = DeployHostState("controller-0")
        dhs.abort()
        mock_db.return_value.update_deploy_host.assert_called_once_with(
            "controller-0", DEPLOY_HOST_STATES.ROLLBACK_PENDING)


class TestDeployStateHostDeployUpdated(unittest.TestCase):
    """Tests for DeployState.host_deploy_updated() — aggregation logic
    that determines overall deploy state from individual host states.
    """

    def setUp(self):
        DeployState._instance = None
        DeployState._callbacks = []

    @mock.patch('software.deploy_state.get_instance')
    def test_all_deployed_transitions_to_host_done(self, mock_db):
        """When all hosts are deployed, transitions to HOST_DONE."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'host'}
        ]
        mock_db.return_value.get_deploy_host.return_value = [
            {'hostname': 'controller-0', 'state': 'deployed'},
            {'hostname': 'worker-0', 'state': 'deployed'},
        ]
        DeployState.host_deploy_updated("worker-0",
                                        DEPLOY_HOST_STATES.DEPLOYED)
        mock_db.return_value.update_deploy.assert_called_once_with(
            state=DEPLOY_STATES.HOST_DONE)

    @mock.patch('software.deploy_state.get_instance')
    def test_any_failed_transitions_to_host_failed(self, mock_db):
        """When any host has failed, transitions to HOST_FAILED."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'host'}
        ]
        mock_db.return_value.get_deploy_host.return_value = [
            {'hostname': 'controller-0', 'state': 'deployed'},
            {'hostname': 'worker-0', 'state': 'failed'},
        ]
        DeployState.host_deploy_updated("worker-0",
                                        DEPLOY_HOST_STATES.FAILED)
        mock_db.return_value.update_deploy.assert_called_once_with(
            state=DEPLOY_STATES.HOST_FAILED)

    @mock.patch('software.deploy_state.get_instance')
    def test_some_still_deploying_stays_in_host(self, mock_db):
        """When some hosts still deploying, stays in HOST."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'host'}
        ]
        mock_db.return_value.get_deploy_host.return_value = [
            {'hostname': 'controller-0', 'state': 'deployed'},
            {'hostname': 'worker-0', 'state': 'deploying'},
        ]
        DeployState.host_deploy_updated("controller-0",
                                        DEPLOY_HOST_STATES.DEPLOYED)
        mock_db.return_value.update_deploy.assert_called_once_with(
            state=DEPLOY_STATES.HOST)

    @mock.patch('software.deploy_state.get_instance')
    def test_all_rollback_deployed_transitions_to_host_rollback_done(self, mock_db):
        """All hosts rollback-deployed -> HOST_ROLLBACK_DONE."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'host-rollback'}
        ]
        mock_db.return_value.get_deploy_host.return_value = [
            {'hostname': 'controller-0', 'state': 'rollback-deployed'},
            {'hostname': 'worker-0', 'state': 'rollback-deployed'},
        ]
        DeployState.host_deploy_updated("worker-0",
                                        DEPLOY_HOST_STATES.ROLLBACK_DEPLOYED)
        mock_db.return_value.update_deploy.assert_called_once_with(
            state=DEPLOY_STATES.HOST_ROLLBACK_DONE)

    @mock.patch('software.deploy_state.get_instance')
    def test_not_in_host_state_does_nothing(self, mock_db):
        """If deploy is not in HOST/HOST_FAILED state, no transition."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'start-done'}
        ]
        mock_db.return_value.get_deploy_host.return_value = [
            {'hostname': 'controller-0', 'state': 'deployed'},
        ]
        DeployState.host_deploy_updated("controller-0",
                                        DEPLOY_HOST_STATES.DEPLOYED)
        mock_db.return_value.update_deploy.assert_not_called()

    @mock.patch('software.deploy_state.get_instance')
    def test_failed_takes_priority_over_pending(self, mock_db):
        """Failed state takes priority — even if some are still pending."""
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': 'host'}
        ]
        mock_db.return_value.get_deploy_host.return_value = [
            {'hostname': 'controller-0', 'state': 'pending'},
            {'hostname': 'worker-0', 'state': 'failed'},
        ]
        DeployState.host_deploy_updated("worker-0",
                                        DEPLOY_HOST_STATES.FAILED)
        mock_db.return_value.update_deploy.assert_called_once_with(
            state=DEPLOY_STATES.HOST_FAILED)
