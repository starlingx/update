#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from enum import Enum
from unittest import mock
from unittest import TestCase

from software.exceptions import DeployAlreadyExist
from software.exceptions import DeployDoNotExist
from software.exceptions import StateValidationFailure
from software.exceptions import SystemDeployNotExist
from software.software_entities import DeployHandler
from software.software_entities import DeployHostHandler
from software.software_entities import SystemDeployHandler
from software.states import DEPLOY_HOST_STATES
from software.states import DEPLOY_STATES
from software.states import SYSTEM_DEPLOY_STATES
from software.tests import base as test_base  # noqa: F401
from software.utils import check_instances
from software.utils import check_state
from software.utils import validate_versions

MOCK_GET_DATA = "software.software_entities.get_software_filesystem_data"
MOCK_SAVE = "software.software_entities.save_to_json_file"


class TestCheckInstances(TestCase):

    def test_invalid_type(self):
        self.assertRaises(ValueError, check_instances, [1], str)


class TestCheckState(TestCase):
    def setUp(self):
        self.states = Enum('States', 'active deploying')

    def test_invalid_state(self):
        self.assertRaises(
            StateValidationFailure,
            check_state,
            'bad',
            self.states)


class TestValidateVersions(TestCase):

    def test_invalid_version(self):
        self.assertRaises(ValueError, validate_versions, ["abc"])


class TestDeployHandler(TestCase):
    def setUp(self):
        self.handler = DeployHandler()

    @mock.patch(MOCK_SAVE)
    @mock.patch(MOCK_GET_DATA, return_value={"deploy": []})
    def test_create(self, _mock_get, mock_save):
        self.handler.create("1.0", "2.0", "/feed", "abc123", True, None)
        mock_save.assert_called_once()
        data = mock_save.call_args[0][1]
        self.assertEqual(len(data["deploy"]), 1)
        self.assertEqual(data["deploy"][0]["from_release"], "1.0")
        self.assertEqual(data["deploy"][0]["state"], DEPLOY_STATES.START.value)

    @mock.patch(MOCK_GET_DATA,
                return_value={"deploy": [{"from_release": "1.0",
                              "to_release": "2.0",
                                          "state": "start"}]})
    def test_create_already_exists(self, _mock_get):
        self.assertRaises(
            DeployAlreadyExist,
            self.handler.create,
            "1.0",
            "2.0",
            "/feed",
            "abc",
            True,
            None)

    @mock.patch(MOCK_GET_DATA, return_value={
        "deploy": [{"from_release": "1.0", "to_release": "2.0"}]
    })
    def test_query(self, _mock_get):
        result = self.handler.query("1.0", "2.0")
        self.assertEqual(result["from_release"], "1.0")

    @mock.patch(MOCK_GET_DATA, return_value={"deploy": []})
    def test_query_not_found(self, _mock_get):
        result = self.handler.query("1.0", "2.0")
        self.assertEqual(result, [])

    @mock.patch(MOCK_SAVE)
    @mock.patch(MOCK_GET_DATA,
                return_value={"deploy": [{"from_release": "1.0",
                              "to_release": "2.0",
                                          "state": "start"}]})
    def test_update_state(self, _mock_get, mock_save):
        self.handler.update(new_state=DEPLOY_STATES.HOST)
        mock_save.assert_called_once()
        data = mock_save.call_args[0][1]
        self.assertEqual(data["deploy"][0]["state"], DEPLOY_STATES.HOST.value)

    @mock.patch(MOCK_GET_DATA, return_value={"deploy": []})
    def test_update_no_deploy(self, _mock_get):
        self.assertRaises(DeployDoNotExist,
                          self.handler.update, new_state=DEPLOY_STATES.HOST)

    @mock.patch(MOCK_SAVE)
    @mock.patch(MOCK_GET_DATA,
                return_value={"deploy": [{"from_release": "1.0",
                              "to_release": "2.0",
                                          "state": "start"}]})
    def test_delete(self, _mock_get, mock_save):
        self.handler.delete()
        mock_save.assert_called_once()
        data = mock_save.call_args[0][1]
        self.assertEqual(data["deploy"], [])

    @mock.patch(MOCK_GET_DATA, return_value={"deploy": []})
    def test_delete_no_deploy(self, _mock_get):
        self.assertRaises(DeployDoNotExist, self.handler.delete)


class TestDeployHostHandler(TestCase):
    def setUp(self):
        self.handler = DeployHostHandler()

    @mock.patch(MOCK_SAVE)
    @mock.patch(MOCK_GET_DATA, return_value={"deploy_host": []})
    def test_create(self, _mock_get, mock_save):
        self.handler.create("controller-0")
        mock_save.assert_called_once()
        data = mock_save.call_args[0][1]
        self.assertEqual(data["deploy_host"][0]["hostname"], "controller-0")
        self.assertEqual(
            data["deploy_host"][0]["state"],
            DEPLOY_HOST_STATES.PENDING.value)

    @mock.patch(MOCK_GET_DATA, return_value={
        "deploy_host": [{"hostname": "controller-0", "state": "pending"}]
    })
    def test_create_already_exists(self, _mock_get):
        self.assertRaises(DeployAlreadyExist,
                          self.handler.create, "controller-0")

    @mock.patch(MOCK_GET_DATA, return_value={
        "deploy_host": [{"hostname": "controller-0", "state": "pending"}]
    })
    def test_query(self, _mock_get):
        result = self.handler.query("controller-0")
        self.assertEqual(result["hostname"], "controller-0")

    @mock.patch(MOCK_GET_DATA, return_value={"deploy_host": []})
    def test_query_not_found(self, _mock_get):
        result = self.handler.query("controller-0")
        self.assertIsNone(result)

    @mock.patch(MOCK_SAVE)
    @mock.patch(MOCK_GET_DATA, return_value={
        "deploy_host": [{"hostname": "controller-0", "state": "pending"}]
    })
    def test_update(self, _mock_get, mock_save):
        result = self.handler.update(
            "controller-0", DEPLOY_HOST_STATES.DEPLOYED)
        self.assertEqual(result["state"], DEPLOY_HOST_STATES.DEPLOYED.value)
        mock_save.assert_called_once()

    @mock.patch(MOCK_GET_DATA, return_value={"deploy_host": []})
    def test_update_not_found(self, _mock_get):
        self.assertRaises(Exception,  # noqa: H202
                          self.handler.update,
                          "controller-0",
                          DEPLOY_HOST_STATES.DEPLOYED)

    @mock.patch(MOCK_GET_DATA, return_value={"deploy_host": []})
    def test_delete_not_found(self, _mock_get):
        self.assertRaises(DeployDoNotExist,
                          self.handler.delete, "controller-0")


class TestSystemDeployHandler(TestCase):
    def setUp(self):
        self.handler = SystemDeployHandler()

    @mock.patch(MOCK_SAVE)
    @mock.patch(MOCK_GET_DATA, return_value={})
    def test_create(self, _mock_get, mock_save):
        self.handler.create("deploy-1", "2.0", "1.25",
                            SYSTEM_DEPLOY_STATES.START)
        mock_save.assert_called_once()
        data = mock_save.call_args[0][1]
        self.assertEqual(data["system_deploy"]["id"], "deploy-1")
        self.assertEqual(
            data["system_deploy"]["state"],
            SYSTEM_DEPLOY_STATES.START.value)

    @mock.patch(MOCK_GET_DATA, return_value={
        "system_deploy": {"id": "deploy-1", "to_release": "2.0",
                          "to_k8s_version": "1.25", "state": "start"}
    })
    def test_query(self, _mock_get):
        result = self.handler.query()
        self.assertEqual(result["id"], "deploy-1")

    @mock.patch(MOCK_GET_DATA, return_value={})
    def test_query_empty(self, _mock_get):
        result = self.handler.query()
        self.assertEqual(result, [])

    @mock.patch(MOCK_SAVE)
    @mock.patch(MOCK_GET_DATA, return_value={
        "system_deploy": {"id": "deploy-1", "to_release": "2.0",
                          "to_k8s_version": "1.25", "state": "start"}
    })
    def test_update(self, _mock_get, mock_save):
        result = self.handler.update(SYSTEM_DEPLOY_STATES.START_DONE)
        self.assertEqual(
            result["state"],
            SYSTEM_DEPLOY_STATES.START_DONE.value)
        mock_save.assert_called_once()

    @mock.patch(MOCK_GET_DATA, return_value={})
    def test_update_no_deploy(self, _mock_get):
        self.assertRaises(SystemDeployNotExist,
                          self.handler.update, SYSTEM_DEPLOY_STATES.START_DONE)
