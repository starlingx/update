#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for PatchController methods with mocked __init__."""

import threading
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

from software.tests import base as test_base  # noqa: F401
from software.exceptions import ReleaseInvalidRequest
from software.exceptions import SoftwareServiceError
from software.software_controller import PatchController
from software import states


INIT_PATCH = mock.patch(
    'software.software_controller.PatchController.__init__',
    return_value=None
)


class TestSanitizeExtraOptions(unittest.TestCase):
    """Tests for _sanitize_extra_options."""

    @INIT_PATCH
    def test_valid_value(self, _mock_init):
        controller = PatchController()
        result = controller._sanitize_extra_options("hello-world_1")
        self.assertEqual(result, "hello-world_1")

    @INIT_PATCH
    def test_value_with_spaces(self, _mock_init):
        controller = PatchController()
        result = controller._sanitize_extra_options("hello world")
        self.assertEqual(result, "hello world")

    @INIT_PATCH
    def test_invalid_value_special_chars(self, _mock_init):
        controller = PatchController()
        self.assertRaises(
            SoftwareServiceError,
            controller._sanitize_extra_options, "bad!value"
        )

    @INIT_PATCH
    def test_invalid_value_semicolon(self, _mock_init):
        controller = PatchController()
        self.assertRaises(
            SoftwareServiceError,
            controller._sanitize_extra_options, "val;ue"
        )


class TestParseAndSanitizeExtraOptions(unittest.TestCase):
    """Tests for _parse_and_sanitize_extra_options."""

    @INIT_PATCH
    def test_valid_key_value(self, _mock_init):
        controller = PatchController()
        result = controller._parse_and_sanitize_extra_options(["key=value"])
        self.assertEqual(result, {"key": "value"})

    @INIT_PATCH
    def test_multiple_pairs(self, _mock_init):
        controller = PatchController()
        result = controller._parse_and_sanitize_extra_options(
            ["key1=val1", "key2=val2"]
        )
        self.assertEqual(result, {"key1": "val1", "key2": "val2"})

    @INIT_PATCH
    def test_strips_whitespace(self, _mock_init):
        controller = PatchController()
        result = controller._parse_and_sanitize_extra_options(
            [" key = value "]
        )
        self.assertEqual(result, {"key": "value"})

    @INIT_PATCH
    def test_invalid_format_no_equals(self, _mock_init):
        controller = PatchController()
        self.assertRaises(
            SoftwareServiceError,
            controller._parse_and_sanitize_extra_options, ["noequals"]
        )

    @INIT_PATCH
    def test_invalid_format_multiple_equals(self, _mock_init):
        controller = PatchController()
        self.assertRaises(
            SoftwareServiceError,
            controller._parse_and_sanitize_extra_options, ["a=b=c"]
        )

    @INIT_PATCH
    def test_reserved_word_rejected(self, _mock_init):
        controller = PatchController()
        self.assertRaises(
            SoftwareServiceError,
            controller._parse_and_sanitize_extra_options,
            ["OS_AUTH_URL=http"]
        )

    @INIT_PATCH
    def test_empty_list(self, _mock_init):
        controller = PatchController()
        result = controller._parse_and_sanitize_extra_options([])
        self.assertEqual(result, {})


class TestAddTextTagToXml(unittest.TestCase):
    """Tests for add_text_tag_to_xml."""

    @INIT_PATCH
    def test_creates_new_element(self, _mock_init):
        controller = PatchController()
        parent = ET.Element("root")
        elem = controller.add_text_tag_to_xml(parent, "child", "hello")
        self.assertEqual(elem.text, "hello")
        self.assertEqual(elem.tag, "child")
        self.assertIsNotNone(parent.find("child"))

    @INIT_PATCH
    def test_updates_existing_element(self, _mock_init):
        controller = PatchController()
        parent = ET.Element("root")
        ET.SubElement(parent, "child").text = "old"
        elem = controller.add_text_tag_to_xml(parent, "child", "new")
        self.assertEqual(elem.text, "new")
        self.assertEqual(len(parent.findall("child")), 1)


class TestIsDeploymentListRebootRequired(unittest.TestCase):
    """Tests for is_deployment_list_reboot_required."""

    @INIT_PATCH
    @mock.patch(
        'software.software_controller.get_SWReleaseCollection'
    )
    def test_reboot_required(self, mock_swrc, _mock_init):
        controller = PatchController()
        mock_release = mock.MagicMock()
        mock_release.reboot_required = True
        mock_collection = mock.MagicMock()
        mock_collection.get_release_by_id.return_value = mock_release
        mock_swrc.return_value = mock_collection
        self.assertTrue(
            controller.is_deployment_list_reboot_required(["r1"])
        )

    @INIT_PATCH
    @mock.patch(
        'software.software_controller.get_SWReleaseCollection'
    )
    def test_no_reboot_required(self, mock_swrc, _mock_init):
        controller = PatchController()
        mock_release = mock.MagicMock()
        mock_release.reboot_required = False
        mock_collection = mock.MagicMock()
        mock_collection.get_release_by_id.return_value = mock_release
        mock_swrc.return_value = mock_collection
        self.assertFalse(
            controller.is_deployment_list_reboot_required(["r1"])
        )

    @INIT_PATCH
    @mock.patch(
        'software.software_controller.get_SWReleaseCollection'
    )
    def test_empty_list(self, mock_swrc, _mock_init):
        controller = PatchController()
        mock_swrc.return_value = mock.MagicMock()
        self.assertFalse(
            controller.is_deployment_list_reboot_required([])
        )


class TestCheckReleasesState(unittest.TestCase):
    """Tests for check_releases_state."""

    @INIT_PATCH
    @mock.patch(
        'software.software_controller.get_SWReleaseCollection'
    )
    def test_all_match(self, mock_swrc, _mock_init):
        controller = PatchController()
        mock_release = mock.MagicMock()
        mock_release.state = states.AVAILABLE
        mock_collection = mock.MagicMock()
        mock_collection.get_release_by_id.return_value = mock_release
        mock_swrc.return_value = mock_collection
        self.assertTrue(
            controller.check_releases_state(["r1", "r2"], states.AVAILABLE)
        )

    @INIT_PATCH
    @mock.patch(
        'software.software_controller.get_SWReleaseCollection'
    )
    def test_mismatch(self, mock_swrc, _mock_init):
        controller = PatchController()
        mock_release = mock.MagicMock()
        mock_release.state = states.DEPLOYED
        mock_collection = mock.MagicMock()
        mock_collection.get_release_by_id.return_value = mock_release
        mock_swrc.return_value = mock_collection
        self.assertFalse(
            controller.check_releases_state(["r1"], states.AVAILABLE)
        )

    @INIT_PATCH
    @mock.patch(
        'software.software_controller.get_SWReleaseCollection'
    )
    def test_release_not_found(self, mock_swrc, _mock_init):
        controller = PatchController()
        mock_collection = mock.MagicMock()
        mock_collection.get_release_by_id.return_value = None
        mock_swrc.return_value = mock_collection
        self.assertFalse(
            controller.check_releases_state(["r1"], states.AVAILABLE)
        )


class TestIsAvailableDeployedCommitted(unittest.TestCase):
    """Tests for is_available, is_deployed, is_committed wrappers."""

    @INIT_PATCH
    @mock.patch(
        'software.software_controller.get_SWReleaseCollection'
    )
    def test_is_available(self, mock_swrc, _mock_init):
        controller = PatchController()
        mock_release = mock.MagicMock()
        mock_release.state = states.AVAILABLE
        mock_collection = mock.MagicMock()
        mock_collection.get_release_by_id.return_value = mock_release
        mock_swrc.return_value = mock_collection
        self.assertTrue(controller.is_available(["r1"]))

    @INIT_PATCH
    @mock.patch(
        'software.software_controller.get_SWReleaseCollection'
    )
    def test_is_deployed(self, mock_swrc, _mock_init):
        controller = PatchController()
        mock_release = mock.MagicMock()
        mock_release.state = states.DEPLOYED
        mock_collection = mock.MagicMock()
        mock_collection.get_release_by_id.return_value = mock_release
        mock_swrc.return_value = mock_collection
        self.assertTrue(controller.is_deployed(["r1"]))

    @INIT_PATCH
    @mock.patch(
        'software.software_controller.get_SWReleaseCollection'
    )
    def test_is_committed(self, mock_swrc, _mock_init):
        controller = PatchController()
        mock_release = mock.MagicMock()
        mock_release.state = states.COMMITTED
        mock_collection = mock.MagicMock()
        mock_collection.get_release_by_id.return_value = mock_release
        mock_swrc.return_value = mock_collection
        self.assertTrue(controller.is_committed(["r1"]))


class TestQueryAppDependencies(unittest.TestCase):
    """Tests for query_app_dependencies."""

    @INIT_PATCH
    def test_returns_copy(self, _mock_init):
        controller = PatchController()
        controller.app_dependencies = {"app1": ["p1"]}
        result = controller.query_app_dependencies()
        self.assertEqual(result, {"app1": ["p1"]})
        self.assertIsNot(result, controller.app_dependencies)

    @INIT_PATCH
    def test_empty(self, _mock_init):
        controller = PatchController()
        controller.app_dependencies = {}
        self.assertEqual(controller.query_app_dependencies(), {})


class TestReportAppDependencies(unittest.TestCase):
    """Tests for report_app_dependencies."""

    @INIT_PATCH
    @mock.patch('tempfile.mkstemp', return_value=(99, '/tmp/fake'))
    @mock.patch('os.write')
    @mock.patch('os.close')
    @mock.patch('os.rename')
    def test_add_dependency(self, _rename, _close, _write, _mkstemp,
                            _mock_init):
        controller = PatchController()
        controller.app_dependencies = {}
        result = controller.report_app_dependencies(
            ["p1", "p2"], app="myapp"
        )
        self.assertTrue(result)
        self.assertEqual(
            controller.app_dependencies, {"myapp": ["p1", "p2"]}
        )

    @INIT_PATCH
    @mock.patch('tempfile.mkstemp', return_value=(99, '/tmp/fake'))
    @mock.patch('os.write')
    @mock.patch('os.close')
    @mock.patch('os.rename')
    def test_remove_dependency(self, _rename, _close, _write, _mkstemp,
                               _mock_init):
        controller = PatchController()
        controller.app_dependencies = {"myapp": ["p1"]}
        result = controller.report_app_dependencies([], app="myapp")
        self.assertTrue(result)
        self.assertNotIn("myapp", controller.app_dependencies)

    @INIT_PATCH
    def test_missing_app_kwarg(self, _mock_init):
        controller = PatchController()
        controller.app_dependencies = {}
        self.assertRaises(
            ReleaseInvalidRequest,
            controller.report_app_dependencies, ["p1"]
        )


class TestGetPrecheckResultFilePath(unittest.TestCase):
    """Tests for _get_precheck_result_file_path."""

    @INIT_PATCH
    def test_path_format(self, _mock_init):
        controller = PatchController()
        result = controller._get_precheck_result_file_path("24.09")
        self.assertEqual(
            result, "/opt/software/releases/24.09/precheck-result.json"
        )


class TestSavePrecheckResult(unittest.TestCase):
    """Tests for _save_precheck_result."""

    @INIT_PATCH
    @mock.patch('builtins.open', mock.mock_open())
    @mock.patch('json.dump')
    def test_saves_result(self, mock_dump, _mock_init):
        controller = PatchController()
        controller._save_precheck_result("24.09", True)
        call_args = mock_dump.call_args[0][0]
        self.assertTrue(call_args["healthy"])
        self.assertIn("timestamp", call_args)


class TestShouldRunPrecheckPriorDeployStart(unittest.TestCase):
    """Tests for _should_run_precheck_prior_deploy_start."""

    @INIT_PATCH
    def test_pre_bootstrap_returns_false(self, _mock_init):
        controller = PatchController()
        controller.pre_bootstrap = True
        self.assertFalse(
            controller._should_run_precheck_prior_deploy_start(
                "24.09", False, False, None
            )
        )

    @INIT_PATCH
    def test_patch_and_force_returns_false(self, _mock_init):
        controller = PatchController()
        controller.pre_bootstrap = False
        self.assertFalse(
            controller._should_run_precheck_prior_deploy_start(
                "24.09", True, True, None
            )
        )

    @INIT_PATCH
    @mock.patch('os.path.isfile', return_value=False)
    def test_no_file_returns_true(self, _isfile, _mock_init):
        controller = PatchController()
        controller.pre_bootstrap = False
        self.assertTrue(
            controller._should_run_precheck_prior_deploy_start(
                "24.09", False, False, None
            )
        )

    @INIT_PATCH
    @mock.patch('os.path.isfile', return_value=True)
    @mock.patch('builtins.open', mock.mock_open(
        read_data='{"healthy": true, "timestamp": 9999999999}'
    ))
    @mock.patch('time.time', return_value=9999999999.0)
    def test_healthy_recent_returns_false(self, _time, _isfile, _mock_init):
        controller = PatchController()
        controller.pre_bootstrap = False
        self.assertFalse(
            controller._should_run_precheck_prior_deploy_start(
                "24.09", False, False, None
            )
        )

    @INIT_PATCH
    @mock.patch('os.path.isfile', return_value=True)
    @mock.patch('builtins.open', mock.mock_open(
        read_data='{"healthy": true, "timestamp": 0}'
    ))
    @mock.patch('time.time', return_value=9999999999.0)
    def test_expired_returns_true(self, _time, _isfile, _mock_init):
        controller = PatchController()
        controller.pre_bootstrap = False
        self.assertTrue(
            controller._should_run_precheck_prior_deploy_start(
                "24.09", False, False, None
            )
        )

    @INIT_PATCH
    @mock.patch('os.path.isfile', return_value=True)
    def test_kwargs_present_returns_true(self, _isfile, _mock_init):
        controller = PatchController()
        controller.pre_bootstrap = False
        self.assertTrue(
            controller._should_run_precheck_prior_deploy_start(
                "24.09", False, False, None, extra="val"
            )
        )


class TestDeployHostList(unittest.TestCase):
    """Tests for deploy_host_list."""

    @INIT_PATCH
    def test_returns_host_list(self, _mock_init):
        controller = PatchController()
        controller.db_api_instance = mock.MagicMock()
        controller.db_api_instance.get_deploy_host.return_value = [
            {"hostname": "controller-0", "state": "deployed"}
        ]
        controller.db_api_instance.get_deploy_all.return_value = [
            {"from_release": "24.09.0", "to_release": "24.09.1",
             "reboot_required": True}
        ]
        result = controller.deploy_host_list()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["hostname"], "controller-0")
        self.assertEqual(result[0]["software_release"], "24.09.0")
        self.assertEqual(result[0]["target_release"], "24.09.1")

    @INIT_PATCH
    def test_no_deploy(self, _mock_init):
        controller = PatchController()
        controller.db_api_instance = mock.MagicMock()
        controller.db_api_instance.get_deploy_host.return_value = []
        controller.db_api_instance.get_deploy_all.return_value = []
        result = controller.deploy_host_list()
        self.assertEqual(result, [])

    @INIT_PATCH
    def test_host_with_none_state(self, _mock_init):
        controller = PatchController()
        controller.db_api_instance = mock.MagicMock()
        controller.db_api_instance.get_deploy_host.return_value = [
            {"hostname": "worker-0", "state": None}
        ]
        controller.db_api_instance.get_deploy_all.return_value = [
            {"from_release": "24.09.0", "to_release": "24.09.1",
             "reboot_required": True}
        ]
        result = controller.deploy_host_list()
        self.assertIsNone(result[0]["target_release"])
        self.assertIsNone(result[0]["reboot_required"])


class TestGetSoftwareUpgrade(unittest.TestCase):
    """Tests for _get_software_upgrade and get_software_upgrade."""

    @INIT_PATCH
    def test_returns_upgrade_info(self, _mock_init):
        controller = PatchController()
        controller.db_api_instance = mock.MagicMock()
        controller.db_api_instance.get_deploy_all.return_value = [
            {"from_release": "24.09.0", "to_release": "24.09.1",
             "state": "start-done"}
        ]
        result = controller._get_software_upgrade()
        self.assertIsNotNone(result)
        self.assertEqual(result["from_release"], "24.09")
        self.assertEqual(result["to_release"], "24.09")
        self.assertEqual(result["state"], "start-done")

    @INIT_PATCH
    def test_no_deploy_returns_none(self, _mock_init):
        controller = PatchController()
        controller.db_api_instance = mock.MagicMock()
        controller.db_api_instance.get_deploy_all.return_value = []
        self.assertIsNone(controller._get_software_upgrade())

    @INIT_PATCH
    def test_get_software_upgrade_wrapper(self, _mock_init):
        controller = PatchController()
        controller.db_api_instance = mock.MagicMock()
        controller.db_api_instance.get_deploy_all.return_value = [
            {"from_release": "24.09.0", "to_release": "25.03.0",
             "state": "activated"}
        ]
        result = controller.get_software_upgrade()
        self.assertEqual(result["from_release"], "24.09")
        self.assertEqual(result["to_release"], "25.03")


class TestGetAllSoftwareHostUpgrade(unittest.TestCase):
    """Tests for get_all_software_host_upgrade."""

    @INIT_PATCH
    def test_returns_host_upgrades(self, _mock_init):
        controller = PatchController()
        controller.db_api_instance = mock.MagicMock()
        controller.db_api_instance.get_deploy_all.return_value = [
            {"from_release": "24.09.0", "to_release": "25.03.0",
             "state": "start-done"}
        ]
        controller.db_api_instance.get_deploy_host.return_value = [
            {"hostname": "controller-0", "state": states.DEPLOYED},
            {"hostname": "worker-0", "state": "pending"}
        ]
        result = controller.get_all_software_host_upgrade()
        self.assertEqual(len(result), 2)
        self.assertEqual(
            result[0]["current_sw_version"], "25.03"
        )
        self.assertEqual(
            result[1]["current_sw_version"], "24.09"
        )

    @INIT_PATCH
    def test_no_deploy_returns_none(self, _mock_init):
        controller = PatchController()
        controller.db_api_instance = mock.MagicMock()
        controller.db_api_instance.get_deploy_all.return_value = []
        self.assertIsNone(controller.get_all_software_host_upgrade())


class TestGetOneSoftwareHostUpgrade(unittest.TestCase):
    """Tests for get_one_software_host_upgrade."""

    @INIT_PATCH
    def test_found(self, _mock_init):
        controller = PatchController()
        controller.db_api_instance = mock.MagicMock()
        controller.db_api_instance.get_deploy_all.return_value = [
            {"from_release": "24.09.0", "to_release": "25.03.0",
             "state": "start-done"}
        ]
        controller.db_api_instance.get_deploy_host.return_value = [
            {"hostname": "controller-0", "state": states.DEPLOYED}
        ]
        result = controller.get_one_software_host_upgrade("controller-0")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["hostname"], "controller-0")

    @INIT_PATCH
    def test_not_found(self, _mock_init):
        controller = PatchController()
        controller.db_api_instance = mock.MagicMock()
        controller.db_api_instance.get_deploy_all.return_value = [
            {"from_release": "24.09.0", "to_release": "25.03.0",
             "state": "start-done"}
        ]
        controller.db_api_instance.get_deploy_host.return_value = [
            {"hostname": "controller-0", "state": states.DEPLOYED}
        ]
        self.assertIsNone(
            controller.get_one_software_host_upgrade("worker-0")
        )

    @INIT_PATCH
    def test_no_deploy(self, _mock_init):
        controller = PatchController()
        controller.db_api_instance = mock.MagicMock()
        controller.db_api_instance.get_deploy_all.return_value = []
        self.assertIsNone(
            controller.get_one_software_host_upgrade("controller-0")
        )


class TestIsHostActiveController(unittest.TestCase):
    """Tests for is_host_active_controller."""

    @INIT_PATCH
    @mock.patch('os.path.exists', return_value=False)
    def test_no_initial_config(self, _exists, _mock_init):
        controller = PatchController()
        self.assertFalse(controller.is_host_active_controller())

    @INIT_PATCH
    @mock.patch('os.path.exists', return_value=True)
    @mock.patch('software.software_controller.utils.gethostbyname',
                return_value="10.10.10.2")
    @mock.patch('software.software_controller.utils.get_management_family',
                return_value="AF_INET")
    @mock.patch('software.software_controller.cfg.get_mgmt_iface',
                return_value="mgmt0")
    @mock.patch('software.software_controller.utils.get_iface_ip',
                return_value=["10.10.10.2"])
    def test_is_active(self, _iface_ip, _mgmt_iface, _family,
                       _gethostbyname, _exists, _mock_init):
        controller = PatchController()
        self.assertTrue(controller.is_host_active_controller())

    @INIT_PATCH
    @mock.patch('os.path.exists', return_value=True)
    @mock.patch('software.software_controller.utils.gethostbyname',
                return_value="10.10.10.2")
    @mock.patch('software.software_controller.utils.get_management_family',
                return_value="AF_INET")
    @mock.patch('software.software_controller.cfg.get_mgmt_iface',
                return_value="mgmt0")
    @mock.patch('software.software_controller.utils.get_iface_ip',
                return_value=["10.10.10.3"])
    def test_not_active(self, _iface_ip, _mgmt_iface, _family,
                        _gethostbyname, _exists, _mock_init):
        controller = PatchController()
        self.assertFalse(controller.is_host_active_controller())

    @INIT_PATCH
    @mock.patch('os.path.exists', return_value=True)
    @mock.patch('software.software_controller.utils.gethostbyname',
                return_value=None)
    def test_no_floating_ip(self, _gethostbyname, _exists, _mock_init):
        controller = PatchController()
        self.assertFalse(controller.is_host_active_controller())


class TestReleaseBasicChecks(unittest.TestCase):
    """Tests for _release_basic_checks."""

    @INIT_PATCH
    @mock.patch(
        'software.software_controller.get_SWReleaseCollection'
    )
    def test_release_exists(self, mock_swrc, _mock_init):
        controller = PatchController()
        mock_release = mock.MagicMock()
        mock_collection = mock.MagicMock()
        mock_collection.get_release_by_id.return_value = mock_release
        mock_swrc.return_value = mock_collection
        result = controller._release_basic_checks("release-1")
        self.assertEqual(result, mock_release)

    @INIT_PATCH
    @mock.patch(
        'software.software_controller.get_SWReleaseCollection'
    )
    def test_release_not_found(self, mock_swrc, _mock_init):
        controller = PatchController()
        mock_collection = mock.MagicMock()
        mock_collection.get_release_by_id.return_value = None
        mock_swrc.return_value = mock_collection
        self.assertRaises(
            SoftwareServiceError,
            controller._release_basic_checks, "missing-release"
        )


class TestInSyncControllerApi(unittest.TestCase):
    """Tests for in_sync_controller_api."""

    @INIT_PATCH
    @mock.patch(
        'software.software_controller.is_deploy_state_in_sync',
        return_value=True
    )
    def test_in_sync(self, _mock_sync, _mock_init):
        controller = PatchController()
        result = controller.in_sync_controller_api()
        self.assertEqual(result, {"in_sync": True})

    @INIT_PATCH
    @mock.patch(
        'software.software_controller.is_deploy_state_in_sync',
        return_value=False
    )
    def test_not_in_sync(self, _mock_sync, _mock_init):
        controller = PatchController()
        result = controller.in_sync_controller_api()
        self.assertEqual(result, {"in_sync": False})


class TestDropHost(unittest.TestCase):
    """Tests for drop_host."""

    @INIT_PATCH
    def test_drop_known_host(self, _mock_init):
        controller = PatchController()
        controller.hosts_lock = threading.Lock()
        controller.socket_lock = threading.Lock()
        controller.sock_out = mock.MagicMock()
        controller.interim_state = {}
        agent = mock.MagicMock()
        agent.hostname = "controller-0"
        controller.hosts = {"10.10.10.1": agent}
        result = controller.drop_host("10.10.10.1", False)
        self.assertNotIn("10.10.10.1", controller.hosts)
        self.assertEqual(result["error"], "")

    @INIT_PATCH
    def test_drop_by_hostname(self, _mock_init):
        controller = PatchController()
        controller.hosts_lock = threading.Lock()
        controller.socket_lock = threading.Lock()
        controller.sock_out = mock.MagicMock()
        controller.interim_state = {}
        agent = mock.MagicMock()
        agent.hostname = "controller-0"
        controller.hosts = {"10.10.10.1": agent}
        result = controller.drop_host("controller-0", False)
        self.assertNotIn("10.10.10.1", controller.hosts)
        self.assertEqual(result["error"], "")

    @INIT_PATCH
    def test_drop_unknown_host(self, _mock_init):
        controller = PatchController()
        controller.hosts_lock = threading.Lock()
        controller.socket_lock = threading.Lock()
        controller.hosts = {}
        controller.interim_state = {}
        result = controller.drop_host("unknown", False)
        self.assertIn("Unknown host", result["error"])

    @INIT_PATCH
    def test_drop_cleans_interim_state(self, _mock_init):
        controller = PatchController()
        controller.hosts_lock = threading.Lock()
        controller.socket_lock = threading.Lock()
        controller.sock_out = mock.MagicMock()
        agent = mock.MagicMock()
        agent.hostname = "controller-0"
        controller.hosts = {"10.10.10.1": agent}
        controller.interim_state = {"patch1": ["10.10.10.1", "10.10.10.2"]}
        controller.drop_host("10.10.10.1", False)
        self.assertNotIn("10.10.10.1", controller.interim_state["patch1"])
