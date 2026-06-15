"""Shared pytest fixtures and helpers for Cohesity Oracle module tests."""

from __future__ import absolute_import, division, print_function

import importlib.util
import os
import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock

import pytest

COLLECTION_ROOT = Path(__file__).resolve().parent.parent
MODULES_DIR = COLLECTION_ROOT / "plugins" / "modules"
MODULE_UTILS_DIR = COLLECTION_ROOT / "plugins" / "module_utils"


def _ensure_package(name, path=None):
    if name in sys.modules:
        return sys.modules[name]
    pkg = ModuleType(name)
    pkg.__path__ = [str(path)] if path else []
    sys.modules[name] = pkg
    return pkg


def _install_collection_import_stubs():
    """Stub ansible_collections layout so modules can be loaded for unit tests."""
    _ensure_package("ansible")
    _ensure_package("ansible.module_utils")
    sys.modules["ansible.module_utils.basic"] = MagicMock()
    sys.modules["ansible.module_utils.urls"] = MagicMock()

    _ensure_package("ansible_collections")
    _ensure_package("ansible_collections.cohesity")
    _ensure_package("ansible_collections.cohesity.dataprotect", COLLECTION_ROOT)
    _ensure_package(
        "ansible_collections.cohesity.dataprotect.plugins", COLLECTION_ROOT / "plugins"
    )
    _ensure_package(
        "ansible_collections.cohesity.dataprotect.plugins.module_utils",
        MODULE_UTILS_DIR,
    )

    auth_mod = ModuleType(
        "ansible_collections.cohesity.dataprotect.plugins.module_utils.cohesity_auth"
    )
    auth_mod.get__cohesity_auth__token = MagicMock(return_value="test-token")
    sys.modules[auth_mod.__name__] = auth_mod

    util_mod = ModuleType(
        "ansible_collections.cohesity.dataprotect.plugins.module_utils.cohesity_utilities"
    )
    util_mod.cohesity_common_argument_spec = MagicMock(
        return_value={
            "cluster": {"type": "str"},
            "username": {"type": "str"},
            "password": {"type": "str", "no_log": True},
            "validate_certs": {"type": "bool", "default": False},
        }
    )
    util_mod.raise__cohesity_exception__handler = MagicMock(
        side_effect=lambda err, module: module.fail_json(msg=str(err))
    )
    util_mod.REQUEST_TIMEOUT = 60
    sys.modules[util_mod.__name__] = util_mod

    hints_mod = ModuleType(
        "ansible_collections.cohesity.dataprotect.plugins.module_utils.cohesity_hints"
    )
    hints_mod.get_cohesity_client = MagicMock()
    hints_mod.refresh_protection_source = MagicMock()
    hints_mod.check_source_reachability = MagicMock(return_value=True)
    sys.modules[hints_mod.__name__] = hints_mod

    sdk_models = ModuleType(
        "cohesity_management_sdk.models.register_protection_source_parameters"
    )
    sdk_models.RegisterProtectionSourceParameters = MagicMock
    sys.modules[sdk_models.__name__] = sdk_models

    sdk_exc = ModuleType("cohesity_management_sdk.exceptions.api_exception")
    sdk_exc.APIException = Exception
    sys.modules[sdk_exc.__name__] = sdk_exc


def _install_oracle_job_sdk_stubs():
    """Install SDK model stubs used only by cohesity_oracle_job."""
    for model_name in (
        "delete_protection_job_param",
        "cancel_protection_job_run_param",
        "protection_job_request_body",
        "run_protection_job_param",
        "source_special_parameter",
        "oracle_special_parameters",
        "oracle_database_node_channel",
        "oracle_app_params",
    ):
        mod = ModuleType("cohesity_management_sdk.models.%s" % model_name)
        for cls in (
            "DeleteProtectionJobParam",
            "CancelProtectionJobRunParam",
            "ProtectionJobRequestBody",
            "RunProtectionJobParam",
            "SourceSpecialParameter",
            "OracleSpecialParameters",
            "OracleDatabaseNodeChannel",
            "OracleAppParams",
        ):
            setattr(mod, cls, MagicMock)
        sys.modules[mod.__name__] = mod


@pytest.fixture(scope="session", autouse=True)
def _collection_stubs():
    """Install collection import stubs once for the entire test session."""
    _install_collection_import_stubs()


def load_module(module_filename):
    """Load a collection module by file name from plugins/modules."""
    module_path = MODULES_DIR / module_filename
    module_name = module_path.stem
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def oracle_source_module():
    return load_module("cohesity_oracle_source.py")


@pytest.fixture
def oracle_job_module():
    _install_oracle_job_sdk_stubs()
    return load_module("cohesity_oracle_job.py")


@pytest.fixture
def oracle_restore_module():
    return load_module("cohesity_oracle_restore.py")


@pytest.fixture
def mock_ansible_module():
    module = MagicMock()
    module.params = {}
    module.check_mode = False
    # exit_json exits with code 0 (success); fail_json exits with code 1 (failure).
    # Use `with pytest.raises(SystemExit) as exc_info` and check exc_info.value.code.
    module.fail_json = MagicMock(side_effect=lambda **kw: sys.exit(1))
    module.exit_json = MagicMock(side_effect=lambda **kw: sys.exit(0))
    return module


@pytest.fixture
def e2e_config():
    """E2E tests require live cluster credentials via environment variables."""
    return {
        "enabled": os.environ.get("COHESITY_E2E", "").lower() in ("1", "true", "yes"),
        "cluster": os.environ.get("COHESITY_SERVER", ""),
        "username": os.environ.get("COHESITY_USERNAME", "admin"),
        "password": os.environ.get("COHESITY_PASSWORD", ""),
        "validate_certs": os.environ.get("COHESITY_VALIDATE_CERTS", "false").lower()
        == "true",
        "oracle_endpoint": os.environ.get("ORACLE_ENDPOINT", ""),
        "rac_endpoint": os.environ.get("RAC_ENDPOINT", ""),
        "scan_vip_address": os.environ.get("SCAN_VIP_ADDRESS")
        or os.environ.get("RAC_AGENT_NODE", ""),
        "oracle_source_type": os.environ.get("ORACLE_SOURCE_TYPE", "standalone"),
    }
