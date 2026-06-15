"""E2E tests for cohesity_oracle_source module.

Requires a live Cohesity cluster. Enable with environment variables:

  export COHESITY_E2E=1
  export COHESITY_SERVER=<cluster-vip>
  export COHESITY_USERNAME=admin
  export COHESITY_PASSWORD=<password>
  export ORACLE_SOURCE_TYPE=standalone   # or rac
  export ORACLE_ENDPOINT=<standalone-host>  # standalone only
  export SCAN_VIP_ADDRESS=<scan-or-vip>   # rac only (SCAN/VIP Address)
  export RAC_ENDPOINT=<reachable-host>       # rac only (optional)
"""

from __future__ import absolute_import, division, print_function

import subprocess

import pytest

from helpers import skip_unless_e2e

pytestmark = pytest.mark.e2e


def _rac_module_args(e2e_config, include_endpoint=True):
    """Build RAC module args; endpoint (reachable host) is optional."""
    args = (
        "cluster=%s username=%s password=%s validate_certs=%s "
        "scan_vip_address=%s source_type=rac state=present"
        % (
            e2e_config["cluster"],
            e2e_config["username"],
            e2e_config["password"],
            str(e2e_config["validate_certs"]).lower(),
            e2e_config["scan_vip_address"],
        )
    )
    if include_endpoint and e2e_config["rac_endpoint"]:
        args += " endpoint=%s" % e2e_config["rac_endpoint"]
    return args


class TestCohesityOracleSourceE2E:
    def test_check_mode_register_standalone(self, e2e_config):
        skip_unless_e2e(e2e_config)
        if e2e_config["oracle_source_type"] != "standalone":
            pytest.skip("Set ORACLE_SOURCE_TYPE=standalone for this test")
        if not e2e_config["oracle_endpoint"]:
            pytest.skip("ORACLE_ENDPOINT is required for standalone E2E")

        cmd = [
            "ansible",
            "localhost",
            "-c", "local",
            "-i", "localhost,",
            "-m", "cohesity.dataprotect.cohesity_oracle_source",
            "-a",
            "cluster=%s username=%s password=%s validate_certs=%s "
            "endpoint=%s source_type=standalone state=present"
            % (
                e2e_config["cluster"],
                e2e_config["username"],
                e2e_config["password"],
                str(e2e_config["validate_certs"]).lower(),
                e2e_config["oracle_endpoint"],
            ),
            "--check",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        assert result.returncode == 0, result.stderr or result.stdout

    def test_check_mode_register_rac(self, e2e_config):
        skip_unless_e2e(e2e_config)
        if e2e_config["oracle_source_type"] != "rac":
            pytest.skip("Set ORACLE_SOURCE_TYPE=rac for this test")
        if not e2e_config["scan_vip_address"]:
            pytest.skip("SCAN_VIP_ADDRESS is required for RAC E2E")

        cmd = [
            "ansible",
            "localhost",
            "-c", "local",
            "-i", "localhost,",
            "-m", "cohesity.dataprotect.cohesity_oracle_source",
            "-a", _rac_module_args(e2e_config, include_endpoint=True),
            "--check",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        assert result.returncode == 0, result.stderr or result.stdout

    def test_check_mode_register_rac_without_optional_endpoint(self, e2e_config):
        skip_unless_e2e(e2e_config)
        if e2e_config["oracle_source_type"] != "rac":
            pytest.skip("Set ORACLE_SOURCE_TYPE=rac for this test")
        if not e2e_config["scan_vip_address"]:
            pytest.skip("SCAN_VIP_ADDRESS is required for RAC E2E")

        cmd = [
            "ansible",
            "localhost",
            "-c", "local",
            "-i", "localhost,",
            "-m", "cohesity.dataprotect.cohesity_oracle_source",
            "-a", _rac_module_args(e2e_config, include_endpoint=False),
            "--check",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        assert result.returncode == 0, result.stderr or result.stdout

    def test_refresh_source_check_mode(self, e2e_config):
        skip_unless_e2e(e2e_config)
        if e2e_config["oracle_source_type"] == "rac":
            if not e2e_config["scan_vip_address"]:
                pytest.skip("SCAN_VIP_ADDRESS is required for RAC refresh E2E")
            endpoint = e2e_config["rac_endpoint"] or ""
            extra = " source_type=rac scan_vip_address=%s" % e2e_config["scan_vip_address"]
        else:
            endpoint = e2e_config["oracle_endpoint"]
            extra = ""
            if not endpoint:
                pytest.skip("ORACLE_ENDPOINT is required for standalone refresh E2E")

        cmd = [
            "ansible",
            "localhost",
            "-c", "local",
            "-i", "localhost,",
            "-m", "cohesity.dataprotect.cohesity_oracle_source",
            "-a",
            "cluster=%s username=%s password=%s validate_certs=%s "
            "endpoint=%s state=present refresh=true%s"
            % (
                e2e_config["cluster"],
                e2e_config["username"],
                e2e_config["password"],
                str(e2e_config["validate_certs"]).lower(),
                endpoint,
                extra,
            ),
            "--check",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        assert result.returncode == 0, result.stderr or result.stdout
