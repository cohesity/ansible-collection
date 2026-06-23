"""E2E tests for cohesity_oracle_restore module.

Requires a live Cohesity cluster with Oracle backups available.

  export COHESITY_E2E=1
  export COHESITY_SERVER=<cluster-vip>
  export COHESITY_USERNAME=admin
  export COHESITY_PASSWORD=<password>
  export ORACLE_SOURCE_TYPE=standalone
  export ORACLE_ENDPOINT=<standalone-host>
  export SCAN_VIP_ADDRESS=<scan-or-vip>
  export RAC_ENDPOINT=<reachable-host>
  export ORACLE_SOURCE_DB=<source-db>
  export ORACLE_TARGET_SERVER=<target-host>
  export ORACLE_TARGET_DB=<target-db>
  export ORACLE_HOME=<oracle-home-path>      # default: /u01/app/oracle/product/12.1.0.2/db_1
  export ORACLE_BASE=<oracle-base-path>      # default: /u01/app/oracle
  export ORACLE_DATA=<oracle-data-path>      # default: /u01/app/oracle/product/12.1.0.2/db_1
"""

from __future__ import absolute_import, division, print_function

import os
import subprocess

import pytest

from helpers import skip_unless_e2e

pytestmark = pytest.mark.e2e


class TestCohesityOracleRestoreE2E:
    def test_check_mode_recover_database(self, e2e_config):
        skip_unless_e2e(e2e_config)
        source_server = (
            e2e_config["scan_vip_address"]
            if e2e_config["oracle_source_type"] == "rac"
            else e2e_config["oracle_endpoint"]
        )
        if not source_server:
            pytest.skip("Source server not configured for E2E restore test")

        source_db = os.environ.get("ORACLE_SOURCE_DB", "cdb1")
        target_server = os.environ.get("ORACLE_TARGET_SERVER", source_server)
        target_db = os.environ.get("ORACLE_TARGET_DB", "cdb2")
        oracle_home = os.environ.get(
            "ORACLE_HOME", "/u01/app/oracle/product/12.1.0.2/db_1"
        )
        oracle_base = os.environ.get("ORACLE_BASE", "/u01/app/oracle")
        oracle_data = os.environ.get(
            "ORACLE_DATA", "/u01/app/oracle/product/12.1.0.2/db_1"
        )

        cmd = [
            "ansible",
            "localhost",
            "-c", "local",
            "-i", "localhost,",
            "-m", "cohesity.dataprotect.cohesity_oracle_restore",
            "-a",
            "cluster=%s username=%s password=%s validate_certs=%s "
            "source_type=%s source_db=%s source_server=%s "
            "target_server=%s target_db=%s task_name=e2e_recover_test "
            "oracle_home=%s oracle_base=%s oracle_data=%s state=present"
            % (
                e2e_config["cluster"],
                e2e_config["username"],
                e2e_config["password"],
                str(e2e_config["validate_certs"]).lower(),
                e2e_config["oracle_source_type"],
                source_db,
                source_server,
                target_server,
                target_db,
                oracle_home,
                oracle_base,
                oracle_data,
            ),
            "--check",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        assert result.returncode == 0, result.stderr or result.stdout
