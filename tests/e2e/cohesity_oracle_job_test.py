"""E2E tests for cohesity_oracle_job module.

Requires a live Cohesity cluster with a registered Oracle source.

  export COHESITY_E2E=1
  export COHESITY_SERVER=<cluster-vip>
  export COHESITY_USERNAME=admin
  export COHESITY_PASSWORD=<password>
  export ORACLE_SOURCE_TYPE=standalone
  export ORACLE_ENDPOINT=<standalone-host>
  export SCAN_VIP_ADDRESS=<scan-or-vip>
  export RAC_ENDPOINT=<reachable-host>
  export COHESITY_JOB_NAME=protect_oracle
  export COHESITY_JOB_POLICY=Bronze              # default: Bronze
  export COHESITY_STORAGE_DOMAIN=DefaultStorageDomain  # default: DefaultStorageDomain
"""

from __future__ import absolute_import, division, print_function

import os
import subprocess

import pytest

from helpers import oracle_job_module_args, skip_unless_e2e

pytestmark = pytest.mark.e2e


class TestCohesityOracleJobE2E:
    def test_check_mode_create_job(self, e2e_config):
        skip_unless_e2e(e2e_config)
        source_args = oracle_job_module_args(e2e_config)
        job_name = os.environ.get("COHESITY_JOB_NAME", os.environ.get("ORACLE_JOB_NAME", "protect_oracle"))
        policy = os.environ.get("COHESITY_JOB_POLICY", os.environ.get("ORACLE_JOB_POLICY", "Bronze"))
        storage_domain = os.environ.get(
            "COHESITY_STORAGE_DOMAIN",
            os.environ.get("ORACLE_STORAGE_DOMAIN", "DefaultStorageDomain"),
        )
        if not source_args:
            pytest.skip("Oracle source args not configured for E2E job test")

        cmd = [
            "ansible",
            "localhost",
            "-c", "local",
            "-i", "localhost,",
            "-m", "cohesity.dataprotect.cohesity_oracle_job",
            "-a",
            "cluster=%s username=%s password=%s validate_certs=%s "
            "name=%s %s state=present "
            "protection_policy=%s storage_domain=%s"
            % (
                e2e_config["cluster"],
                e2e_config["username"],
                e2e_config["password"],
                str(e2e_config["validate_certs"]).lower(),
                job_name,
                source_args,
                policy,
                storage_domain,
            ),
            "--check",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        assert result.returncode == 0, result.stderr or result.stdout

    def test_check_mode_start_job(self, e2e_config):
        skip_unless_e2e(e2e_config)
        source_args = oracle_job_module_args(e2e_config)
        job_name = os.environ.get("COHESITY_JOB_NAME", os.environ.get("ORACLE_JOB_NAME", "protect_oracle"))
        if not source_args:
            pytest.skip("Oracle source args not configured for E2E job test")

        cmd = [
            "ansible",
            "localhost",
            "-c", "local",
            "-i", "localhost,",
            "-m", "cohesity.dataprotect.cohesity_oracle_job",
            "-a",
            "cluster=%s username=%s password=%s validate_certs=%s "
            "name=%s %s state=started"
            % (
                e2e_config["cluster"],
                e2e_config["username"],
                e2e_config["password"],
                str(e2e_config["validate_certs"]).lower(),
                job_name,
                source_args,
            ),
            "--check",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        assert result.returncode == 0, result.stderr or result.stdout
