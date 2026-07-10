"""Unit tests for cohesity_oracle_job module."""

from __future__ import absolute_import, division, print_function

from unittest.mock import MagicMock

import pytest

from helpers import mock_protection_sources_client


class TestGetSourceIdByEndpoint:
    def test_standalone_matches_name(self, oracle_job_module, mock_ansible_module):
        nodes = [{"protectionSource": {"name": "host.example.com", "id": 501}}]
        mock_protection_sources_client(oracle_job_module, nodes, parent_id=1)
        mock_ansible_module.params = {
            "endpoint": "host.example.com",
            "scan_vip_address": "",
            "environment": "kOracle",
            "source_type": "standalone",
        }
        parent_id, source_id = oracle_job_module.get_source_id_by_endpoint(
            mock_ansible_module
        )
        assert parent_id == 1
        assert source_id == 501

    def test_rac_matches_scan_name(self, oracle_job_module, mock_ansible_module):
        nodes = [
            {
                "protectionSource": {"name": "10.14.40.96", "id": 602},
                "registrationInfo": {
                    "accessInfo": {"endpoint": "10.14.40.74"}
                },
            }
        ]
        mock_protection_sources_client(oracle_job_module, nodes, parent_id=1)
        mock_ansible_module.params = {
            "endpoint": "",
            "scan_vip_address": "10.14.40.96",
            "environment": "kOracle",
            "source_type": "rac",
        }
        parent_id, source_id = oracle_job_module.get_source_id_by_endpoint(
            mock_ansible_module
        )
        assert parent_id == 1
        assert source_id == 602

    def test_rac_matches_reachable_endpoint_fallback(
        self, oracle_job_module, mock_ansible_module
    ):
        nodes = [
            {
                "protectionSource": {"name": "10.14.40.96", "id": 604},
                "registrationInfo": {
                    "accessInfo": {"endpoint": "10.14.40.74"}
                },
            }
        ]
        mock_protection_sources_client(oracle_job_module, nodes, parent_id=1)
        mock_ansible_module.params = {
            "endpoint": "10.14.40.74",
            "scan_vip_address": "unreachable-scan.example.com",
            "environment": "kOracle",
            "source_type": "rac",
        }
        parent_id, source_id = oracle_job_module.get_source_id_by_endpoint(
            mock_ansible_module
        )
        assert parent_id == 1
        assert source_id == 604

    def test_returns_none_when_not_found(self, oracle_job_module, mock_ansible_module):
        mock_protection_sources_client(oracle_job_module, [], parent_id=1)
        mock_ansible_module.params = {
            "endpoint": "missing.example.com",
            "scan_vip_address": "",
            "environment": "kOracle",
            "source_type": "standalone",
        }
        parent_id, source_id = oracle_job_module.get_source_id_by_endpoint(
            mock_ansible_module
        )
        assert parent_id is None
        assert source_id is None


class TestCheckMandatoryParams:
    def test_present_requires_endpoint_policy_storage(
        self, oracle_job_module, mock_ansible_module
    ):
        mock_ansible_module.params = {
            "state": "present",
            "environment": "kOracle",
            "source_type": "standalone",
            "endpoint": "",
            "scan_vip_address": "",
            "protection_policy": "",
            "storage_domain": "",
        }
        with pytest.raises(SystemExit) as exc_info:
            oracle_job_module.check__mandatory__params(mock_ansible_module)
        assert exc_info.value.code == 1
        mock_ansible_module.fail_json.assert_called_once()
        assert "endpoint" in mock_ansible_module.fail_json.call_args[1]["missing"]

    def test_present_rac_requires_scan_vip_address(
        self, oracle_job_module, mock_ansible_module
    ):
        mock_ansible_module.params = {
            "state": "present",
            "environment": "kOracle",
            "source_type": "rac",
            "endpoint": "",
            "scan_vip_address": "",
            "protection_policy": "Bronze",
            "storage_domain": "DefaultStorageDomain",
        }
        with pytest.raises(SystemExit) as exc_info:
            oracle_job_module.check__mandatory__params(mock_ansible_module)
        assert exc_info.value.code == 1
        mock_ansible_module.fail_json.assert_called_once()
        assert "scan_vip_address" in mock_ansible_module.fail_json.call_args[1]["missing"]

    def test_present_passes_with_required_fields(
        self, oracle_job_module, mock_ansible_module
    ):
        mock_ansible_module.params = {
            "state": "present",
            "environment": "kOracle",
            "source_type": "standalone",
            "endpoint": "host.example.com",
            "scan_vip_address": "",
            "protection_policy": "Bronze",
            "storage_domain": "DefaultStorageDomain",
        }
        oracle_job_module.check__mandatory__params(mock_ansible_module)
        mock_ansible_module.fail_json.assert_not_called()

    def test_absent_does_not_require_policy_or_storage(
        self, oracle_job_module, mock_ansible_module
    ):
        mock_ansible_module.params = {
            "state": "absent",
            "environment": "kOracle",
            "endpoint": "host.example.com",
            "protection_policy": "",
            "storage_domain": "",
        }
        oracle_job_module.check__mandatory__params(mock_ansible_module)
        mock_ansible_module.fail_json.assert_not_called()


class TestGetProtectionRunStatusById:
    def _mock_run(self, oracle_job_module, status):
        last_run = MagicMock()
        last_run.backup_run.status = status
        client = MagicMock()
        client.protection_runs.get_protection_runs.return_value = [last_run]
        oracle_job_module.cohesity_client = client
        return last_run

    @pytest.mark.parametrize(
        "status",
        ["kAccepted", "kRunning", "kCanceling"],
    )
    def test_active_run_statuses(self, oracle_job_module, mock_ansible_module, status):
        last_run = self._mock_run(oracle_job_module, status)
        active, returned_status, returned_run = (
            oracle_job_module.get_protection_run__status__by_id(
                mock_ansible_module, 900
            )
        )
        assert active is True
        assert returned_status == status
        assert returned_run == last_run

    @pytest.mark.parametrize(
        "status",
        ["kSuccess", "kCanceled"],
    )
    def test_finished_run_statuses(self, oracle_job_module, mock_ansible_module, status):
        last_run = self._mock_run(oracle_job_module, status)
        active, returned_status, returned_run = (
            oracle_job_module.get_protection_run__status__by_id(
                mock_ansible_module, 900
            )
        )
        assert active is False
        assert returned_status == status
        assert returned_run == last_run

    def test_returns_inactive_when_no_runs(self, oracle_job_module, mock_ansible_module):
        client = MagicMock()
        client.protection_runs.get_protection_runs.return_value = []
        oracle_job_module.cohesity_client = client
        active, status, last_run = oracle_job_module.get_protection_run__status__by_id(
            mock_ansible_module, 900
        )
        assert active is False
        assert status == ""
        assert last_run == ""

    def test_returns_inactive_on_api_exception(
        self, oracle_job_module, mock_ansible_module
    ):
        client = MagicMock()
        client.protection_runs.get_protection_runs.side_effect = Exception("API error")
        oracle_job_module.cohesity_client = client
        with pytest.raises(SystemExit) as exc_info:
            oracle_job_module.get_protection_run__status__by_id(mock_ansible_module, 900)
        assert exc_info.value.code == 1
        mock_ansible_module.fail_json.assert_called_once()


class TestCheckProtectionJobExists:
    def test_returns_job_id_when_found(self, oracle_job_module, mock_ansible_module):
        job = MagicMock()
        job.name = "protect_oracle"
        job.id = 900
        client = MagicMock()
        client.protection_jobs.get_protection_jobs.return_value = [job]
        oracle_job_module.cohesity_client = client
        mock_ansible_module.params = {
            "name": "protect_oracle",
            "environment": "kOracle",
        }
        job_id, job_meta = oracle_job_module.check__protection_job__exists(
            mock_ansible_module
        )
        assert job_id == 900
        assert job_meta == job

    def test_returns_false_when_not_found(self, oracle_job_module, mock_ansible_module):
        client = MagicMock()
        client.protection_jobs.get_protection_jobs.return_value = []
        oracle_job_module.cohesity_client = client
        mock_ansible_module.params = {
            "name": "missing_job",
            "environment": "kOracle",
        }
        job_id, job_meta = oracle_job_module.check__protection_job__exists(
            mock_ansible_module
        )
        assert job_id is False
        assert job_meta == ""
