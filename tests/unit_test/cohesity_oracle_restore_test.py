"""Unit tests for cohesity_oracle_restore module."""

from __future__ import absolute_import, division, print_function

import json
from unittest.mock import MagicMock, patch

import pytest


def _vm(source_aliases, snapshot=1000, db_name="cdb1"):
    return {
        "vmDocument": {
            "objectAliases": source_aliases,
            "versions": [{"snapshotTimestampUsecs": snapshot}],
            "objectId": {
                "jobId": 11,
                "jobUid": {"id": 1},
                "entity": {"parentId": 22, "id": 33},
            },
        }
    }


class TestGetRacSourceAliases:
    def test_returns_scan_and_reachable_aliases(self, oracle_restore_module):
        client = MagicMock()
        entry = MagicMock()
        entry.nodes = [
            {
                "protectionSource": {"name": "10.14.40.96"},
                "registrationInfo": {
                    "accessInfo": {"endpoint": "10.14.40.74"}
                },
            }
        ]
        client.protection_sources.list_protection_sources.return_value = [entry]
        oracle_restore_module.cohesity_client = client
        aliases = oracle_restore_module.get_rac_source_aliases("10.14.40.96")
        assert aliases == ["10.14.40.96", "10.14.40.74"]

    def test_returns_only_scan_when_nodes_empty(self, oracle_restore_module):
        client = MagicMock()
        entry = MagicMock()
        entry.nodes = []
        client.protection_sources.list_protection_sources.return_value = [entry]
        oracle_restore_module.cohesity_client = client
        aliases = oracle_restore_module.get_rac_source_aliases("10.14.40.96")
        assert aliases == []

    def test_returns_empty_on_error(self, oracle_restore_module):
        client = MagicMock()
        client.protection_sources.list_protection_sources.side_effect = Exception(
            "api error"
        )
        oracle_restore_module.cohesity_client = client
        aliases = oracle_restore_module.get_rac_source_aliases("10.14.40.96")
        assert aliases == []


class TestSearchForDatabase:
    def test_standalone_matches_source_server(
        self, oracle_restore_module, mock_ansible_module
    ):
        mock_ansible_module.params = {
            "cluster": "10.14.57.205",
            "source_db": "cdb1",
            "source_server": "host.example.com",
            "source_type": "standalone",
            "validate_certs": False,
        }
        search_response = json.dumps(
            {"vms": [_vm(["host.example.com"], snapshot=2000)]}
        ).encode()
        mock_http = MagicMock()
        mock_http.read.return_value = search_response

        with patch.object(oracle_restore_module, "open_url", return_value=mock_http):
            result = oracle_restore_module.search_for_database(
                "token", mock_ansible_module
            )

        assert result["vmDocument"]["objectAliases"] == ["host.example.com"]

    def test_rac_uses_alias_fallback(self, oracle_restore_module, mock_ansible_module):
        # source_server is the reachable node address, NOT the SCAN/VIP stored in
        # objectAliases. The first-pass search misses, triggering the RAC alias fallback.
        mock_ansible_module.params = {
            "cluster": "10.14.57.205",
            "source_db": "cdb1",
            "source_server": "10.14.40.74",  # reachable node — not in objectAliases
            "source_type": "rac",
            "validate_certs": False,
        }
        search_response = json.dumps(
            {"vms": [_vm(["10.14.40.96"], snapshot=3000)]}  # SCAN/VIP is in aliases
        ).encode()
        mock_http = MagicMock()
        mock_http.read.return_value = search_response

        with patch.object(
            oracle_restore_module,
            "get_rac_source_aliases",
            return_value=["10.14.40.96", "10.14.40.74"],
        ) as mock_aliases, patch.object(
            oracle_restore_module, "open_url", return_value=mock_http
        ):
            result = oracle_restore_module.search_for_database(
                "token", mock_ansible_module
            )

        mock_aliases.assert_called_once_with("10.14.40.74")
        assert "10.14.40.96" in result["vmDocument"]["objectAliases"]

    def test_fails_when_database_not_in_source(
        self, oracle_restore_module, mock_ansible_module
    ):
        mock_ansible_module.params = {
            "cluster": "10.14.57.205",
            "source_db": "cdb1",
            "source_server": "host.example.com",
            "source_type": "standalone",
            "validate_certs": False,
        }
        search_response = json.dumps(
            {"vms": [_vm(["other.example.com"], snapshot=1000)]}
        ).encode()
        mock_http = MagicMock()
        mock_http.read.return_value = search_response

        with patch.object(oracle_restore_module, "open_url", return_value=mock_http):
            with pytest.raises(SystemExit) as exc_info:
                oracle_restore_module.search_for_database(
                    "token", mock_ansible_module
                )
        assert exc_info.value.code == 1
        mock_ansible_module.fail_json.assert_called_once()

    def test_fails_when_vms_list_is_empty(
        self, oracle_restore_module, mock_ansible_module
    ):
        mock_ansible_module.params = {
            "cluster": "10.14.57.205",
            "source_db": "cdb1",
            "source_server": "host.example.com",
            "source_type": "standalone",
            "validate_certs": False,
        }
        search_response = json.dumps({"vms": []}).encode()
        mock_http = MagicMock()
        mock_http.read.return_value = search_response

        with patch.object(oracle_restore_module, "open_url", return_value=mock_http):
            with pytest.raises(SystemExit) as exc_info:
                oracle_restore_module.search_for_database(
                    "token", mock_ansible_module
                )
        assert exc_info.value.code == 1
        mock_ansible_module.fail_json.assert_called_once()
