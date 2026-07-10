"""Unit tests for cohesity_oracle_source module."""

from __future__ import absolute_import, division, print_function

import json
from unittest.mock import MagicMock, patch

import pytest

from helpers import mock_protection_sources_client


class TestRacOptionalEndpoint:
    def test_rac_connect_address_falls_back_to_scan(
        self, oracle_source_module, mock_ansible_module
    ):
        mock_ansible_module.params = {
            "endpoint": "",
            "scan_vip_address": "10.14.40.96",
        }
        assert oracle_source_module._rac_connect_address(mock_ansible_module) == (
            "10.14.40.96"
        )

    def test_rac_connect_address_prefers_reachable(
        self, oracle_source_module, mock_ansible_module
    ):
        mock_ansible_module.params = {
            "endpoint": "10.14.40.74",
            "scan_vip_address": "10.14.40.96",
        }
        assert oracle_source_module._rac_connect_address(mock_ansible_module) == (
            "10.14.40.74"
        )

    def test_rac_build_prot_sources_without_endpoint(
        self, oracle_source_module, mock_ansible_module
    ):
        mock_ansible_module.params = {
            "endpoint": "",
            "source_type": "rac",
            "scan_vip_address": "10.14.40.96",
        }
        with patch.object(
            oracle_source_module, "get__cohesity_auth__token", return_value="token-1"
        ):
            result = oracle_source_module._build_prot_sources(
                mock_ansible_module, "kPhysical"
            )
        assert result["endpoint"] == ""
        assert result["scan_vip_address"] == "10.14.40.96"
        assert result["token"] == "token-1"


class TestBuildProtSources:
    def test_standalone_excludes_rac_fields(self, oracle_source_module, mock_ansible_module):
        mock_ansible_module.params = {
            "endpoint": "host.example.com",
            "source_type": "standalone",
            "scan_vip_address": "",
        }
        with patch.object(
            oracle_source_module, "get__cohesity_auth__token", return_value="token-1"
        ):
            result = oracle_source_module._build_prot_sources(
                mock_ansible_module, "kPhysical"
            )
        assert result["endpoint"] == "host.example.com"
        assert result["environment"] == "kPhysical"
        assert result["token"] == "token-1"
        assert "source_type" not in result
        assert "scan_vip_address" not in result

    def test_rac_includes_scan_and_optional_reachable(
        self, oracle_source_module, mock_ansible_module
    ):
        mock_ansible_module.params = {
            "endpoint": "10.14.40.74",
            "source_type": "rac",
            "scan_vip_address": "10.14.40.96",
        }
        with patch.object(
            oracle_source_module, "get__cohesity_auth__token", return_value="token-1"
        ):
            result = oracle_source_module._build_prot_sources(
                mock_ansible_module, "kPhysical"
            )
        assert result["source_type"] == "rac"
        assert result["scan_vip_address"] == "10.14.40.96"
        assert result["endpoint"] == "10.14.40.74"


class TestGetProtectionSourceRegistrationStatus:
    def test_standalone_matches_name(self, oracle_source_module, mock_ansible_module):
        nodes = [
            {
                "protectionSource": {"name": "host.example.com", "id": 101},
                "registrationInfo": {},
            }
        ]
        mock_protection_sources_client(oracle_source_module, nodes)
        self_dict = {
            "environment": "kPhysical",
            "endpoint": "host.example.com",
        }
        result = oracle_source_module.get__protection_source_registration__status(
            mock_ansible_module, self_dict
        )
        assert result == 101

    def test_rac_matches_scan_in_access_info(
        self, oracle_source_module, mock_ansible_module
    ):
        nodes = [
            {
                "protectionSource": {"name": "10.14.40.96", "id": 202},
                "registrationInfo": {
                    "accessInfo": {"endpoint": "10.14.40.74"}
                },
            }
        ]
        mock_protection_sources_client(oracle_source_module, nodes)
        self_dict = {
            "environment": "kPhysical",
            "endpoint": "10.14.40.74",
            "source_type": "rac",
            "scan_vip_address": "10.14.40.96",
        }
        result = oracle_source_module.get__protection_source_registration__status(
            mock_ansible_module, self_dict
        )
        assert result == 202

    def test_rac_matches_scan_name(
        self, oracle_source_module, mock_ansible_module
    ):
        nodes = [
            {
                "protectionSource": {"name": "10.14.40.96", "id": 303},
                "registrationInfo": {
                    "accessInfo": {"endpoint": "10.14.40.74"}
                },
            }
        ]
        mock_protection_sources_client(oracle_source_module, nodes)
        self_dict = {
            "environment": "kPhysical",
            "endpoint": "",
            "source_type": "rac",
            "scan_vip_address": "10.14.40.96",
        }
        result = oracle_source_module.get__protection_source_registration__status(
            mock_ansible_module, self_dict
        )
        assert result == 303

    def test_rac_matches_reachable_access_endpoint(
        self, oracle_source_module, mock_ansible_module
    ):
        nodes = [
            {
                "protectionSource": {"name": "10.14.40.96", "id": 404},
                "registrationInfo": {
                    "accessInfo": {"endpoint": "10.14.40.74"}
                },
            }
        ]
        mock_protection_sources_client(oracle_source_module, nodes)
        self_dict = {
            "environment": "kPhysical",
            "endpoint": "10.14.40.74",
            "source_type": "rac",
            "scan_vip_address": "10.14.40.96",
        }
        result = oracle_source_module.get__protection_source_registration__status(
            mock_ansible_module, self_dict
        )
        assert result == 404

    def test_returns_false_when_not_found(
        self, oracle_source_module, mock_ansible_module
    ):
        mock_protection_sources_client(oracle_source_module, [])
        self_dict = {"environment": "kPhysical", "endpoint": "missing.example.com"}
        result = oracle_source_module.get__protection_source_registration__status(
            mock_ansible_module, self_dict
        )
        assert result is False


class TestRegisterRacPhysicalSource:
    def test_backupsources_payload(self, oracle_source_module, mock_ansible_module):
        mock_ansible_module.params = {
            "cluster": "10.14.57.205",
            "validate_certs": False,
            "force_register": False,
        }
        prot_sources = {
            "token": "test-token",
            "endpoint": "10.14.40.74",
            "scan_vip_address": "10.14.40.96",
        }
        response_body = json.dumps({"id": 42}).encode()
        mock_response = MagicMock()
        mock_response.read.return_value = response_body

        with patch.object(
            oracle_source_module, "open_url", return_value=mock_response
        ) as mock_open_url:
            result = oracle_source_module.register_rac_physical_source(
                mock_ansible_module, prot_sources
            )

        assert result == {"id": 42}
        mock_open_url.assert_called_once()
        call_kwargs = mock_open_url.call_args[1]
        assert call_kwargs["method"] == "POST"
        assert call_kwargs["url"].endswith("/irisservices/api/v1/backupsources")
        payload = json.loads(call_kwargs["data"])
        assert payload["entity"]["physicalEntity"]["name"] == "10.14.40.96"
        assert payload["entityInfo"]["endPoint"] == "10.14.40.74"
        assert payload["entity"]["physicalEntity"]["type"] == 6

    def test_backupsources_payload_uses_scan_when_no_reachable_endpoint(
        self, oracle_source_module, mock_ansible_module
    ):
        mock_ansible_module.params = {
            "cluster": "10.14.57.205",
            "validate_certs": False,
            "force_register": False,
        }
        prot_sources = {
            "token": "test-token",
            "endpoint": "",
            "scan_vip_address": "10.14.40.96",
        }
        response_body = json.dumps({"id": 42}).encode()
        mock_response = MagicMock()
        mock_response.read.return_value = response_body

        with patch.object(
            oracle_source_module, "open_url", return_value=mock_response
        ) as mock_open_url:
            oracle_source_module.register_rac_physical_source(
                mock_ansible_module, prot_sources
            )

        payload = json.loads(mock_open_url.call_args[1]["data"])
        assert payload["entity"]["physicalEntity"]["name"] == "10.14.40.96"
        assert payload["entityInfo"]["endPoint"] == "10.14.40.96"

    def test_raises_on_url_error(self, oracle_source_module, mock_ansible_module):
        from urllib.error import URLError

        mock_ansible_module.params = {
            "cluster": "10.14.57.205",
            "validate_certs": False,
            "force_register": False,
        }
        prot_sources = {
            "token": "test-token",
            "endpoint": "10.14.40.74",
            "scan_vip_address": "10.14.40.96",
        }
        err = URLError("connection refused")
        err.read = lambda: b"connection refused"  # URLError needs .read() for the handler
        with patch.object(
            oracle_source_module, "open_url", side_effect=err
        ):
            with pytest.raises(SystemExit) as exc_info:
                oracle_source_module.register_rac_physical_source(
                    mock_ansible_module, prot_sources
                )
        assert exc_info.value.code == 1
        mock_ansible_module.fail_json.assert_called_once()


class TestRegisterOracleSource:
    def test_includes_db_credentials(self, oracle_source_module, mock_ansible_module):
        mock_ansible_module.params = {
            "cluster": "10.14.57.205",
            "validate_certs": False,
            "db_username": "oracle",
            "db_password": "secret",
        }
        prot_sources = {"token": "tok", "endpoint": "", "scan_vip_address": "10.14.40.96"}
        response_body = json.dumps({"status": "ok"}).encode()
        mock_response = MagicMock()
        mock_response.read.return_value = response_body

        with patch.object(
            oracle_source_module, "open_url", return_value=mock_response
        ) as mock_open_url:
            result = oracle_source_module.register_oracle_source(
                mock_ansible_module, prot_sources, 55
            )

        assert result is True
        payload = json.loads(mock_open_url.call_args[1]["data"])
        assert payload["ownerEntity"]["id"] == 55
        assert payload["ownerEntity"]["displayName"] == "10.14.40.96"
        assert payload["appCredentialsVec"][0]["credentials"]["username"] == "oracle"

    def test_returns_false_on_empty_response(
        self, oracle_source_module, mock_ansible_module
    ):
        mock_ansible_module.params = {
            "cluster": "10.14.57.205",
            "validate_certs": False,
            "db_username": "",
            "db_password": "",
        }
        prot_sources = {"token": "tok", "endpoint": "host.example.com", "scan_vip_address": ""}
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({}).encode()

        with patch.object(oracle_source_module, "open_url", return_value=mock_response):
            result = oracle_source_module.register_oracle_source(
                mock_ansible_module, prot_sources, 10
            )

        assert result is False

    def test_returns_false_on_url_error(
        self, oracle_source_module, mock_ansible_module
    ):
        from urllib.error import URLError

        mock_ansible_module.params = {
            "cluster": "10.14.57.205",
            "validate_certs": False,
            "db_username": "",
            "db_password": "",
        }
        prot_sources = {"token": "tok", "endpoint": "host.example.com", "scan_vip_address": ""}
        err = URLError("timeout")
        err.read = lambda: b"timeout"  # URLError needs .read() for the handler
        with patch.object(
            oracle_source_module, "open_url", side_effect=err
        ):
            with pytest.raises(SystemExit) as exc_info:
                oracle_source_module.register_oracle_source(
                    mock_ansible_module, prot_sources, 10
                )

        assert exc_info.value.code == 1
        mock_ansible_module.fail_json.assert_called_once()
