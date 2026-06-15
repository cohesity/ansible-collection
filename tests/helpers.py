"""Shared test helper utilities for Cohesity Oracle module tests.

These helpers are kept here (not in conftest.py) so they can be explicitly
imported by test files in subdirectories (unit_test/, e2e/).
"""

from __future__ import absolute_import, division, print_function

import sys
from unittest.mock import MagicMock

import pytest


def mock_protection_sources_client(module_obj, nodes, parent_id=1):
    """Configure a fake cohesity_client on *module_obj*.

    Sets up ``protection_sources.list_protection_sources`` to return a single
    tree entry with the supplied *nodes* list and *parent_id*.
    """
    client = MagicMock()
    entry = MagicMock()
    entry.protection_source = MagicMock()
    entry.protection_source.id = parent_id
    entry.nodes = nodes
    client.protection_sources.list_protection_sources.return_value = [entry]
    module_obj.cohesity_client = client
    return client


def skip_unless_e2e(e2e_config):
    """Skip the calling test unless ``COHESITY_E2E`` and ``COHESITY_SERVER`` are set."""
    if not e2e_config["enabled"]:
        pytest.skip("Set COHESITY_E2E=1 to run E2E tests")
    if not e2e_config["cluster"]:
        pytest.skip("COHESITY_SERVER is required for E2E tests")


def oracle_job_endpoint(e2e_config):
    """Return the endpoint to use for Oracle job E2E tests."""
    if e2e_config["oracle_source_type"] == "rac":
        return e2e_config["scan_vip_address"]
    return e2e_config["oracle_endpoint"]
