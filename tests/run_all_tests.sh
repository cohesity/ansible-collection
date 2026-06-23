#!/usr/bin/env bash
# Run all Oracle module tests: unit + E2E (standalone + RAC).
#
# Usage:
#   ./tests/run_all_tests.sh              # unit tests only
#   ./tests/run_all_tests.sh --e2e        # unit + E2E (needs cluster env vars below)
#
# E2E environment (required when using --e2e):
#   export COHESITY_SERVER=<cluster-vip>
#   export COHESITY_USERNAME=admin
#   export COHESITY_PASSWORD=<password>
#   export ORACLE_ENDPOINT=<standalone-host>
#   export SCAN_VIP_ADDRESS=<scan-or-vip>
#   export RAC_ENDPOINT=<reachable-host>   # optional

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "========== Unit tests =========="
python3 -m pytest tests/unit_test/ -v
echo "Unit tests passed."

if [[ "${1:-}" != "--e2e" ]]; then
  echo ""
  echo "E2E tests skipped. To include them, run:"
  echo "  ./tests/run_all_tests.sh --e2e"
  exit 0
fi

: "${COHESITY_SERVER:?Set COHESITY_SERVER for E2E tests}"
export COHESITY_USERNAME="${COHESITY_USERNAME:-admin}"
: "${COHESITY_PASSWORD:?Set COHESITY_PASSWORD for E2E tests}"

export COHESITY_E2E=1
export COHESITY_VALIDATE_CERTS="${COHESITY_VALIDATE_CERTS:-false}"

echo ""
echo "========== E2E tests — Oracle Standalone =========="
export ORACLE_SOURCE_TYPE=standalone
: "${ORACLE_ENDPOINT:?Set ORACLE_ENDPOINT for standalone E2E}"
python3 -m pytest tests/e2e/ -v -m e2e -k "standalone or not rac"
echo "Standalone E2E tests passed."

echo ""
echo "========== E2E tests — Oracle RAC =========="
export ORACLE_SOURCE_TYPE=rac
export SCAN_VIP_ADDRESS="${SCAN_VIP_ADDRESS:-${RAC_AGENT_NODE:-}}"
if [[ -z "${SCAN_VIP_ADDRESS}" ]]; then
  echo "Set SCAN_VIP_ADDRESS for RAC E2E (legacy env: RAC_AGENT_NODE)" >&2
  exit 1
fi
python3 -m pytest tests/e2e/ -v -m e2e
echo "RAC E2E tests passed."

echo ""
echo "All tests completed."
