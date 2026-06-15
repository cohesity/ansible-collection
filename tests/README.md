# Cohesity Oracle Module Tests

This directory contains **unit tests** (mocked, no cluster required) and **E2E tests** (live Cohesity cluster, run in Ansible `--check` mode).

## Directory layout

| Path | Description |
|------|-------------|
| `unit_test/` | Unit tests for `cohesity_oracle_source`, `cohesity_oracle_job`, and `cohesity_oracle_restore` |
| `e2e/` | End-to-end tests against a live cluster (marked with `@pytest.mark.e2e`) |
| `conftest.py` | Shared pytest fixtures and module loaders |
| `helpers.py` | Shared helpers (`skip_unless_e2e`, `oracle_job_endpoint`, etc.) |
| `pytest.ini` | Pytest configuration and markers |
| `run_all_tests.sh` | Convenience script to run unit and/or E2E tests |
| `.env` | Local credentials and test settings (**not committed** — create from template below) |

## Prerequisites

From the repository root:

```bash
python3 -m pip install --upgrade pip
python3 -m pip install pytest cohesity-management-sdk
pip install -r requirements.txt
```

E2E tests also require:

- Ansible installed and the collection available on `ANSIBLE_COLLECTIONS_PATH` (or installed via `ansible-galaxy collection install .`)
- Network access to a Cohesity cluster and Oracle source hosts configured in your environment

---

## Configure `tests/.env`

Create `tests/.env` from the template below. This file is listed in `.gitignore` — **never commit credentials**.

Load it before running E2E tests:

```bash
source tests/.env
```

### `.env` template (no values)

Copy this into `tests/.env` and replace each placeholder with your environment details.

```bash
# Cohesity E2E test credentials — DO NOT COMMIT
# Source before E2E: source tests/.env

# --- Required for E2E ---
export COHESITY_E2E=1
export COHESITY_SERVER=<cluster-vip-or-hostname>
export COHESITY_USERNAME=<cluster-username>
export COHESITY_PASSWORD=<cluster-password>
export COHESITY_VALIDATE_CERTS=false

# --- Oracle source type: standalone OR rac (uncomment one block) ---

# Standalone
# export ORACLE_SOURCE_TYPE=standalone
# export ORACLE_ENDPOINT=<standalone-oracle-host>

# RAC
# export ORACLE_SOURCE_TYPE=rac
# export SCAN_VIP_ADDRESS=<scan-or-vip-address>
# export RAC_ENDPOINT=<reachable-rac-host>   # optional

# --- Job E2E settings (optional — defaults shown) ---
export ORACLE_JOB_NAME=<protection-job-name>
export ORACLE_JOB_POLICY=<protection-policy-name>
export ORACLE_STORAGE_DOMAIN=<storage-domain-name>

# --- Restore E2E settings (optional — defaults shown) ---
export ORACLE_SOURCE_DB=<source-database-name>
export ORACLE_TARGET_DB=<target-database-name>
export ORACLE_TARGET_SERVER=<target-oracle-host>
export ORACLE_HOME=<oracle-home-path>
export ORACLE_BASE=<oracle-base-path>
export ORACLE_DATA=<oracle-data-path>
```

### Environment variable reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `COHESITY_E2E` | E2E only | — | Set to `1`, `true`, or `yes` to enable E2E tests |
| `COHESITY_SERVER` | E2E only | — | Cohesity cluster VIP or hostname |
| `COHESITY_USERNAME` | E2E only | `admin` | Cluster login username |
| `COHESITY_PASSWORD` | E2E only | — | Cluster login password |
| `COHESITY_VALIDATE_CERTS` | No | `false` | Set to `true` to validate TLS certificates |
| `ORACLE_SOURCE_TYPE` | E2E only | `standalone` | `standalone` or `rac` — controls which E2E tests run |
| `ORACLE_ENDPOINT` | Standalone E2E | — | Hostname/IP of standalone Oracle server |
| `SCAN_VIP_ADDRESS` | RAC E2E | — | SCAN or VIP address for RAC registration |
| `RAC_ENDPOINT` | No | — | Reachable RAC host (optional for some RAC tests) |
| `RAC_AGENT_NODE` | No | — | Legacy alias for `SCAN_VIP_ADDRESS` |
| `ORACLE_JOB_NAME` | No | `protect_oracle` | Protection job name used in job E2E tests |
| `ORACLE_JOB_POLICY` | No | `Bronze` | Protection policy name |
| `ORACLE_STORAGE_DOMAIN` | No | `DefaultStorageDomain` | Storage domain name |
| `ORACLE_SOURCE_DB` | No | `cdb1` | Source database for restore E2E |
| `ORACLE_TARGET_DB` | No | `cdb2` | Target database for restore E2E |
| `ORACLE_TARGET_SERVER` | No | source server | Target host for restore E2E |
| `ORACLE_HOME` | No | `/u01/app/oracle/product/12.1.0.2/db_1` | Oracle home path |
| `ORACLE_BASE` | No | `/u01/app/oracle` | Oracle base path |
| `ORACLE_DATA` | No | same as `ORACLE_HOME` | Oracle data path |

**Standalone vs RAC:** Set `ORACLE_SOURCE_TYPE` to match your Oracle deployment. Tests that do not apply to the selected type are skipped automatically.

---

## Running tests

All commands below are run from the **repository root**.

### Unit tests only (no cluster)

```bash
./tests/run_all_tests.sh
```

Or directly with pytest:

```bash
python3 -m pytest tests/unit_test/ -v
```

### E2E tests (live cluster)

Load credentials, then run E2E tests for the source type configured in `.env`:

```bash
source tests/.env && python3 -m pytest tests/e2e/ -v -m e2e
```

Run a specific E2E module:

```bash
source tests/.env && python3 -m pytest tests/e2e/cohesity_oracle_source_test.py -v -m e2e
source tests/.env && python3 -m pytest tests/e2e/cohesity_oracle_job_test.py -v -m e2e
source tests/.env && python3 -m pytest tests/e2e/cohesity_oracle_restore_test.py -v -m e2e
```

### Unit + E2E together

```bash
source tests/.env && python3 -m pytest tests/unit_test/ tests/e2e/ -v
```

### Full test suite via script (standalone + RAC)

`run_all_tests.sh --e2e` runs unit tests first, then E2E for **both** standalone and RAC (overriding `ORACLE_SOURCE_TYPE` for each phase). Ensure `ORACLE_ENDPOINT` and `SCAN_VIP_ADDRESS` are set:

```bash
source tests/.env && ./tests/run_all_tests.sh --e2e
```

### Other useful pytest options

```bash
# Run a single test by name
python3 -m pytest tests/unit_test/cohesity_oracle_source_test.py -v -k "test_name_fragment"

# Show skip reasons
python3 -m pytest tests/e2e/ -v -m e2e -rs

# Stop on first failure
python3 -m pytest tests/unit_test/ -v -x
```

---

## Notes

- E2E tests invoke Ansible modules in **`--check` mode**. They validate module behaviour without applying changes on the cluster.
- Without `COHESITY_E2E=1`, E2E tests are **skipped** (not failed).
- Unit tests use mocked SDK clients and do not need network access or credentials.
