<!--
  Title: Cohesity Ansible Collection
  Description: This project provides a Ansible Collection for interacting with the Cohesity DataPlatform
  Author: Cohesity Inc
  -->
# Ansible Collection - cohesity.dataprotect

![](https://github.com/cohesity/ansible-collection/blob/main/docs/assets/images/cohesity_ansible.png)

## Overview
[![License: GNU General Public License v3.0](https://img.shields.io/badge/LICENSE-GPL--v3.0-blue)](https://github.com/cohesity/ansible-collection/blob/main/LICENSE)

This project provides an Ansible Collection for interacting with the [Cohesity DataPlatform](https://www.cohesity.com/products/data-platform).

This Ansible Collection can be used on Windows, Linux or MacOS leveraging Python.

It includes modules, tasks, and example plays useful for automating common tasks and orchestrating workflows in your environment.

This Ansible Collection leverages Cohesity REST API to interact with the Cohesity Cluster.

# Installation
```bash
ansible-galaxy collection install cohesity.dataprotect
```
To use this collection, add the following to the top of your playbook:
```
collections:
  - cohesity.dataprotect
```
# Requirements
- ansible-core version >= 2.16.0
- requests >= 2.31.0
- python version >= '3.6'
- cohesity_management_sdk >= 1.6.0

To install the requirements, run **pip install -r [requirement.txt](https://github.com/cohesity/ansible-collection/blob/main/requirements.txt)**

## Table of contents

 - [Getting Started](https://github.com/cohesity/ansible-collection/blob/main/README.md#get-started)
 - [More samples playbooks](https://github.com/cohesity/ansible-collection/blob/main/README.md#examples)
 - [Changelog](#changelog)
 - [Support (Red Hat Users)](#support-red-hat-users)
 - [How can you contribute](https://github.com/cohesity/ansible-collection/blob/main/README.md#contribute)
 - [Suggestions and Feedback](https://github.com/cohesity/ansible-collection/blob/main/README.md#suggest)
 - [Disclaimer](#disclaimer)


## <a name="get-started"></a> Let's get started

* [Documentation for Cohesity Ansible Collection](https://github.com/cohesity/ansible-collection/tree/main/docs).

## <a name="examples"></a> Some samples to get you going :bulb:

* Refer [`playbooks`](https://github.com/cohesity/ansible-collection/tree/main/playbooks) folder to find more examples.

## <a name="changelog"></a> Changelog

See [CHANGELOG.rst](https://github.com/cohesity/ansible-collection/blob/main/CHANGELOG.rst) for a full list of changes by version.

**Recent highlights:**

- **v1.4.5** — Added Oracle RAC cluster support (`source_type`, `scan_vip_address` / SCAN/VIP Address) across Oracle source, job, and restore modules; config-driven Oracle workflow playbooks; fixed missing `Content-Type: application/json` headers on REST API calls; added standalone/RAC unit and E2E tests.
- **v1.4.4** — Bumped `requests` minimum version to `>=2.31.0` to address known security vulnerabilities; added Changelog and Support (Red Hat Users) sections to README.
- **v1.4.3** — Fixed agent detection failing with "Cohesity Agent is partially installed" on systemd hosts where the SysV init script is not created by the installer.
- **v1.4.2** — Bumped minimum Ansible-Core version to 2.16; fixed `LiteralPath` issue during Windows agent installation and collection failure issues on some Ansible versions.

## Oracle RAC Workflow

Oracle workflow playbooks under [`playbooks/oracle-workflow/`](playbooks/oracle-workflow/) support both **Standalone** and **RAC** deployments.

**One-time setup:**

```bash
mkdir -p /tmp/ansible_collections/cohesity/dataprotect
cp -r plugins /tmp/ansible_collections/cohesity/dataprotect/
cd playbooks/oracle-workflow
export ANSIBLE_COLLECTIONS_PATH=/tmp/ansible_collections
```

Re-run the `cp -r plugins` step after any module code changes.

Set values in `playbooks/ansible_config.ini` before running playbooks. For RAC, the only required command-line flag is `-e "oracle_source_type=rac"`. To overwrite any config value, pass it with `-e` (command-line takes precedence).

```ini
[workstation]
localhost ansible_connection=local

[workstation:vars]
# SCAN/VIP Address — same label as Cohesity UI (required for RAC)
scan_vip_address=<scan-or-vip>
rac_endpoint=<reachable-host>          # optional
oracle_endpoint=<standalone-host>      # standalone only

[all:vars]
cohesity_server=<cluster-server>
cohesity_username=<cluster-username>
cohesity_password=<cluster-password>
cohesity_validate_certs=False
oracle_job_name=protect_oracle
oracle_job_policy=Bronze
oracle_storage_domain=DefaultStorageDomain
oracle_source_db=db1
oracle_target_db=db1
oracle_task_name=recover_tasks_rac_1
oracle_home=/u01/app/oracle/product/12.1.0.2/db_1
oracle_base=/u01/app/oracle
oracle_data=/u01/app/oracle/product/12.1.0.2/db_1
```

`scan_vip_address` is the **SCAN/VIP Address** from the Cohesity UI (required for RAC). `rac_endpoint` is optional — use when the cluster cannot reach the SCAN/VIP during discovery.

**Register Oracle RAC source (recommended — config file only):**

```bash
ANSIBLE_COLLECTIONS_PATH=/tmp/ansible_collections \
ansible-playbook register_oracle_source.yml \
  -i ../ansible_config.ini \
  -e "oracle_source_type=rac"
```

**Overwrite values on the command line (optional):**

```bash
ansible-playbook register_oracle_source.yml \
  -i ../ansible_config.ini \
  -e "oracle_source_type=rac" \
  -e "scan_vip_address=<scan-or-vip>" \
  -e "rac_endpoint=<reachable-host>"
```

**Refresh source and create protection job:**

```bash
ansible-playbook refresh_oracle_source.yml -i ../ansible_config.ini \
  -e "oracle_source_type=rac"

ansible-playbook create_oracle_job.yml -i ../ansible_config.ini \
  -e "oracle_source_type=rac"

# Protect specific databases only (optional):
ansible-playbook create_oracle_job.yml -i ../ansible_config.ini \
  -e "oracle_source_type=rac" -e 'oracle_databases=["db1"]'
```

**Create job vs run backup (Step 3 vs Step 4):**

`create_oracle_job.yml` **creates** the protection job on the cluster (`state=present`) — policy, storage domain, and which databases to protect. It does **not** run a backup.

After the job exists, use ad-hoc `cohesity_oracle_job` calls with different `state` values on the **same job name**:

| Action | `state` | What it does |
|--------|---------|--------------|
| Start backup | `started` | Triggers an **on-demand backup run** (does not create a new job). |
| Cancel running backup | `stopped` + `cancel_active=true` | Stops the **current backup run**. The protection job remains. |
| Delete protection job | `absent` | Removes the **protection job** from the cluster. Does not unregister the source. |

```bash
# Start on-demand backup
ansible localhost -i ../ansible_config.ini -c local \
  -m cohesity.dataprotect.cohesity_oracle_job \
  -a "cluster=<cluster-server> username=<cluster-username> password=<cluster-password> validate_certs=false state=started name=<oracle_job_name>"

# Cancel a running backup (cancel_active=true is required)
ansible localhost -i ../ansible_config.ini -c local \
  -m cohesity.dataprotect.cohesity_oracle_job \
  -a "cluster=<cluster-server> username=<cluster-username> password=<cluster-password> validate_certs=false state=stopped cancel_active=true name=<oracle_job_name>"

# Delete the protection job
ansible localhost -i ../ansible_config.ini -c local \
  -m cohesity.dataprotect.cohesity_oracle_job \
  -a "cluster=<cluster-server> username=<cluster-username> password=<cluster-password> validate_certs=false state=absent name=<oracle_job_name>"
```

**Recover database:**

```bash
ansible-playbook recover_db.yml -i ../ansible_config.ini \
  -e "oracle_source_type=rac"
```

Edit `ansible_config.ini` for job name, policy, databases, recovery targets, and Oracle paths. See playbook header comments for standalone usage.

**Run tests:**

```bash
# Unit tests (no cluster required)
./tests/run_all_tests.sh

# E2E tests (requires live cluster)
# Option A — set env vars directly
export COHESITY_E2E=1
export COHESITY_SERVER=<cluster-vip>
export COHESITY_PASSWORD=<password>
export ORACLE_ENDPOINT=<standalone-host>        # standalone
export SCAN_VIP_ADDRESS=<scan-or-vip>          # rac
export RAC_ENDPOINT=<reachable-host>             # rac optional
./tests/run_all_tests.sh --e2e

# Option B — use the .env file (recommended, never committed)
# Edit tests/.env with your cluster credentials, then:
source tests/.env && ./tests/run_all_tests.sh --e2e
```

## Support (Red Hat Users)

This collection is part of **Red Hat Ansible Certified Content** and is entitled to support through the [Ansible Automation Platform (AAP)](https://www.redhat.com/en/technologies/management/ansible).

If you are an AAP subscriber, you can open a support case directly from **Ansible Automation Hub**:

1. Navigate to the collection page on [Ansible Automation Hub](https://console.redhat.com/ansible/automation-hub/repo/published/cohesity/dataprotect/).
2. Click the **Create issue** button to file a support ticket with Red Hat.

For issues or feature requests outside of an AAP subscription, use the [GitHub issue tracker](https://github.com/cohesity/ansible-collection/issues/new/choose).

## <a name="contribute"></a> Contribute

* [Refer our contribution guideline](https://github.com/cohesity/ansible-collection/tree/main/CONTRIBUTING.md).

* [Refer our contribution guideline](https://github.com/cohesity/ansible-collection/tree/main/CONTRIBUTING.md).

## <a name="suggest"></a> Suggestions and Feedback

We would love to hear from you. Please send your suggestions and feedback to: [support@cohesity.com](mailto:support@cohesity.com)

## Code of Conduct
This collection follows the [Ansible project's Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html).

## License

GNU General Public License v3.0.

## <a name ="disclaimer"></a> Disclaimer

The scripts, recipes, and integrations provided here are community-contributed or best-effort solutions from Cohesity engineering and ecosystem partners. These resources are not officially supported by Cohesity Support or Field teams.
For production-grade use or enterprise implementation support, please contact Cohesity Professional Services or your account team.
