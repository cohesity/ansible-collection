# Oracle Workflow

Ansible playbooks for protecting and recovering **Oracle Standalone** and **Oracle RAC** databases with Cohesity DataProtect.

## Directory layout

| File | Description |
|------|-------------|
| `register_oracle_source.yml` | Register an Oracle source on the Cohesity cluster |
| `refresh_oracle_source.yml` | Refresh source metadata after registration |
| `create_oracle_job.yml` | Create a protection job (policy, storage domain, databases) |
| `recover_db.yml` | Recover an Oracle database from backup |
| `../ansible_config.ini` | Shared inventory and variables for all Oracle playbooks |
| `Oracle Protection Job Guide.pdf` / `.html` | Step-by-step protection job guide |
| `Oracle RAC Commands.pdf` / `.html` | RAC command reference |

## Prerequisites

- Ansible-core >= 2.16.0
- Cohesity collection installed or available on `ANSIBLE_COLLECTIONS_PATH`
- Network access from the Ansible control node to the Cohesity cluster and Oracle hosts
- Cohesity Agent installed on Oracle database servers

Install Python dependencies from the repository root:

```bash
pip install -r requirements.txt
```

---

## One-time setup

When developing or testing local module changes, point Ansible at the collection source:

```bash
mkdir -p /tmp/ansible_collections/cohesity/dataprotect
cp -r plugins /tmp/ansible_collections/cohesity/dataprotect/
cd playbooks/oracle-workflow
export ANSIBLE_COLLECTIONS_PATH=/tmp/ansible_collections
```

Re-run the `cp -r plugins` step after any module code changes.

If the collection is installed via Galaxy, skip the above and run playbooks from this directory:

```bash
cd playbooks/oracle-workflow
```

---

## Configure `ansible_config.ini`

Edit `playbooks/ansible_config.ini` before running playbooks. Command-line `-e` values override the config file.

### Config template (no values)

```ini
[workstation]
localhost ansible_connection=local

[workstation:vars]
# SCAN/VIP Address — same label as Cohesity UI (required for RAC)
scan_vip_address=<scan-or-vip>
rac_endpoint=<reachable-host>          # optional
oracle_endpoint=<standalone-host>    # standalone only

[all:vars]
cohesity_server=<cluster-server>
cohesity_username=<cluster-username>
cohesity_password=<cluster-password>
cohesity_validate_certs=False
oracle_job_name=<protection-job-name>
oracle_job_policy=<protection-policy-name>
oracle_storage_domain=<storage-domain-name>
oracle_source_db=<source-database-name>
oracle_target_db=<target-database-name>
oracle_task_name=<recovery-task-name>
oracle_home=<oracle-home-path>
oracle_base=<oracle-base-path>
oracle_data=<oracle-data-path>
```

### Key variables

| Variable | Standalone | RAC | Description |
|----------|------------|-----|-------------|
| `oracle_endpoint` | Required | — | Hostname/IP of standalone Oracle server |
| `scan_vip_address` | — | Required | SCAN/VIP Address from the Cohesity UI |
| `rac_endpoint` | — | Optional | Reachable RAC host when cluster cannot reach SCAN/VIP during discovery |
| `oracle_source_type` | `standalone` (default) | `rac` | Set via `-e` on the command line |
| `cohesity_server` | Required | Required | Cohesity cluster VIP or hostname |
| `oracle_job_name` | Optional | Optional | Protection job name (default in playbooks: `protect_oracle`) |
| `oracle_job_policy` | Optional | Optional | Protection policy name |
| `oracle_storage_domain` | Optional | Optional | Storage domain name |

---

## Workflow steps

All commands below assume you are in `playbooks/oracle-workflow/` and use `-i ../ansible_config.ini`.

### Step 1 — Register Oracle source

**Standalone (default):**

```bash
ansible-playbook register_oracle_source.yml -i ../ansible_config.ini
```

**RAC:**

```bash
ansible-playbook register_oracle_source.yml -i ../ansible_config.ini \
  -e "oracle_source_type=rac"
```

**Override config values on the command line (optional):**

```bash
ansible-playbook register_oracle_source.yml -i ../ansible_config.ini \
  -e "oracle_source_type=rac" \
  -e "scan_vip_address=<scan-or-vip>" \
  -e "rac_endpoint=<reachable-host>"
```

### Step 2 — Refresh source

**Standalone:**

```bash
ansible-playbook refresh_oracle_source.yml -i ../ansible_config.ini
```

**RAC:**

```bash
ansible-playbook refresh_oracle_source.yml -i ../ansible_config.ini \
  -e "oracle_source_type=rac"
```

### Step 3 — Create protection job

`create_oracle_job.yml` **creates** the protection job on the cluster (`state=present`) — policy, storage domain, and which databases to protect. It does **not** run a backup.

**Standalone:**

```bash
ansible-playbook create_oracle_job.yml -i ../ansible_config.ini
```

**RAC:**

```bash
ansible-playbook create_oracle_job.yml -i ../ansible_config.ini \
  -e "oracle_source_type=rac"
```

**Protect specific databases only (optional):**

```bash
ansible-playbook create_oracle_job.yml -i ../ansible_config.ini \
  -e "oracle_source_type=rac" -e 'oracle_databases=["db1"]'
```

### Step 4 — Run, cancel, or delete backup jobs

After the protection job exists, use ad-hoc `cohesity_oracle_job` calls with different `state` values on the **same job name**:

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

### Step 5 — Recover database

**Standalone:**

```bash
ansible-playbook recover_db.yml -i ../ansible_config.ini
```

**RAC:**

```bash
ansible-playbook recover_db.yml -i ../ansible_config.ini \
  -e "oracle_source_type=rac"
```

Edit `ansible_config.ini` for job name, policy, databases, recovery targets, and Oracle paths. See playbook header comments in each `.yml` file for additional options.

---

## Testing

Oracle module unit and E2E tests live under `tests/`. See [tests/README.md](../../tests/README.md) for `.env` setup and run commands.

---

## Additional guides

- [Oracle Protection Job Guide](Oracle%20Protection%20Job%20Guide.pdf) — detailed protection job walkthrough
- [Oracle RAC Commands](Oracle%20RAC%20Commands.pdf) — RAC-specific command reference
