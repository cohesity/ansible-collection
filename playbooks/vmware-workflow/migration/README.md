# VMware Migration Sample Playbooks

Refer the Cohesity Ansible playbook Documentation here. The documentation covers vm migration tasks for all the modules and some sample playbooks to get started.

## Table of contents

 - [Create Migration](#create-migration)
 - [Cancel Migration](#cancel-migration)
 - [Poll for Migration](#poll-migration)
 - [Finalise Migration](#finalise-migration)

## <a name="create-migration"></a> Create Migration

1) List of supported parameters while creating a cohesity migrate job [here](https://galaxy.ansible.com/ui/repo/published/cohesity/dataprotect/docs/cohesity_migrate_vm_module.html)
2) Once the migration task is created, user can check for the task status usinf task id.

* [Refer sample playbook to create a migration task.](create_vm_migration.yml)
* [Refer sample playbook to create a migration task and poll for status](migrate_task.yml)

## <a name="poll-migration"></a>Poll for Migration

1) Based on the task Id returned while creating migrate task, poll for migrate task status.
2) In the response list of total_vms, sync_vms and in case of errors list of 'errors' will be returned.

* [Refer sample playbook to Poll for a migration task status.](get_migration_status.yml)

## <a name="cancel-migration"></a> Cancel Migration

1) Based on the task Id and migrate task status, User can cancel the task based on total_vms and sync_vms.

* [Refer sample playbook to cancel a migration task.](cancel_migration.yml)

## <a name="finalise-migration"></a> Finalise Migration

1) Based on the task Id and migrate task status, User can finalise the task based on total_vms and sync_vms.

* [Refer sample playbook to finalise a migration task.](finalize_migration.yml)