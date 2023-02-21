# VMware Migration Sample Playbooks

Refer the Cohesity Ansible playbook Documentation here. The documentation covers vm migration tasks for all the modules and some sample playbooks to get started.

## Table of contents

 - [Create Migration](https://github.com/cohesity/ansible-collection/blob/main/playbooks/vmware-workflow/migration/README.md#create-migration)
 - [Cancel Migration](https://github.com/cohesity/ansible-collection/blob/main/playbooks/vmware-workflow/migration/README.md#cancel-migration)
 - [Poll for Migration](https://github.com/cohesity/ansible-collection/blob/main/playbooks/vmware-workflow/migration/README.md#poll-migration)
 - [Finalise Migration](https://github.com/cohesity/ansible-collection/blob/main/playbooks/vmware-workflow/migration/README.md#finalise-migration)

## <a name="create-migration"></a> Create Migration

1) List of supported parameters while creating a cohesity migrate job [here](https://github.com/cohesity/ansible-collection/blob/main/docs/modules/cohesity_migrate_vm.rst)
2) Once the migration task is created, user can check for the task status usinf task id.

* [Refer sample playbook to create a migration task.](https://github.com/cohesity/ansible-collection/blob/main/playbooks/vmware-workflow/migration/create_vm_migration.yml).
* [Refer sample playbook to create a migration task and poll for status](https://github.com/cohesity/ansible-collection/blob/main/playbooks/vmware-workflow/migration/migrate_task.yml).

## <a name="poll-migration"></a>Poll for Migration

1) Based on the task Id returned while creating migrate task, poll for migrate task status.
2) In the response list of total_vms, sync_vms and in case of errors list of 'errors' will be returned.

* [Refer sample playbook to Poll for a migration task status.](https://github.com/cohesity/ansible-collection/blob/main/playbooks/vmware-workflow/migration/get_migration_status.yml#poll-migration)
* Sample Response
  ![image](https://user-images.githubusercontent.com/62049303/220300735-5b3f1881-6c84-48ea-a888-ff46bf6d263e.png)

## <a name="cancel-migration"></a> Cancel Migration

1) Based on the task Id and migrate task status, User can cancel the task based on total_vms and sync_vms.

* [Refer sample playbook to cancel a migration task.](https://github.com/cohesity/ansible-collection/blob/main/playbooks/vmware-workflow/migration/cancel_migration.yml#cancel-migration)

## <a name="finalise-migration"></a> Finalise Migration

1) Based on the task Id and migrate task status, User can finalise the task based on total_vms and sync_vms.

* [Refer sample playbook to finalise a migration task.](https://github.com/cohesity/ansible-collection/blob/main/playbooks/vmware-workflow/migration/finalize_migration.yml#finalise-migration)
