.. _ansible_collections.cohesity.dataprotect.docsite.guide_vmware_migration:

Migrate VMware virtual machines
===============================

This guide describes the VM migration workflow: create a migration task, poll its status, then either finalize
or cancel it. The example playbooks are in the
`migration directory <https://github.com/cohesity/ansible-collection/tree/main/playbooks/vmware-workflow/migration>`_
of the repository.

All examples assume that the cluster address and credentials are provided as the variables ``cohesity_server``,
``cohesity_username``, ``cohesity_password`` and ``cohesity_validate_certs``.

Workflow
--------

#. Create the migration task with :ansplugin:`cohesity.dataprotect.cohesity_migrate_vm#module`. The module
   returns the task ID.
#. Poll the task with :ansplugin:`cohesity.dataprotect.cohesity_migration_status#module` using that task ID. The
   response includes the total number of VMs, the number of VMs in sync, and a list of errors if any occurred.
#. Based on the status, finalize the migration with
   :ansplugin:`cohesity.dataprotect.cohesity_finalize_migration#module` or cancel it with
   :ansplugin:`cohesity.dataprotect.cohesity_cancel_migration#module`.

Create a migration task
-----------------------

.. code-block:: yaml

    - name: Create a migration task
      cohesity.dataprotect.cohesity_migrate_vm:
        cluster: "{{ cohesity_server }}"
        username: "{{ cohesity_username }}"
        password: "{{ cohesity_password }}"
        validate_certs: "{{ cohesity_validate_certs }}"
        name: "Testing"
        job_vm_pair:
          job_name_1:
            - VM1
          job_name_2:
            - VM2
            - VM3
        state: present
        datacenter: Datacenter
        cluster_compute_resource: Cluster1
        network_name: VLAN
        preserve_mac_address: true
        enable_network: false
        vm_folder_name: cohesity_folder
        resource_pool_name: resource_pool
        datastore_name: datastore_name
        endpoint: vcenter.domain.com
        detach_network: false
        suffix: "_1"
        prefix: "copy_"
      register: task

Poll for the migration status
-----------------------------

.. code-block:: yaml

    - name: Poll for migration status of VMs
      cohesity.dataprotect.cohesity_migration_status:
        cluster: "{{ cohesity_server }}"
        username: "{{ cohesity_username }}"
        password: "{{ cohesity_password }}"
        validate_certs: "{{ cohesity_validate_certs }}"
        task_id: "{{ task.id }}"
      register: job_result
      until: job_result.status in ['Succeeded', 'Canceled', 'Failed', 'OnHold']
      retries: 20
      delay: 30

Finalize or cancel the migration
--------------------------------

Finalize the task when the objects are in sync, or cancel it when too few objects synchronized. The
``migrate_task.yml`` example playbook shows how to combine the three steps with ``when`` conditions based on the
``sync_vms`` and ``total_vms`` values from the status response.

.. code-block:: yaml

    - name: Finalize the migration
      cohesity.dataprotect.cohesity_finalize_migration:
        cluster: "{{ cohesity_server }}"
        username: "{{ cohesity_username }}"
        password: "{{ cohesity_password }}"
        validate_certs: "{{ cohesity_validate_certs }}"
        task_id: "{{ task.id }}"

    - name: Cancel the migration
      cohesity.dataprotect.cohesity_cancel_migration:
        cluster: "{{ cohesity_server }}"
        username: "{{ cohesity_username }}"
        password: "{{ cohesity_password }}"
        validate_certs: "{{ cohesity_validate_certs }}"
        task_id: "{{ task.id }}"

Related modules
---------------

* :ansplugin:`cohesity.dataprotect.cohesity_migrate_vm#module`
* :ansplugin:`cohesity.dataprotect.cohesity_migration_status#module`
* :ansplugin:`cohesity.dataprotect.cohesity_finalize_migration#module`
* :ansplugin:`cohesity.dataprotect.cohesity_cancel_migration#module`
* :ansplugin:`cohesity.dataprotect.cohesity_sync_objects#module`
