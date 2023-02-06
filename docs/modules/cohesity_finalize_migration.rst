.. _cohesity_finalize_migration_module:


cohesity_finalize_migration -- Finalize the VM migration
========================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Ansible Module used to finalize a Cohesity Migration Job on a Cohesity Cluster.

When executed in a playbook, the Cohesity migration Job will be finalized.



Requirements
------------
The below requirements are needed on the host that executes this module.

- python >= 3.6
- cohesity_management_sdk >= 1.6.0



Parameters
----------

  task_id (optional, str, None)
    Task Id of the migrate job.


  cluster (optional, str, None)
    IP or FQDN for the Cohesity Cluster


  cohesity_admin (optional, str, None)
    Username with which Ansible will connect to the Cohesity Cluster. Domain Specific credentails can be configured in following formats

    AD.domain.com/username

    AD.domain.com/username@tenant

    LOCAL/username@tenant


  cohesity_password (optional, str, None)
    Password belonging to the selected Username.  This parameter will not be logged.


  state (optional, str, present)
    Determines the state of the Recovery Job.

    (C)present a recovery job will be created and started.

    (C)absent is currently not implemented


  task_name (optional, str, None)
    Name of the recovery task name.


  validate_certs (optional, bool, True)
    Switch determines if SSL Validation should be enabled.





Notes
-----

.. note::
   - Currently, the Ansible Module requires Full Cluster Administrator access.




Examples
--------

.. code-block:: yaml+jinja

    

    # Finalize migration.
    - name: Finalize a Virtual Machine Migration
      cohesity_finalize_migration:
        cluster: cohesity.lab
        username: admin
        password: password
        state: present
        task_id: "1755745655068243:1672666992780:11012"






Status
------





Authors
~~~~~~~

- Naveena (@naveena-maplelabs)

