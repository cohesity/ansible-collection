.. _cohesity_migration_status_module:


cohesity_migration_status -- Check Sync status of objects available in the VM migration task
============================================================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Ansible Module used to poll for status of objects in a Cohesity Migration Job

When executed in a playbook, the insync sttaus of objects in Cohesity migration Job will be returned.



Requirements
------------
The below requirements are needed on the host that executes this module.

- python \>= 3.6
- cohesity\_management\_sdk \>= 1.6.0



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


  start_time (optional, str, None)
    Restore tasks will be filtered by a start time specified. If not provided the start time is set to the last week. Provide value as "origin" for using cluster creation date.


  end_time (optional, str, None)
    Restore tasks will be filtered by a start time specified. If not provided the end time is the current time.


  validate_certs (optional, bool, True)
    Switch determines if SSL Validation should be enabled.





Notes
-----

.. note::
   - Currently, the Ansible Module requires Full Cluster Administrator access.




Examples
--------

.. code-block:: yaml+jinja

    

    # Poll migration status
    - name: Get status in the VM migration task
      cohesity_migration_status:
        cluster: cohesity.lab
        username: admin
        password: password
        state: present
        task_id: "2520974734107749:1675035602065:2559"





Status
------





Authors
~~~~~~~

- Naveena (@naveena-maplelabs)

