.. _cohesity_oracle_restore_module:


cohesity_oracle_restore -- Restore one or more Virtual Machines from Cohesity Protection Jobs
=============================================================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Ansible Module used to start a Cohesity Recovery Job on a Cohesity Cluster.

When executed in a playbook, the Cohesity Recovery Job will be validated and the appropriate state action

will be applied.



Requirements
------------
The below requirements are needed on the host that executes this module.

- python >= 3.6
- cohesity_management_sdk >= 1.6.0



Parameters
----------

  cluster (optional, str, None)
    IP or FQDN for the Cohesity Cluster


  cohesity_admin (optional, str, None)
    Username with which Ansible will connect to the Cohesity Cluster. Domain Specific credentails can be configured in following formats

    username@AD.domain.com

    AD.domain.com/username@tenant

    LOCAL/username@tenant

    Domain/username (Will be deprecated in future)


  cohesity_password (optional, str, None)
    Password belonging to the selected Username.  This parameter will not be logged.


  state (optional, str, present)
    Determines if the oracle recovery should be ``present`` or ``absent``.

    absent is currently not implemented.


  audit_path (optional, str, )
    Yet to be implemented.


  bct_file (optional, str, )
    Yet to be implemented.


  channels (False, str, None)
    Yet to be implemented.


  clone_app_view (optional, bool, False)
    Enabling this option will clone app view.


  control_file (optional, str, )
    Yet to be implemented.


  diag_path (optional, str, )
    Yet to be implemented.


  fra_path (optional, str, )
    Fra Path.  Yet to be implemented.


  fra_size_mb (optional, int, 2048)
    Specifies the Fra size Mb.


  log_time (optional, str, )
    Log Time. Yet to be implemented.


  no_recovery (optional, bool, False)
    No recovery. Yet to be implemented.


  oracle_base (True, str, None)
    Specifies the oracle base directory.


  oracle_data (True, str, None)
    Oracle Data. Yet to be implemented.


  oracle_home (True, str, None)
    Specifies the Oracle home directory path.


  overwrite (optional, bool, False)
    Enabling this option will overwrite the database, if already available.


  redo_log_path (optional, str, )
    Redo Log Path. Yet to be implemented.


  source_db (True, str, None)
    Specifies the name of the database which needs to be recovered.


  source_server (True, str, None)
    Specifies the source server name where database is located.


  target_db (True, str, None)
    Specifies the name of the target database that will be restored.

    If the database is not already available new database will be created.


  target_server (True, str, None)
    Specifies the oracle server where database is restored.


  task_name (optional, str, None)
    Specifies the restore task name


  validate_certs (optional, bool, True)
    Switch determines if SSL Validation should be enabled.





Notes
-----

.. note::
   - Currently, the Ansible Module requires Full Cluster Administrator access.




Examples
--------

.. code-block:: yaml+jinja

    
    # Restore Oracle database.
    - name: Restore Oracle database.
      cohesity_oracle:
        source_db: cdb1
        task_name: recover_tasks
        view_name: xyz
        source_server: "10.2.103.113"
        target_server: "10.2.103.113"
        target_db: cdb2
        oracle_home: /u01/app/oracle/product/12.1.0.2/db_1
        oracle_base: /u01/app/oracle
        oracle_data: /u01/app/oracle/product/12.1.0.2/db_1






Status
------





Authors
~~~~~~~

- Naveena (@naveena-maplelabs)

