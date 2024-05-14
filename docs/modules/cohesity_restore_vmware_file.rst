.. _cohesity_restore_vmware_file_module:


cohesity_restore_vmware_file -- Restore Files and Folders from Cohesity Protection Jobs
=======================================================================================

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

- python \>= 3.6
- cohesity\_management\_sdk \>= 1.6.0



Parameters
----------

  backup_timestamp (optional, str, )
    protection run timestamp in YYYY-MM-DD:HH:MM format to use as source for the Restore operation. If not specified, the most recent timestamp is used


  cluster (optional, str, None)
    IP or FQDN for the Cohesity Cluster


  cohesity_admin (optional, str, None)
    Username with which Ansible will connect to the Cohesity Cluster. Domain Specific credentails

    can be configured in one of two formats - username@domain or Domain/username (will be deprecated in future).


  cohesity_password (optional, str, None)
    Password belonging to the selected Username.  This parameter will not be logged.


  endpoint (True, str, None)
    Specifies the name of Vcenter where file is located.


  environment (optional, str, VMware)
    Environment type of the restore.


  file_names (True, list, None)
    Array of Files and Folders to restore


  job_name (True, str, None)
    Name of the Protection Job


  name (True, str, None)
    Descriptor to assign to the Recovery Job.  The Recovery Job name will consist of the job\_name:name format.


  overwrite (optional, bool, True)
    Should the restore operation overwrite the files or folders if they exist.


  preserve_attributes (optional, bool, True)
    Should the restore operation maintain the original file or folder attributes


  restore_location (optional, str, )
    Alternate location to which the files will be restored


  state (optional, str, present)
    Determines the state of the Recovery Job.

    (C)present a recovery job will be created and started.

    (C)absent is currently not implemented


  validate_certs (optional, bool, True)
    Switch determines if SSL Validation should be enabled.


  vm_name (optional, str, )
    Name of the Vcenter virtual machine, from where the files are located. Required if the environment is VMware.


  vm_password (optional, str, )
    Password of the virtual machine, where files will be restored. Required if the environment is VMware.


  vm_username (optional, str, )
    Username of the virtual machine, where files will be restored. Required if the environment is VMware.


  wait_for_job (optional, bool, True)
    Should wait until the Restore Job completes


  wait_minutes (optional, int, 10)
    Number of minutes to wait until the job completes.





Notes
-----

.. note::
   - File and Folder restores from SMB based backups are currently not supported
   - Currently, the Ansible Module requires Full Cluster Administrator access.




Examples
--------

.. code-block:: yaml+jinja

    

    # Restore multiple files from a specific VMware Backup and wait for up to 10 minutes for the process to complete
    - cohesity_restore_vmware_file:
        cluster: cohesity.lab
        username: admin
        password: password
        state: present
        name: Restore Single File
        job_name: myhost
        endpoint: myvcenter.host.lab
        file_names:
          - C:\data\files
          - C:\data\large_directory
        vm_name: "demo"
        vm_username: admin
        vm_password: admin
        wait_for_job: yes
        wait_minutes: 10


    # Restore a single file from a VMware VM Backup
    - cohesity_restore_vmware_file:
        name: "Ansible File Restore to Virtual Machine"
        environment: "VMware"
        job_name: "myvm.demo"
        endpoint: "myvcenter.cohesity.demo"
        files:
          - "/home/cohesity/sample"
        wait_for_job: True
        state: "present"
        backup_timestamp: 2021-04-11:21:37
        restore_location: /home/cohesity/
        vm_name: "demo"
        vm_username: admin
        vm_password: admin






Status
------





Authors
~~~~~~~

- Naveena (@naveena-maplelabs)

