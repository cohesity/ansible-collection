.. _cohesity_restore_file_module:


cohesity_restore_file -- Restore Files and Folders from Cohesity Protection Jobs
================================================================================

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


  validate_certs (optional, bool, True)
    Switch determines if SSL Validation should be enabled.


  cohesity_admin (optional, str, None)
    Username with which Ansible will connect to the Cohesity Cluster. Domain Specific credentails

    can be configured in one of two formats - username@domain or Domain/username (will be deprecated in future).


  cohesity_password (optional, str, None)
    Password belonging to the selected Username.  This parameter will not be logged.


  state (optional, str, present)
    Determines the state of the Recovery Job.

    (C)present a recovery job will be created and started.

    (C)absent is currently not implemented


  name (True, str, None)
    Descriptor to assign to the Recovery Job.  The Recovery Job name will consist of the job_name:name format.


  environment (False, str, PhysicalFiles)
    Specifies the environment type (such as PhysicalFiles or Physical or GenericNas) of the Protection Job

    . Supported environment types include 'PhysicalFiles', 'GenericNas'


  job_name (True, str, None)
    Name of the Protection Job


  endpoint (True, str, None)
    Specifies the network endpoint of the Protection Source where it is reachable. It could

    be an URL or hostname or an IP address of the Protection Source or a NAS Share/Export Path.


  backup_id (optional, int, None)
    Optional Cohesity ID to use as source for the Restore operation.  If not selected, the most recent RunId will be used


  file_names (True, list, None)
    Array of Files and Folders to restore


  wait_for_job (optional, bool, True)
    Should wait until the Restore Job completes


  wait_minutes (optional, int, 10)
    Number of minutes to wait until the job completes.


  overwrite (optional, bool, True)
    Should the restore operation overwrite the files or folders if they exist.


  preserve_attributes (optional, bool, True)
    Should the restore operation maintain the original file or folder attributes


  restore_location (optional, str, None)
    Alternate location to which the files will be restored


  backup_timestamp (optional, str, None)
    protection run timestamp in YYYY-MM-DD:HH:MM format to use as source for the Restore operation. If not specified, the most recent timestamp is used





Notes
-----

.. note::
   - File and Folder restores from SMB based backups are currently not supported
   - Currently, the Ansible Module requires Full Cluster Administrator access.




Examples
--------

.. code-block:: yaml+jinja

    
    # Restore a single file from a PhysicalFiles Windows Backup
    - cohesity_restore_file:
        cluster: cohesity.lab
        username: admin
        password: password
        state: present
        name: Restore Single File
        job_name: myhost
        environment: PhysicalFiles
        endpoint: mywindows.host.lab
        file_names:
          - C:\data\big_file
        wait_for_job: no

    # Restore a single file from a GenericNas NFS Backup and wait for the job to complete
    - cohesity_restore_file:
        cluster: cohesity.lab
        username: admin
        password: password
        state: present
        name: Restore Single File to NFS Location
        job_name: mynfs
        environment: GenericNas
        endpoint: mynfs.host.lab:/exports
        file_names:
          - /data
        restore_location: /restore
        wait_for_job: yes

    # Restore multiple files from a specific Physical Windows Backup and wait for up to 10 minutes for the process to complete
    - cohesity_restore_file:
        cluster: cohesity.lab
        username: admin
        password: password
        state: present
        name: Restore Single File
        job_name: myhost
        environment: Physical
        endpoint: mywindows.host.lab
        file_names:
          - C:\data\files
          - C:\data\large_directory
        wait_for_job: yes
        wait_minutes: 10





Status
------





Authors
~~~~~~~

- Naveena (@naveena-maplelabs)

