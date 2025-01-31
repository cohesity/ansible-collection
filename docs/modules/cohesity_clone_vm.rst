.. _cohesity_clone_vm_module:


cohesity_clone_vm -- Management of Cohesity VM Clone
====================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Ansible Module used to clone the Virtual Machine.



Requirements
------------
The below requirements are needed on the host that executes this module.

- python \>= 3.6
- cohesity\_management\_sdk \>= 1.6.0



Parameters
----------

  backup_timestamp (False, str, )
    Option to identify backups based on a timestamp


  cluster (optional, str, None)
    IP or FQDN for the Cohesity Cluster


  cohesity_admin (optional, str, None)
    Username with which Ansible will connect to the Cohesity Cluster. Domain Specific credentails can be configured in following formats

    Formats,

    AD.domain.com/username

    AD.domain.com/username@tenant

    LOCAL/username@tenant


  cohesity_password (optional, str, None)
    Password belonging to the selected Username.  This parameter will not be logged.


  end_timestamp (False, str, )
    Option to identify backups based on a end timestamp


  environment (optional, str, VMware)
    Optional directory path to which the installer will be downloaded.  If not selected, then a temporary

    directory will be created in the default System Temp Directory.  When choosing an alternate directory,

    the directory and installer will not be deleted at the end of the execution.


  job_name (True, str, None)
    Name of the Protection Job


  name (True, str, None)
    Descriptor to assign to the Recovery Job.  The Recovery Job name will consist of the job\_name:name format.


  network_connected (optional, bool, True)
    Specifies whether the network should be left in disabled state. Attached network is enabled by default. Set this flag to true to disable it.


  power_on (optional, bool, True)
    Specifies the power state of the cloned or recovered objects. By default, the cloned or recovered objects are powered off.


  prefix (optional, str, )
    Specifies a prefix to prepended to the source object name to derive a new name for the recovered or cloned object.


  resource_pool (True, str, None)
    Specifies the resource pool where the cloned or recovered objects are attached.


  start_timestamp (False, str, )
    Option to identify backups based on a start timestamp.


  state (optional, str, present)
    Determines if the clone vm should be \ :literal:`present`\  or \ :literal:`absent`\  from the cluster


  suffix (optional, str, )
    Specifies a suffix to appended to the original source object name to derive a new name      for the recovered or cloned object.


  view_name (optional, str, None)
    Name of the view


  vm_names (True, list, None)
    List of virtual machines


  wait_for_job (optional, bool, True)
    Should wait until the Restore Job completes


  wait_minutes (optional, int, 30)
    Number of minutes to wait until the job completes.


  validate_certs (optional, bool, True)
    Switch determines if SSL Validation should be enabled.





Notes
-----

.. note::
   - Currently, the Ansible Module requires Full Cluster Administrator access.




Examples
--------

.. code-block:: yaml+jinja

    

    # Restore a single Virtual Machine
    - name: Restore a Virtual Machine
      cohesity_clone_vm:
        cluster: cohesity.lab
        username: admin
        password: password
        state: present
        name: "Ansible Test VM Restore"
        endpoint: "myvcenter.cohesity.demo"
        environment: "VMware"
        job_name: "myvcenter.cohesity.demo"
        vm_names:
          - chs-win-01

    # Restore multiple Virtual Machines from a specific snapshot with a new prefix and disable the network
    - name: Restore a Virtual Machine
      cohesity_clone_vm:
        cluster: cohesity.lab
        username: admin
        password: password
        state: present
        name: "Ansible Test VM Restore"
        endpoint: "myvcenter.cohesity.demo"
        environment: "VMware"
        job_name: "myvcenter.cohesity.demo"
        backup_id: "48291"
        vm_names:
          - chs-win-01
          - chs-win-02
        prefix: "rst-"
        network_connected: false





Status
------





Authors
~~~~~~~

- Naveena (@naveena-maplelabs)

