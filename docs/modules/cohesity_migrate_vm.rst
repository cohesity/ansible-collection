.. _cohesity_migrate_vm_module:


cohesity_migrate_vm -- Migrate one or more Virtual Machines from Cohesity Migrate Jobs
======================================================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Ansible Module used to start a Cohesity Migration Job on a Cohesity Cluster.

When executed in a playbook, the Cohesity migration Job will be validated and the appropriate state action

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

    AD.domain.com/username

    AD.domain.com/username@tenant

    LOCAL/username@tenant


  cohesity_password (optional, str, None)
    Password belonging to the selected Username.  This parameter will not be logged.


  cluster_compute_resource (optional, str, None)
    If the cluster compute resource is specified, VM will be recovered to resource pool under the specified compute resource.


  datacenter (optional, str, None)
    If multiple datastore exists, datacenter and cluster resource details are used to uniquely identify the resourcepool.


  datastore_name (True, str, None)
    Specifies the datastore where the files should be recovered to. This field is required to recover objects to

    a different resource pool or to a different parent source. If not specified, objects are recovered to their original

    datastore locations in the parent source.


  detach_network (optional, bool, False)
    If this is set to true, then the network will be detached from the recovered VMs. All the other networking parameters set will be ignored if set to true


  enable_network (optional, bool, True)
    Specifies whether the attached network should be left in enabled state


  endpoint (True, str, None)
    Specifies the network endpoint of the Protection Source where it is reachable. It could

    be an URL or hostname or an IP address of the Protection Source or a NAS Share/Export Path.


  environment (False, str, VMware)
    Specifies the environment type (such as VMware) of the Protection Source this Job

    is protecting. Supported environment types include 'VMware'


  interface_group_name (optional, str, None)
    Specifies the interface name to connect after restoring the VM.


  name (False, str, None)
    Descriptor to assign to the Recovery Job.  The Recovery Job name will consist of the name_date_time format.


  network_name (optional, str, None)
    Specifies a network name to be attached to the migrated object.


  power_state (optional, bool, True)
    Specifies the power state of the recovered objects. By default, the migrated objects are powered off.


  prefix (optional, str, None)
    Specifies a prefix to prepended to the source object name to derive a new name for the recovered object.


  preserve_mac_address (optional, bool, False)
    Specifies whether to preserve the MAC address of the migrated VM.


  recovery_process_type (optional, str, CopyRecovery)
    Specifies the recovery type.


  resource_pool_name (True, str, None)
    Specifies the resource pool name where the migrated objects are attached.


  state (optional, str, present)
    Determines the state of the Recovery Job.

    (C)present a recovery job will be created and started.

    (C)absent is currently not implemented


  suffix (optional, str, None)
    Specifies a suffix to appended to the original source object name to derive a new name for the migrated object


  vm_folder_name (optional, str, None)
    Specifies a folder name where the VMs should be restored.


  job_vm_pair (True, dict, None)
    Key value pair with job names as key and list of Virtual Machines to migrate


  validate_certs (optional, bool, True)
    Switch determines if SSL Validation should be enabled.





Notes
-----

.. note::
   - Currently, the Ansible Module requires Full Cluster Administrator access.




Examples
--------

.. code-block:: yaml+jinja

    

    # Migrate a single Virtual Machine
    - name: Migrate a Virtual Machine
      cohesity_migrate_vm:
        cluster: cohesity.lab
        username: admin
        password: password
        state: present
        name: "Ansible Test VM Migrate"
        endpoint: "myvcenter.cohesity.demo"
        environment: "VMware"
        job_vm_pair:
          "Backup_job":
            - chs-win-01
            - chs-win-02

    # Migrate multiple Virtual Machines from a specific snapshot with a new prefix and disable the network
    - name: Migrate a Virtual Machine
      cohesity_migrate_vm:
        cluster: cohesity.lab
        username: admin
        password: password
        state: present
        name: "Ansible Test VM Migrate"
        endpoint: "myvcenter.cohesity.demo"
        environment: "VMware"
        job_vm_pair:
          "Backup_job":
            - chs-win-01
            - chs-win-02
          "Protect_VM":
            - chs-ubun-01
            - chs-ubun-02
        prefix: "rst-"






Status
------





Authors
~~~~~~~

- Naveena (@naveena-maplelabs)

