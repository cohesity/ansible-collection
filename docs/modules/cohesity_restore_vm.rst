.. _cohesity_restore_vm_module:


cohesity_restore_vm -- Restore one or more Virtual Machines from Cohesity Protection Jobs
=========================================================================================

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

  backup_id (optional, int, None)
    Optional Cohesity ID to use as source for the Restore operation.  If not selected, the most recent RunId will be used


  backup_timestamp (optional, str, None)
    Future option to identify backups based on a timestamp

    Currently not implemented.


  cluster (optional, str, None)
    IP or FQDN for the Cohesity Cluster


  cohesity_admin (optional, str, None)
    Username with which Ansible will connect to the Cohesity Cluster. Domain Specific credentails can be configured in following formats

    AD.domain.com/username

    AD.domain.com/username@tenant

    LOCAL/username@tenant


  cohesity_password (optional, str, None)
    Password belonging to the selected Username.  This parameter will not be logged.


  datastore_folder_id (optional, int, None)
    Specifies the folder where the restore datastore should be created. This is applicable only when the VMs are being cloned.


  datastore_id (optional, int, None)
    Specifies the datastore Id where the files should be recovered to. This field is required to recover objects to

    a different resource pool or to a different parent source. If not specified, objects are recovered to their original

    datastore locations in the parent source.


  cluster_compute_resource (optional, str, None)
    If the cluster compute resource is specified, VM will be recovered to resource pool under the specified compute resource.


  datacenter (optional, str, None)
    If multiple datastore exists, datacenter and cluster resource details are used to uniquely identify the resourcepool.


  datastore_name (optional, str, None)
    Specifies the datastore where the files should be recovered to. This field is required to recover objects to

    a different resource pool or to a different parent source. If not specified, objects are recovered to their original

    datastore locations in the parent source.


  endpoint (True, str, None)
    Specifies the network endpoint of the Protection Source where it is reachable. It could

    be an URL or hostname or an IP address of the VMware Protection Source.


  environment (False, str, VMware)
    Specifies the environment type (such as VMware) of the Protection Source this Job

    is protecting. Supported environment types include 'VMware'


  interface_group_name (optional, str, None)
    Specifies the interface name to connect after restoring the VM.


  job_name (False, str, None)
    Name of the Protection Job


  name (True, str, None)
    Descriptor to assign to the Recovery Job.  The Recovery Job name will consist of the job_name:name format.


  network_connected (optional, bool, True)
    Specifies whether the network should be left in disabled state. Attached network is enabled by default. Set this flag to true to disable it.


  network_id (optional, int, None)
    Specifies a network configuration to be attached to the cloned or recovered object. Specify this field to override

    the preserved network configuration or to attach a new network configuration to the cloned or recovered objects. You can

    get the networkId of the kNetwork object by setting includeNetworks to 'true' in the GET /public/protectionSources operation.

    In the response, get the id of the desired kNetwork object, the resource pool, and the registered parent Protection Source.


  network_name (optional, str, None)
    Specifies a network name to be attached to the cloned or recovered object.


  power_state (optional, bool, True)
    Specifies the power state of the cloned or recovered objects. By default, the cloned or recovered objects are powered off.


  prefix (optional, str, None)
    Specifies a prefix to prepended to the source object name to derive a new name for the recovered or cloned object.


  recovery_process_type (optional, str, InstantRecovery)
    Specifies the recovery type.


  resource_pool_id (optional, int, None)
    Specifies the resource pool Id where the cloned or recovered objects are attached.


  resource_pool_name (optional, str, None)
    Specifies the resource pool name where the cloned or recovered objects are attached.


  restore_to_source (optional, bool, None)
    Switch determines if VM is restored to original source.


  state (optional, str, present)
    Determines the state of the Recovery Job.

    (C)present a recovery job will be created and started.

    (C)absent is currently not implemented


  suffix (optional, str, None)
    Specifies a suffix to appended to the original source object name to derive a new name for the recovered or cloned object


  vm_folder_id (optional, int, None)
    Specifies a folder Id where the VMs should be restored.


  vm_folder_name (optional, str, None)
    Specifies a folder name where the VMs should be restored.


  vm_names (False, list, None)
    Array of Virtual Machines to restore


  wait_for_job (optional, bool, True)
    Should wait until the Restore Job completes


  wait_minutes (optional, int, 20)
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
      cohesity_restore_vm:
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
      cohesity_restore_vm:
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
        network_connected: no






Status
------





Authors
~~~~~~~

- Naveena (@naveena-maplelabs)

