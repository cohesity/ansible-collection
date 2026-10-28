.. _ansible_collections.cohesity.dataprotect.docsite.guide_inventory:

Configure your Ansible inventory
================================

The example playbooks in the collection are designed to work with the Ansible inventory to streamline the
process of deploying an entire solution. The inventory is a collection of hosts and variables that controls how
connections are made.

What is an inventory file?
--------------------------

Ansible works against multiple systems in your infrastructure at the same time. It does this by selecting
portions of the systems listed in the inventory. You can specify an inventory file with the ``-i <path>`` option
on the command line.

For more details, see
`Working with inventory <https://docs.ansible.com/projects/ansible/latest/inventory_guide/intro_inventory.html>`_
in the Ansible documentation.

Special note about Windows hosts
--------------------------------

By default, Ansible uses Python and SSH to communicate. This collection is written to be used from a Linux based
workstation. The :ansplugin:`cohesity.dataprotect.cohesity_win_agent#module` module is the exception: it installs
the Cohesity Agent on physical Windows servers using WinRM and PowerShell. To connect to Windows hosts, see
`Setting up a Windows host <https://docs.ansible.com/projects/ansible/latest/os_guide/windows_setup.html>`_.

Required components
-------------------

The following table lists the settings that the example playbooks expect.

.. list-table::
   :header-rows: 1
   :widths: 20 45 35

   * - Key name
     - Description
     - Usage
   * - ``[workstation]``
     - Required. A single host from which calls to the Cohesity cluster are made. This can be your local machine
       or a remote Linux workstation.
     - If local, use the ``ansible_connection=local`` option to prevent SSH calls.
   * - ``[physical:children]``
     - Collection of groups to include in all physical environment actions.
     - A collection of other groups, for example ``linux`` and ``windows``.
   * - ``[group_name]``
     - Organized by platform, operating system, or any other common characteristic. If the name of the server
       does not resolve, add ``ansible_host=IP`` to handle the registration.
     - If each item needs different values, include the supported inventory options on that item.
   * - ``[group_name:vars]``
     - Variables belonging to the named group, such as default authentication settings.
     - A variable set on an item in ``[group_name]`` overrides the value in this section.
   * - ``[vmware]``
     - Inventory name followed by ``ansible_host`` set to the vCenter IP for managed VMware endpoints.
     - If the inventory name is resolvable, ``ansible_host`` is not required.
   * - ``[vmware:vars]``
     - Variables required for VMware environment management.
     - ``type=VMware``, ``vmware_type=VCenter``, ``source_username``, ``source_password``.
   * - ``[generic_nas]``
     - Inventory name followed by ``endpoint`` set to the path of the managed GenericNas endpoint.
     - Backslashes in Windows shares must be escaped, for example ``\\\\windows_host\\share_name``.
   * - ``[generic_nas:vars]``
     - Variables required for GenericNas environment management.
     - ``type=GenericNas``, ``nas_protocol=SMB``, ``nas_username``, ``nas_password``.

Example inventory file
----------------------

.. code-block:: ini

    # Workstation declaration, which is also included in the backup.
    [workstation]
    control ansible_connection=local ansible_host=192.168.1.1 type=Linux

    [centos]
    centos6 ansible_host=192.168.1.1
    centos7 ansible_host=192.168.1.2

    # Default variables for all CentOS environments.
    [centos:vars]
    type=Linux
    ansible_user=root
    ansible_become=False

    # Grouping of all Linux hosts.
    [linux:children]
    centos
    workstation

    # Physical Windows servers.
    [windows]
    windows12 ansible_host=192.168.1.1
    windows16 ansible_host=192.168.1.2

    # Windows variables for each Windows server.
    [windows:vars]
    type=Windows
    install_type=volcbt
    reboot_after_install=True
    ansible_user=administrator
    ansible_password=password
    ansible_port=5986
    ansible_connection=winrm
    ansible_winrm_server_cert_validation=ignore

    # Group all physical servers. This grouping is used by the example
    # playbooks to identify physical servers.
    [physical:children]
    linux
    windows

    # Declare the VMware environments to manage.
    [vmware]
    vcenter01 ansible_host=192.168.1.1

    [vmware:vars]
    type=VMware
    vmware_type=VCenter
    source_username=administrator
    source_password=password

    # Declare the GenericNas endpoints to manage.
    [generic_nas]
    export_path endpoint="192.168.1.1:/export_path" nas_protocol=NFS
    nas_share endpoint="\\\\192.168.1.1\\nas_share"
    data endpoint="\\\\192.168.1.1\\data"

    # Default variables for GenericNas endpoints.
    [generic_nas:vars]
    type=GenericNas
    nas_protocol=SMB
    nas_username=.\cohesity
    nas_password=password

.. warning::

    The example above uses plain text passwords for illustration only. Use Ansible Vault or another secrets
    mechanism for real credentials.
