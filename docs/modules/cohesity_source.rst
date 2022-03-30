.. _cohesity_source_module:


cohesity_source -- Management of Cohesity Protection Sources
============================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Ansible Module used to register or remove the Cohesity Protection Sources to/from a Cohesity Cluster.

When executed in a playbook, the Cohesity Protection Source will be validated and the appropriate

state action will be applied.



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


  endpoint (True, str, None)
    Specifies the network endpoint of the Protection Source where it is reachable. It could

    be an URL or hostname or an IP address of the Protection Source or a NAS Share/Export Path.


  environment (False, str, Physical)
    Specifies the environment type (such as VMware or SQL) of the Protection Source this Job

    is protecting. Supported environment types include 'Physical', 'VMware', 'GenericNas'


  force_register (optional, bool, False)
    Enabling this option will force the registration of the Cohesity Protection Source.


  host_type (optional, str, Linux)
    Specifies the optional OS type of the Protection Source (such as ``Windows`` or ``Linux``).

    ``Linux`` indicates the Linux operating system.

    ``Windows`` indicates the Microsoft Windows operating system.

    ``Aix`` indicates the IBM AIX operating system.

    Optional when *state=present* and *environment=Physical*.


  nas_password (optional, str, None)
    Specifies the password to accessthe target NAS Environment.

    This parameter will not be logged.

    Required when *state=present* and *environment=GenericNas* and *nas_protocol=SMB*


  nas_protocol (optional, str, NFS)
    Specifies the protocol type of connection for the NAS Mountpoint.

    SMB Share paths must be in \\server\share format.

    Required when *state=present* and *environment=GenericNas*


  nas_type (optional, str, Host)
    Specifies the type of connection for the NAS Mountpoint.


  nas_username (optional, str, None)
    Specifies username to access the target NAS Environment.

    Supported Format is Username or username@domain or Domain/username (will be deprecated in future).

    Required when *state=present* and *environment=GenericNas* and *nas_protocol=SMB*


  physical_type (optional, str, Host)
    Specifies the entity type such as ``Host`` if the *environment=Physical*.

    ``Host`` indicates a single physical server.

    ``WindowsCluster`` indicates a Microsoft Windows cluster.

    Optional when *state=present* and *environment=Physical*.


  skip_validation (optional, bool, False)
    Switch for source validation during registeration.


  source_password (optional, str, None)
    Specifies the password to access the target source.

    This parameter will not be logged.

    Required when *state=present* and *environment=VMware*


  source_username (optional, str, None)
    Specifies username to access the target source.

    Required when *state=present* and *environment=VMware*


  state (optional, str, present)
    Determines the state of the Protection Source


  update_source (optional, bool, False)
    Switch determines whether to update the existing source.


  validate_certs (optional, bool, True)
    Switch determines if SSL Validation should be enabled.


  vmware_type (optional, str, VCenter)
    Specifies the entity type such as ``VCenter`` if the environment is ``VMware``.





Notes
-----

.. note::
   - Currently, the Ansible Module requires Full Cluster Administrator access.




Examples
--------

.. code-block:: yaml+jinja

    
    # Register a Physical Cohesity Protection Source on a selected Linux endpoint using Defaults
    - cohesity_source:
        server: cohesity.lab
        username: admin
        password: password
        endpoint: mylinux.host.lab
        state: present

    # Register a Physical Cohesity Protection Source on a selected Windows endpoint
    - cohesity_source:
        server: cohesity.lab
        username: admin
        password: password
        endpoint: mywindows.host.lab
        environment: Physical
        host_type: Windows
        state: present

    # Register a VMware Cohesity Protection Source on a selected endpoint
    - cohesity_source:
        server: cohesity.lab
        username: admin
        password: password
        endpoint: myvcenter.host.lab
        environment: VMware
        source_username: admin@vcenter.local
        source_password: vmware
        vmware_type: Vcenter
        state: present

    # Register a NAS Cohesity Protection Source on a selected NFS mountpoint
    - cohesity_source:
        server: cohesity.lab
        username: admin
        password: password
        endpoint: mynfs.host.lab:/exports
        environment: GenericNas
        state: present

    # Register a NAS Cohesity Protection Source on a selected SMB share
    - cohesity_source:
        server: cohesity.lab
        username: admin
        password: password
        endpoint: \\myfileserver.host.lab\data
        environment: GenericNas
        nas_protocol: SMB
        nas_username: administrator
        nas_password: password
        state: present

    # Unegister an existing Cohesity Protection Source on a selected endpoint
    - cohesity_source:
        server: cohesity.lab
        username: admin
        password: password
        endpoint: myvcenter.host.lab
        environment: VMware
        state: absent





Status
------





Authors
~~~~~~~

- Cohesity (@cohesity)

