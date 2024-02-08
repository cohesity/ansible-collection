.. _cohesity_uda_source_module:


cohesity_uda_source -- Management of UDA Protection Sources
===========================================================

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

- python \>= 3.6
- cohesity\_management\_sdk \>= 1.6.0



Parameters
----------

  cluster (optional, str, None)
    IP or FQDN for the Cohesity Cluster


  hosts (optional, list, None)
    Specifies the list of Ips/hostnames for the nodes forming UDA Source Cluster.


  mount_view (optional, bool, False)
    Specifies if SMB/NFS view mounting should be enabled or not.


  state (optional, str, present)
    Determines the state of the Protection Source


  cohesity_admin (optional, str, None)
    Username with which Ansible will connect to the Cohesity Cluster. Domain Specific credentails can be configured in following formats

    AD.domain.com/username

    AD.domain.com/username@tenant

    LOCAL/username@tenant


  os_type (optional, str, None)
    Type of the UDA source to be registered.

    Field is applicable for few cluster versions.


  source_type (optional, str, Linux)
    Type of the UDA source to be registered.


  cohesity_password (optional, str, None)
    Password belonging to the selected Username.  This parameter will not be logged.


  db_username (optional, str, None)
    Username of the database.


  db_password (optional, str, None)
    Password of the database.


  scripts_dir (optional, str, /opt/cohesity/postgres/scripts/)
    Absolute path of the scripts used to interact with the UDA source.


  source_registration_args (optional, str, None)
    Specifies the custom arguments to be supplied to the source registration scripts.


  source_name (True, str, None)
    Specifies the name of the protection source while registering.


  endpoint (True, str, None)
    Specifies the network endpoint of the Protection Source where it is reachable. It could

    be an URL or hostname or an IP address of the Protection Source


  refresh (optional, bool, False)
    Switch determines whether to refresh the existing source.

    Applicable only when source is already registered.


  update_source (optional, bool, False)
    Specifies whether to update the source, if the source is already registered.


  validate_certs (optional, bool, True)
    Switch determines if SSL Validation should be enabled.





Notes
-----

.. note::
   - Currently, the Ansible Module requires Full Cluster Administrator access.




Examples
--------

.. code-block:: yaml+jinja

    
    # Unegister an existing Cohesity Protection Source on a selected endpoint
    - cohesity_uda_source:
        server: cohesity.lab
        username: admin
        password: password
        endpoint: myvcenter.host.lab
        state: absent





Status
------





Authors
~~~~~~~

- Naveena (@naveena-maplelabs)

