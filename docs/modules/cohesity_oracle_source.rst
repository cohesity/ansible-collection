.. _cohesity_oracle_source_module:


cohesity_oracle_source -- Management of Cohesity Protection Sources
===================================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Ansible Module used to register or remove the Oracle Sources to/from a Cohesity Cluster.

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

    AD.domain.com/username

    AD.domain.com/username@tenant

    LOCAL/username@tenant


  cohesity_password (optional, str, None)
    Password belonging to the selected Username.  This parameter will not be logged.


  endpoint (True, str, None)
    Specifies the network endpoint of the Protection Source where it is reachable. It could

    be an URL or hostname or an IP address of the Protection Source or a NAS Share/Export Path.


  force_register (optional, bool, False)
    Enabling this option will force the registration of the Cohesity Protection Source.


  refresh (optional, bool, False)
    Switch determines whether to refresh the existing source.

    Applicable only when source is already registered.


  db_password (optional, str, None)
    Specifies the password to access the target source database.

    This parameter will not be logged.

    Applicable only when state is set to present.


  db_username (optional, str, None)
    Specifies username to access the target source database.

    Applicable only when state is set to present.


  state (optional, str, present)
    Determines the state of the Protection Source


  validate_certs (optional, bool, True)
    Switch determines if SSL Validation should be enabled.





Notes
-----

.. note::
   - Currently, the Ansible Module requires Full Cluster Administrator access.




Examples
--------

.. code-block:: yaml+jinja

    
    # Register a Physical Cohesity Protection Source and register the physical source
    # as Oracle server.
    - cohesity_oracle:
        server: cohesity-cluster-vip
        username: admin
        password: password
        endpoint: endpoint
        state: present
    # Unegister an existing Cohesity Protection Source on a selected endpoint
    - cohesity_oracle:
        server: cohesity-cluster-vip
        username: admin
        password: password
        endpoint: endpoint
        state: absent





Status
------





Authors
~~~~~~~

- Naveena (@naveena-maplelabs)

