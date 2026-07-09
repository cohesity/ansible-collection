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

Supports both Oracle Standalone and Oracle RAC (Real Application Clusters) deployments.



Requirements
------------
The below requirements are needed on the host that executes this module.

- python \>= 3.6
- cohesity\_management\_sdk \>= 1.6.0



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


  endpoint (False, str, )
    Specifies the network endpoint of the Protection Source where it is reachable. It could

    be an URL or hostname or an IP address of the Protection Source or a NAS Share/Export Path.

    Required when :emphasis:`source\_type=standalone`.

    Optional when :emphasis:`source\_type=rac`. Use as a reachable agent host when the Cohesity cluster

    cannot reach the SCAN/VIP in :emphasis:`scan\_vip\_address`\ ; sent as the connection endpoint during

    RAC physical registration.


  scan_vip_address (optional, str, )
    Oracle RAC SCAN/VIP address. Same label as :literal:`SCAN/VIP Address` in the Cohesity UI.

    Required when :emphasis:`source\_type=rac`.

    Used as the registered physical source name during RAC registration.


  source_type (optional, str, standalone)
    Specifies the type of Oracle deployment being registered.

    Use :literal:`standalone` for a single\-node Oracle host. This is the default.

    Use :literal:`rac` for Oracle RAC with :emphasis:`scan\_vip\_address` as SCAN/VIP and optional :emphasis:`endpoint`

    as a reachable host when the cluster cannot reach the SCAN/VIP.


  force_register (optional, bool, False)
    Enabling this option will force the registration of the Cohesity Protection Source.


  refresh (optional, bool, False)
    Switch determines whether to refresh the existing source.

    Applicable only when source is already registered.


  db_password (optional, str, )
    Specifies the password to access the target source database.

    This parameter will not be logged.

    Applicable only when state is set to present.


  db_username (optional, str, )
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

    
    # Register an Oracle standalone host as a Protection Source.
    - cohesity.dataprotect.cohesity_oracle_source:
        cluster: cohesity-cluster-vip
        username: admin
        password: password
        endpoint: oracle-host.example.com
        source_type: standalone
        state: present

    # Unregister an existing Cohesity Protection Source on a selected endpoint.
    - cohesity.dataprotect.cohesity_oracle_source:
        cluster: cohesity-cluster-vip
        username: admin
        password: password
        endpoint: oracle-host.example.com
        state: absent

    # Register an Oracle RAC cluster as a Protection Source.
    - cohesity.dataprotect.cohesity_oracle_source:
        cluster: cohesity-cluster-vip
        username: admin
        password: password
        scan_vip_address: scan-vip.example.com
        endpoint: reachable-host.example.com
        source_type: rac
        state: present





Status
------





Authors
~~~~~~~

- Naveena (@naveena-maplelabs)

