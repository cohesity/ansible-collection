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

    be an URL or hostname or an IP address of the Protection Source


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

- Naveena (@naveena-maplelabs)

