.. _cohesity_plugin_module:


cohesity_plugin -- Management of Cohesity Datastore Plugin
==========================================================

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


  environment (False, str, Physical)
    Specifies the environment type (such as VMware or SQL) of the Protection Source this Job

    is protecting. Supported environment types include 'Physical', 'VMware', 'GenericNas'


  source_username (optional, str, None)
    Specifies username to access the target source.

    Required when *state=present* and *environment=VMware*


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

    
    # Install cohesity connector plugin on a postgresql host.
    - cohesity_source:
        server: cohesity.lab
        username: admin
        password: password
        state: present
        platform: PostgreSQL





Status
------





Authors
~~~~~~~

- Naveena (@naveena-maplelabs)

