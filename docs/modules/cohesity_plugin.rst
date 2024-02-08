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


  download_location (optional, str, None)
    Absolute path of the scripts used to store the downloaded connection plugin.


  endpoint (True, str, None)
    Specifies the network endpoint of the Protection Source where it is reachable. It could

    be an URL or hostname or an IP address of the Protection Source


  netmask_bits (optional, int, None)
    Applicable when the platform type is PostgreSQL and state is present.

    Is required to add the SapHana hosts to the cluster's global allow lists.


  platform (optional, str, Linux)
    Type of the UDA source to be registered.


  scripts_dir (optional, str, /opt)
    Absolute path of the scripts used to interact with the UDA source.


  state (optional, str, present)
    Determines the state of the Protection Source


  upgrade (optional, bool, False)
    Determines whether to upgrade the connector plugin if already installed.


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
    ---
    - cohesity_source:
        password: password
        platform: PostgreSQL
        server: cohesity.lab
        state: present
        username: admin





Status
------





Authors
~~~~~~~

- Naveena (@naveena-maplelabs)

