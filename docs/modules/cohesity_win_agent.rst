.. _cohesity_win_agent_module:


cohesity_win_agent -- Management of Cohesity Physical Windows Agent
===================================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Ansible Module used to deploy or remove the Cohesity Physical Agent from supported Windows Machines.

When executed in a playbook, the Cohesity Agent installation will be validated and the appropriate

state action will be applied.  The most recent version of the Cohesity Agent will be automatically

downloaded to the host.



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


  state (optional, any, present)
    Determines if the agent should be ``present`` or ``absent`` from the host


  service_user (optional, any, None)
    Username with which Cohesity Agent will be installed


  service_password (optional, any, None)
    Password belonging to the selected Username.  This parameter will not be logged.


  install_type (optional, any, volcbt)
    Installation type for the Cohesity Agent on Windows


  preservesettings (optional, bool, no)
    Should the settings be retained when uninstalling the Cohesity Agent


  validate_certs (optional, bool, True)
    Switch determines if SSL Validation should be enabled.





Notes
-----

.. note::
   - Currently, the Ansible Module requires Full Cluster Administrator access.




Examples
--------

.. code-block:: yaml+jinja

    
    # Install the current version of the agent on Windows
    - cohesity_win_agent:
        server: cohesity.lab
        username: admin
        password: password
        state: present

    # Install the current version of the agent with custom Service Username/Password
    - cohesity_win_agent:
        server: cohesity.lab
        username: admin
        password: password
        state: present
        service_user: cagent
        service_password: cagent

    # Install the current version of the agent using FileSystem ChangeBlockTracker
    - cohesity_win_agent:
        server: cohesity.lab
        username: admin
        password: password
        state: present
        install_type: fscbt





Status
------





Authors
~~~~~~~

- Naveena (@naveena-maplelabs)

