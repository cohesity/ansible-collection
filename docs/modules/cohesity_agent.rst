.. _cohesity_agent_module:


cohesity_agent -- Management of Cohesity Physical Agent
=======================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Ansible Module used to deploy or remove the Cohesity Physical Agent from supported Linux Machines.

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


  create_user (False, bool, True)
    When enabled, will create a new user and group based on the values of *service_user* and *service_group*

    This parameter does not apply for native installations.


  download_location (optional, str, None)
    Optional directory path to which the installer will be downloaded.  If not selected, then a temporary

    directory will be created in the default System Temp Directory.  When choosing an alternate directory,

    the directory and installer will not be deleted at the end of the execution.


  download_uri (optional, str, )
    The download uri from where the installer can be downloaded


  file_based (False, bool, False)
    When enabled, will install the agent in non-LVM mode and support only file based backups.


  host (optional, str, )
    Host name of the source.


  native_package (optional, bool, False)
    When enabled, native installer packages are used based on the operating system


  operating_system (optional, str, None)
    ansible_distribution from facts, this value is automatically populated. Not given by module user


  service_group (optional, str, cohesityagent)
    Group underwhich permissions will be configured for the Cohesity Agent configuration.

    This group must exist unless *create_user=True* is also configured.

    This parameter doesn't apply for native installation.


  service_user (optional, str, cohesityagent)
    Username underwhich the Cohesity Agent will be installed and run.

    This user must exist unless *create_user=True* is also configured.

    This user must be an existing user for native installation.


  state (optional, str, present)
    Determines if the agent should be ``present`` or ``absent`` from the host


  upgrade (False, bool, False)
    If set to true and agent is already installed in the source, agent will be upgraded.


  wait_minutes (False, int, 30)
    Wait time for agent installation.


  validate_certs (optional, bool, True)
    Switch determines if SSL Validation should be enabled.





Notes
-----

.. note::
   - Currently, the Ansible Module requires Full Cluster Administrator access.




Examples
--------

.. code-block:: yaml+jinja

    
    # Install the current version of the agent on Linux
    - cohesity_agent:
        server: cohesity.lab
        cohesity_admin: admin
        cohesity_password: password
        state: present

    # Install the current version of the agent with custom User and Group
    - cohesity_agent:
        server: cohesity.lab
        cohesity_admin: admin
        cohesity_password: password
        state: present
        service_user: cagent
        service_group: cagent
        create_user: True

    # Removes the current installed agent from the host
    - cohesity_agent:
        server: cohesity.lab
        cohesity_admin: admin
        cohesity_password: password
        state: absent

    # Download the agent installer to a custom location.
    - cohesity_agent:
        server: cohesity.lab
        cohesity_admin: admin
        cohesity_password: password
        download_location: /software/installers
        state: present

    # Install the current version of the agent on Linux using native installers, the service user here should be an
    # existing user
    - cohesity_agent:
        server: cohesity.lab
        cohesity_admin: admin
        cohesity_password: password
        state: present
        service_user: cagent
        native_package: True

    # Install the cohesity agent using native package downloaded from given URI. Here, the Cohesity cluster credentials are not required
    - cohesity_agent:
        state: present
        service_user: cagent
        native_package: True
        download_uri: 'http://192.168.1.1/files/bin/installers/el-cohesity-agent-6.3-1.x86_64.rpm'






Status
------





Authors
~~~~~~~

- Naveena (@naveena-maplelabs)

