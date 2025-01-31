.. _cohesity_policy_module:


cohesity_policy -- Cohesity Protection Policy
=============================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Ansible Module used to create/update/remove protection policy on a Cohesity Cluster.

When executed in a playbook, the Cohesity Policy will be validated and the appropriate state action

will be applied.



Requirements
------------
The below requirements are needed on the host that executes this module.

- python \>= 3.6
- cohesity\_management\_sdk \>= 1.6.0



Parameters
----------

  archival_copy (optional, list, None)
    Specifies the list of external targets to be added while creating policy.


  blackout_window (optional, list, None)
    Specifies the list of blackout windows.


  bmr_backup_schedule (optional, dict, None)
     BMR backup schedule.


  cluster (optional, str, None)
    IP or FQDN for the Cohesity Cluster


  cohesity_admin (optional, str, None)
    Username with which Ansible will connect to the Cohesity Cluster. Domain Specific credentails can be configured in following formats

    AD.domain.com/username

    AD.domain.com/username@tenant

    LOCAL/username@tenant


  cohesity_password (optional, str, None)
    Password belonging to the selected Username.  This parameter will not be logged.


  days_to_retain (optional, int, 90)
    Specifies the number of retention days.


  description (optional, str, )
    Specifies the description for the policy created


  extended_retention (optional, list, None)
    Specifies the extended retention


  full_backup_schedule (optional, dict, None)
    Specifies the full backup schedule for policy creation


  incremental_backup_schedule (True, dict, None)
    Specifies the incremental backup schedule for policy creation


  log_backup_schedule (optional, dict, None)
    Specifies the log backup schedule for policy creation


  name (True, str, None)
    Specifies the name of the protection policy.


  replication_copy (optional, list, None)
    Specifies the list of replication cluster to be added while creating policy.


  retries (optional, int, 3)
    Specifies the retry count while policy creation.


  retry_interval (optional, int, 30)
    Specifies the retry interval.


  state (optional, str, present)
    Determines the state of the Policy.

    (C)present a policy will be created.

    (C)absent will remove the policy.


  validate_certs (optional, bool, True)
    Switch determines if SSL Validation should be enabled.





Notes
-----

.. note::
   - Currently, the Ansible Module requires Full Cluster Administrator access.




Examples
--------

.. code-block:: yaml+jinja

    
    # Create a protection policy.
    - cohesity_policy:
        cluster: cohesity.lab
        username: admin
        password: password
        state: present
        name: 'Ansible'
        incremental_backup_schedule:
          periodicity: Daily

    # Delete a protection policy.

    - cohesity_policy:
        cluster: cohesity.lab
        username: admin
        password: password
        state: present
        name: 'Ansible'





Status
------





Authors
~~~~~~~

- Naveena (@naveena-maplelabs)

