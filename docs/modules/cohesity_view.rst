.. _cohesity_view_module:


cohesity_view -- Management of Cohesity View
============================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Ansible Module to create View.



Requirements
------------
The below requirements are needed on the host that executes this module.

- python >= 3.6
- cohesity_management_sdk >= 1.6.0



Parameters
----------

  case_insensitive (True, bool, None)
    


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


  description (optional, str, )
    Description for the View


  inline_dedupe_compression (optional, bool, False)
    Inline Dedupe Compression


  name (True, str, None)
    Name of the view


  nfs_options (False, dict, None)
    Nfs Option


  object_key_pattern (False, str, None)
    Object Key Pattern


  protocol (optional, str, All)
    Protocol


  qos_policy (optional, str, Backup Target Low)
    Qos Policy


  quota (False, dict, None)
    Quota


  security (False, dict, None)
    Security


  smb_options (False, dict, None)
    SMB Option


  state (optional, str, present)
    Determines if the agent should be ``present`` or ``absent`` from the host


  storage_domain (True, str, None)
    Storage Domain where view is created


  validate_certs (optional, bool, True)
    Switch determines if SSL Validation should be enabled.





Notes
-----

.. note::
   - Currently, the Ansible Module requires Full Cluster Administrator access.




Examples
--------

.. code-block:: yaml+jinja

    
    # Create Cohesity View.
    - cohesity_view:
        server: cohesity.lab
        username: admin
        password: password
        state: present
        name: "AnsibleView"
        description: "View is created using Ansible"
        storage_domain: "DefaultStorageDomain"
        qos_policy: "Backup Target Low"
        protocol: "All"
        case_insensitive: false

    # Delete Cohesity View.
    - cohesity_view:
        server: cohesity.lab
        username: admin
        password: password
        state: absent
        name: "AnsibleView"





Status
------





Authors
~~~~~~~

- Naveena (@naveena-maplelabs)

