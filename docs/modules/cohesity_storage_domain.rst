.. _cohesity_storage_domain_module:


cohesity_storage_domain -- Management of Cohesity Storage Domains.
==================================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Ansible Module used to create or remove a storage domain from a Cohesity Cluster.

When executed in a playbook the appropriate state action will be applied.






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
    Password belonging to the selected Username. This parameter will not be logged.


  ad_domain_name (False, str, None)
    Specifies the active directory name that the view box is mapped to.


  cluster_partition_id (optional, int, 3)
    The Cluster Partition id where the Storage Domain (View Box) will be created.


  state (optional, str, present)
    Determines the state of the storage domain.


  cluster_partition_name (optional, str, DefaultPartition)
    Name of the cluster partition where the Storage Domain (View Box) will be created.


  default_view_quota (optional, str, False)
    Specifies an optional default logical quota limit (in bytes) for the Views in this Storage Domain (View Box).


  kms_Server_id (optional, str, None)
    Specifies the associated KMS Server ID.


  validate_certs (optional, bool, True)
    Switch determines if SSL Validation should be enabled.


  ldap_provider_id (optional, str, None)
    When set, the following provides the LDAP provider the view box is mapped to.


  storage_policy (optional, dict, None)
    Specifies the storage options applied to the Storage Domain (View Box).

    Supports keys duplicate and compression\_policy.


  erasure_coding_params (optional, dict, None)
    Specifies information for erasure coding.









Examples
--------

.. code-block:: yaml+jinja

    
    # Create a view box in the cohesity cluster.
    - cohesity_storage_domain:
        server: cohesity.lab
        username: admin
        password: password
        name: Custom
        partition_name: DefaultPartition
        state: present

    # Remove a viewbox from the cohesity cluster.
    - cohesity_storage_domain:
        server: cohesity.lab
        username: admin
        password: password
        name: Custom
        state: absent





Status
------





Authors
~~~~~~~

- Naveena (@naveena-maplelabs)

