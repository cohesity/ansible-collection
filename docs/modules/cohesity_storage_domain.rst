.. _cohesity_storage_domain_module:


cohesity_storage_domain -- Management of Cohesity Storage Domains
=================================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Ansible Module used to create or delete a storage domain from a Cohesity Cluster.

When executed in a playbook the appropriate state action will be applied.



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
    Password belonging to the selected Username. This parameter will not be logged.


  ad_domain_name (False, str, None)
    Specifies an active directory domain that this storage domain box is mapped to.


  cluster_partition_id (optional, int, 3)
    Specifies the Cluster Partition id where the Storage Domain is located.


  cluster_partition_name (optional, str, None)
    Specifies the Cluster Partition Name where the Storage Domain is located.


  default_view_quota (optional, dict, None)
    Specifies an optional default logical quota limit (in bytes) for the Views in this Storage Domain.

    Supports two fields hard\_limit\_bytes and alert\_limit\_bytes


  physical_quota (optional, dict, None)
    Specifies an optional quota limit (in bytes) for the physical usage of this Storage Domain.

    Supports two fields hard\_limit\_bytes and alert\_limit\_bytes


  id (optional, int, None)
    Specifies the Id of the Storage Domain.

    Applicable only when the domain is already created


  kms_server_id (optional, int, None)
    Specifies the associated KMS Server ID.


  ldap_provider_id (optional, int, None)
    Specifies the following provides the LDAP provider the storage domain is mapped to.


  storage_policy (optional, dict, None)
    Specifies the storage options applied to the Storage Domain.


  validate_certs (optional, bool, True)
    Switch determines if SSL Validation should be enabled.





Notes
-----

.. note::
   - Currently, the Ansible Module requires Full Cluster Administrator access.




Examples
--------

.. code-block:: yaml+jinja

    
    # Create a Storage Domain in the cohesity cluster.
    - cohesity_storage_domain:
        server: cohesity.lab
        username: admin
        password: password
        name: StorageDomain
        cluster_partition_name: DefaultPartition
        state: present

    # Delete a storage domain from the cohesity cluster.
    - cohesity_storage_domain:
        server: cohesity.lab
        username: admin
        password: password
        name: StorageDomain
        state: absent





Status
------





Authors
~~~~~~~

- Naveena (@naveena-maplelabs)

