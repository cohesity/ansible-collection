.. _cohesity_facts_module:


cohesity_facts -- Gather facts about a Cohesity Cluster.
========================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

Gather facts about Cohesity Clusters.






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


  state (optional, str, complete)
    Determines the level of data collection to perform. Complete will gather all details

    currently supported by the module.  Minimal will gather basic cluster information but

    not gather details about source, jobs, or executions.


  include_sources (optional, bool, False)
    When True, will return the details about all registered Protection Sources.  This value

    is skipped when the ``state=complete``


  include_jobs (optional, bool, False)
    When True, will return the details about all registered Protection Jobs.  This value

    is skipped when the ``state=complete``


  include_runs (optional, bool, False)
    When True, will return the details about all registered Protection Job executions.  This value

    is skipped when the ``state=complete``


  active_only (optional, bool, False)
    When True, will return only the actively running Protection Job executions.  This value

    will filter the Protection Job executions data if *active_only=yes*


  include_deleted (optional, bool, False)
    When True, will return all details about all registered Protection data included items marked deleted.  This value

    will filter the Protection Sources, Jobs, and Executions data and return only current information if *include_deleted=no*









Examples
--------

.. code-block:: yaml+jinja

    
    # Gather facts about all nodes and supported resources in a cluster
    - cohesity_facts:
        cluster: cohesity.lab
        username: admin
        password: password

    # Gather facts about all nodes and protection sources in a cluster
    - cohesity_facts:
        cluster: cohesity.lab
        username: admin
        password: password
        state: minimal
        include_sources: True

    # Gather facts about all nodes and return active job executions in a cluster
    - cohesity_facts:
        cluster: cohesity.lab
        username: admin
        password: password
        state: minimal
        include_runs: True
        active_only: True






Status
------





Authors
~~~~~~~

- Naveena (@naveena-maplelabs)

