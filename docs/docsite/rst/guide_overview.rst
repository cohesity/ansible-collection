.. _ansible_collections.cohesity.dataprotect.docsite.guide_overview:

Overview
========

The :anscollection:`cohesity.dataprotect collection <cohesity.dataprotect>` provides Ansible modules for
interacting with `Cohesity DataPlatform <https://www.cohesity.com/products/data-platform>`_.

Leveraging Python, this collection can be used from Linux or macOS control nodes, and it can manage Windows hosts
through WinRM. It includes modules and example playbooks that are useful for automating common tasks and for
orchestrating workflows in your environment.

The collection uses the Cohesity REST API (through the Cohesity Management SDK) to interact with the Cohesity
cluster.

What the collection covers
--------------------------

* Cluster information: :ansplugin:`cohesity.dataprotect.cohesity_facts#module`.
* Protection sources: :ansplugin:`cohesity.dataprotect.cohesity_source#module`,
  :ansplugin:`cohesity.dataprotect.cohesity_oracle_source#module` and
  :ansplugin:`cohesity.dataprotect.cohesity_uda_source#module`.
* Protection policies and groups: :ansplugin:`cohesity.dataprotect.cohesity_policy#module`,
  :ansplugin:`cohesity.dataprotect.cohesity_job#module`,
  :ansplugin:`cohesity.dataprotect.cohesity_oracle_job#module` and
  :ansplugin:`cohesity.dataprotect.cohesity_uda_protection_group#module`.
* Restore and recovery: :ansplugin:`cohesity.dataprotect.cohesity_restore_vm#module`,
  :ansplugin:`cohesity.dataprotect.cohesity_restore_file#module`,
  :ansplugin:`cohesity.dataprotect.cohesity_restore_vmware_file#module`,
  :ansplugin:`cohesity.dataprotect.cohesity_oracle_restore#module` and
  :ansplugin:`cohesity.dataprotect.cohesity_clone_vm#module`.
* VMware migration: :ansplugin:`cohesity.dataprotect.cohesity_migrate_vm#module`,
  :ansplugin:`cohesity.dataprotect.cohesity_migration_status#module`,
  :ansplugin:`cohesity.dataprotect.cohesity_finalize_migration#module`,
  :ansplugin:`cohesity.dataprotect.cohesity_cancel_migration#module` and
  :ansplugin:`cohesity.dataprotect.cohesity_sync_objects#module`.
* Agents and connectors: :ansplugin:`cohesity.dataprotect.cohesity_agent#module`,
  :ansplugin:`cohesity.dataprotect.cohesity_win_agent#module` and
  :ansplugin:`cohesity.dataprotect.cohesity_plugin#module`.
* Storage: :ansplugin:`cohesity.dataprotect.cohesity_storage_domain#module` and
  :ansplugin:`cohesity.dataprotect.cohesity_view#module`.

Example playbooks for these workflows are available in the
`playbooks directory <https://github.com/cohesity/ansible-collection/tree/main/playbooks>`_ of the repository.
