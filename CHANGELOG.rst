==================================
Cohesity.Dataprotect Release Notes
==================================

.. contents:: Topics

This changelog describes changes after version 1.3.0.

v1.4.5
======

Minor Changes
-------------

- Oracle workflow playbooks updated for Standalone and RAC modes (``register_oracle_source``, ``refresh_oracle_source``, ``create_oracle_job``, ``recover_db``). Pass all settings with ``-i localhost,`` and ``-e`` (``ansible_connection=local``, cluster credentials, ``oracle_source_type``, ``scan_vip_address``, optional ``rac_endpoint``).
- cohesity_oracle_job - Added ``source_type`` parameter (``standalone``/``rac``) for Oracle RAC protection job creation with SCAN/VIP endpoint resolution.
- cohesity_oracle_restore - Added ``source_type`` parameter (``standalone``/``rac``) and RAC source alias fallback when searching backups for database recovery.
- cohesity_oracle_source - Added Oracle RAC cluster registration via ``source_type`` (``standalone``/``rac``) and ``scan_vip_address`` (SCAN/VIP Address; alias ``rac_agent_node``), UI-equivalent ``/backupsources`` physical registration, and RAC source lookup by SCAN name and reachable endpoint.

Bugfixes
--------

- Added ``Content-Type: application/json`` header to REST requests across collection modules to prevent HTTP 415 errors.
- cohesity_oracle_source - Fixed ``register_oracle_source()`` return value handling and RAC source registration status lookup.

v1.4.4
======

Bugfixes
--------

- ansible-lint - Removed ``name[template]`` from ``.ansible-lint`` skip_list and fixed task names across playbooks to ensure Jinja2 template variables appear only at the end of task name strings.
- galaxy.yml - Added ``ansible.cfg`` and ``.ansible`` to ``build_ignore`` to prevent local developer configuration files from being packaged into the collection tarball.

Security Fixes
--------------

- Bumped ``requests`` minimum version to ``>=2.31.0`` to address known security vulnerabilities in older versions.

Documentation Changes
---------------------

- Added Changelog section to README with recent version highlights.
- Added Support (Red Hat Users) section to README with Ansible Automation Hub guidance.
- removed ansible-core from requirements.txt

v1.4.3
======

Bugfixes
--------

- cohesity_agent - Fixed agent detection failing with "Cohesity Agent is partially installed" on systemd hosts where the SysV init script is not created by the installer.

v1.4.2
======

Major Changes
-------------

- Ansible-Core Minimum Version Bumped to 2.16

Bugfixes
--------

- Fixed LiteralPath Issue During Cohesity Window Agent Installation
- Fixed collection failure issues for some ansible version