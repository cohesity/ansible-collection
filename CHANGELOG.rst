==================================
Cohesity.Dataprotect Release Notes
==================================

.. contents:: Topics

This changelog describes changes after version 1.3.0.

v1.4.4
======

Bugfixes
--------

- ansible-lint - Removed ``name[template]`` from ``.ansible-lint`` skip_list and fixed task names across playbooks to ensure Jinja2 template variables appear only at the end of task name strings.
- galaxy.yml - Added ``ansible.cfg`` and ``.ansible`` to ``build_ignore`` to prevent local developer configuration files from being packaged into the collection tarball.
- install_win_agent - Replaced ``community.windows.win_firewall_rule`` with ``ansible.windows.win_firewall`` in Windows agent install playbook to use the certified Ansible collection.
- uninstall_win_agent - Replaced ``community.windows.win_firewall_rule`` with ``ansible.windows.win_firewall`` in Windows agent uninstall playbook to use the certified Ansible collection.

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
