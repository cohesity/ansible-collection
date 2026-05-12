==================================
Cohesity.Dataprotect Release Notes
==================================

.. contents:: Topics

This changelog describes changes after version 1.3.0.

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
