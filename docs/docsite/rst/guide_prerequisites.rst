.. _ansible_collections.cohesity.dataprotect.docsite.guide_prerequisites:

Prerequisites
=============

The prerequisites for using the Cohesity Ansible Collection are:

* Cohesity DataPlatform running version 6.0 or higher. Some modules might have different requirements, so see the
  documentation of the individual module.
* `Ansible Core <https://docs.ansible.com/projects/ansible/latest/installation_guide/intro_installation.html>`_
  version 2.16.0 or higher.

  The `Ansible control node <https://docs.ansible.com/projects/ansible/latest/installation_guide/intro_installation.html#control-node-requirements>`_
  must be a system running Linux, macOS, or a BSD. Windows is not supported as a control node.
* Python on the control node that is supported by your Ansible Core version, and Python 3.6 or higher on the
  managed side for modules that run there.
* The following Python packages on the host that executes the modules (see
  ``requirements.txt`` in the collection):

  * ``cohesity-management-sdk``
  * ``requests`` version 2.31.0 or higher
  * ``pywinrm`` (only when managing Windows hosts with :ansplugin:`cohesity.dataprotect.cohesity_win_agent#module`)

  Install them with:

  .. code-block:: shell

      pip install -r requirements.txt

* Credentials for a Cohesity user with Full Cluster Administrator access. See
  :ref:`ansible_collections.cohesity.dataprotect.docsite.guide_faq` for the supported username formats.
