.. _ansible_collections.cohesity.dataprotect.docsite.guide_setup:

Setup
=====

Steps to install
----------------

#. Make sure that the :ref:`prerequisites <ansible_collections.cohesity.dataprotect.docsite.guide_prerequisites>`
   are installed.
#. Install the collection on the Ansible control node using ``ansible-galaxy``:

   .. code-block:: shell

       ansible-galaxy collection install cohesity.dataprotect

#. Install the Python dependencies used by the modules:

   .. code-block:: shell

       pip install -r requirements.txt

#. Reference the collection in your plays. You can either use the fully qualified collection name for every
   task, or list the collection in a play:

   .. code-block:: yaml

       - name: Gather facts from a Cohesity cluster
         hosts: localhost
         collections:
           - cohesity.dataprotect
         tasks:
           - name: Gather cluster facts
             cohesity_facts:
               cluster: "{{ cohesity_server }}"
               username: "{{ cohesity_username }}"
               password: "{{ cohesity_password }}"
               validate_certs: "{{ cohesity_validate_certs }}"

   .. note::

       The ``collections`` keyword is optional. Using fully qualified collection names, such as
       :ansplugin:`cohesity.dataprotect.cohesity_facts#module`, is recommended.

Configure the inventory
-----------------------

The example playbooks read the cluster address and credentials from inventory variables. See
:ref:`ansible_collections.cohesity.dataprotect.docsite.guide_inventory` for details.
