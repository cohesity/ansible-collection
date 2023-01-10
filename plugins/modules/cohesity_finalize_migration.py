#!/usr/bin/python
# Copyright (c) 2022 Cohesity Inc


from __future__ import absolute_import, division, print_function

__metaclass__ = type

# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = """
---
author: "Naveena (@naveena-maplelabs)"
description:
  - "Ansible Module used to start a Cohesity Migration Job on a Cohesity Cluster."
  - "When executed in a playbook, the Cohesity migration Job will be validated and the appropriate state action"
  - "will be applied."
module: cohesity_migrate_vm
options:
  task_id:
    description:
      - "Recovery task Id."
    type: str
  cluster:
    aliases:
      - cohesity_server
    description:
      - "IP or FQDN for the Cohesity Cluster"
    type: str
  cohesity_admin:
    aliases:
      - admin_name
      - cohesity_user
      - username
    description:
      - Username with which Ansible will connect to the Cohesity Cluster. Domain Specific credentails can be configured in following formats
      - AD.domain.com/username
      - AD.domain.com/username@tenant
      - LOCAL/username@tenant
    type: str
  cohesity_password:
    aliases:
      - password
      - admin_pass
    description:
      - "Password belonging to the selected Username.  This parameter will not be logged."
    type: str
  state:
    choices:
      - present
      - absent
    default: present
    description:
      - "Determines the state of the Recovery Job."
      - "(C)present a recovery job will be created and started."
      - "(C)absent is currently not implemented"
    type: str
  task_name:
    description:
      - "Name of the recovery task name."
    type: str
extends_documentation_fragment:
- cohesity.dataprotect.cohesity
short_description: "Finalize the VM migration"
version_added: 1.0.9
"""

EXAMPLES = """

# Restore a single Virtual Machine
- name: Restore a Virtual Machine
  cohesity_migrate_vm:
    cluster: cohesity.lab
    username: admin
    password: password
    state: present
    name: "Ansible Test VM Restore"
    endpoint: "myvcenter.cohesity.demo"
    environment: "VMware"
    job_name: "myvcenter.cohesity.demo"
    vm_names:
      - chs-win-01

# Restore multiple Virtual Machines from a specific snapshot with a new prefix and disable the network
- name: Restore a Virtual Machine
  cohesity_migrate_vm:
    cluster: cohesity.lab
    username: admin
    password: password
    state: present
    name: "Ansible Test VM Restore"
    endpoint: "myvcenter.cohesity.demo"
    environment: "VMware"
    job_name: "myvcenter.cohesity.demo"
    backup_id: "48291"
    vm_names:
      - chs-win-01
      - chs-win-02
    prefix: "rst-"
    network_connected: no

"""

RETURN = """"""


# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)


import json

try:
    from urllib import quote
except ImportError:
    from urllib.parse import quote
from datetime import datetime
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url, urllib_error

try:
    # => When unit testing, we need to look in the correct location however, when run via ansible,
    # => the expectation is that the modules will live under ansible.
    from ansible_collections.cohesity.dataprotect.plugins.module_utils.cohesity_auth import (
        get__cohesity_auth__token,
    )
    from ansible_collections.cohesity.dataprotect.plugins.module_utils.cohesity_utilities import (
        cohesity_common_argument_spec,
        raise__cohesity_exception__handler,
        REQUEST_TIMEOUT,
    )
    from ansible_collections.cohesity.dataprotect.plugins.module_utils.cohesity_hints import (
        get__protection_jobs__by_environment,
        get__vmware_snapshot_information__by_vmname,
        get__restore_job__by_type,
        get_cohesity_client,
    )
except ImportError:
    pass


class ParameterViolation(Exception):
    pass


def check__protection_restore__exists(module, self):
    payload = self.copy()
    payload["restore_type"] = "kRecoverVMs"
    payload["count"] = 1

    restore_tasks = get__restore_job__by_type(module, payload)

    if restore_tasks:
        task_list = [task for task in restore_tasks if task["name"] == self["name"]]
        for task in task_list:
            if task["status"] != "kFinished":
                return True
    return False


def main():
    # => Load the default arguments including those specific to the Cohesity Protection Jobs.
    argument_spec = cohesity_common_argument_spec()
    argument_spec.update(
        dict(
            task_name=dict(type="str"),
            state=dict(choices=["present", "absent"], default="present"),
            task_id=dict(type="str")
        )
    )

    # => Create a new module object
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    results = dict(
        changed=False,
        msg="Attempting to finalize migration",
        state=module.params.get("state"),
    )

    job_details = dict(
        token=get__cohesity_auth__token(module),
        endpoint=module.params.get("endpoint"),
        job_name=module.params.get("job_name"),
        environment=module.params.get("environment"),
    )

    job_exists = check__protection_restore__exists(module, job_details)

    if module.check_mode:
        check_mode_results = dict(
            changed=False,
            msg="Check Mode: Cohesity Protection Restore Job is not currently registered",
            id="",
        )
        if module.params.get("state") == "present":
            if job_exists:
                check_mode_results[
                    "msg"
                ] = "Check Mode: Cohesity Protection Restore Job is currently registered.  No changes"
            else:
                check_mode_results[
                    "msg"
                ] = "Check Mode: Cohesity Protection Restore Job is not currently registered.  This action would register the Cohesity Protection Job."

        else:
            if job_exists:
                check_mode_results[
                    "msg"
                ] = "Check Mode: Cohesity Protection Restore Job is currently registered.  This action would unregister the Cohesity Protection Job."
                check_mode_results["id"] = job_exists
            else:
                check_mode_results[
                    "msg"
                ] = "Check Mode: Cohesity Protection Restore Job is not currently registered.  No changes."
        module.exit_json(**check_mode_results)

    elif module.params.get("state") == "present":
        check_mode_results = dict(msg="")
        cohesity_client = get_cohesity_client(module)
        if job_exists:
            results = dict(
                changed=False,
                msg="The Restore Job for is already registered",
                id=job_exists,
                name=job_details["name"],
            )
        else:
            environment = "k" + module.params.get("environment")
            response = []
            task_name = (
                "Migrate_VM" + "_" + datetime.now().strftime("%b_%d_%Y_%I_%M_%p")
            )

            
            results = dict(
                changed=True,
                msg="Registration of Cohesity Restore Job Complete",
                name=module.params.get("job_name") + ": " + module.params.get("name"),
                restore_jobs=response,
            )

    elif module.params.get("state") == "absent":

        results = dict(
            changed=False,
            msg="Cohesity Restore: This feature (absent) has not be implemented yet.",
            name=module.params.get("job_name") + ": " + module.params.get("name"),
        )
    else:
        # => This error should never happen based on the set assigned to the parameter.
        # => However, in case, we should raise an appropriate error.
        module.fail_json(
            msg="Invalid State selected: {0}".format(module.params.get("state")),
            changed=False,
        )

    module.exit_json(**results)


if __name__ == "__main__":
    main()
