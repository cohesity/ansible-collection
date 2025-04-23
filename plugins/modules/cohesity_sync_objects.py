#!/usr/bin/python
# Copyright (c) 2023 Cohesity Inc


from __future__ import absolute_import, division, print_function

__metaclass__ = type

# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = """
---
author: Naveena (@naveena-maplelabs)
description:
  - Ansible Module used to finalize a Cohesity Migration Job on a Cohesity
    Cluster.
  - When executed in a playbook, the objects in Cohesity migration Job will be
    synced.
module: cohesity_sync_objects
options:
  task_id:
    description:
      - Task Id of the migrate job.
    type: str
  cluster:
    aliases:
      - cohesity_server
    description:
      - IP or FQDN for the Cohesity Cluster
    type: str
  cohesity_admin:
    aliases:
      - admin_name
      - cohesity_user
      - username
    description:
      - Username with which Ansible will connect to the Cohesity Cluster. Domain
        Specific credentails can be configured in following formats
      - AD.domain.com/username
      - AD.domain.com/username@tenant
      - LOCAL/username@tenant
    type: str
  cohesity_password:
    aliases:
      - password
      - admin_pass
    description:
      - Password belonging to the selected Username.  This parameter will not be
        logged.
    type: str
  state:
    choices:
      - present
      - absent
    default: present
    description:
      - Determines the state of the Recovery Job.
      - (C)present a recovery job will be created and started.
      - (C)absent is currently not implemented
    type: str
  task_name:
    description:
      - Name of the recovery task name.
    type: str
extends_documentation_fragment:
  - cohesity.dataprotect.cohesity
short_description: Sync objects available in the VM migration task
version_added: 1.3.0
"""

EXAMPLES = """

# Finalize migration.
- name: Sync objects available in the VM migration task
  cohesity_sync_objects:
    cluster: cohesity.lab
    username: admin
    password: password
    state: present
    task_name: "Ansible Migrate VM- In Sync"
"""

RETURN = """"""


# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)


import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url
try:
    from urllib import error as urllib_error
except ImportError:
    from ansible.module_utils.urls import urllib_error

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
        get__restore_job__by_type,
        get_cohesity_client,
    )
    from ansible_collections.cohesity.dataprotect.plugins.module_utils.cohesity_constants import (
        RELEASE_VERSION,
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

    if restore_tasks and module.params.get("task_id"):
        task_id = module.params.get("task_id").split(":")[-1]
        for task in restore_tasks:
            if task["id"] == int(task_id):
                return task["status"], task["id"], task["name"]
    return False, False, False


def sync_objects(module, self):
    """
    Get VMware protection source details
    :param module: object that holds parameters passed to the module
    :param restore_to_source: boolean flag to get target source details or
    vm's parent source details
    :return:
    """
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = get__cohesity_auth__token(module)
    try:
        uri = "https://" + server + "/irisservices/api/v1/public/restore/recover"
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
            "user-agent": "cohesity-ansible/v{}".format(RELEASE_VERSION),
        }
        body = {
            "restoreTaskId": self["task_id"],
            "childRestoreTaskIds": self.get("child_task_ids", []),
            "options": {"multiStageRestoreAction": "kUpdate"},
        }
        response = open_url(
            url=uri,
            headers=headers,
            validate_certs=validate_certs,
            method="PUT",
            data=json.dumps(body),
            timeout=REQUEST_TIMEOUT,
        )
        response = json.loads(response.read())
        return response
    except urllib_error.URLError as e:
        # => Capture and report any error messages.
        raise__cohesity_exception__handler(e.read(), module)
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def main():
    # => Load the default arguments including those specific to the Cohesity Protection Jobs.
    argument_spec = cohesity_common_argument_spec()
    argument_spec.update(
        dict(
            task_name=dict(type="str"),
            state=dict(choices=["present", "absent"], default="present"),
            task_id=dict(type="str"),
        )
    )

    # => Create a new module object
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    global cohesity_client
    cohesity_client = get_cohesity_client(module)
    results = dict(
        changed=False,
        msg="Attempting to finalize migration",
        state=module.params.get("state"),
    )

    task_details = dict(
        token=get__cohesity_auth__token(module), name=module.params.get("task_name")
    )

    task_status, task_id, task_name = check__protection_restore__exists(
        module, task_details
    )

    if module.check_mode:
        check_mode_results = dict(
            changed=False,
            msg="Check Mode: Cohesity Protection Migrate Job is not currently registered",
            id="",
        )
        if module.params.get("state") == "present":
            if task_status == "kInProgress":
                check_mode_results[
                    "msg"
                ] = "Check Mode: Cohesity Protection Migrate Job currently registered will be finalised."
            else:
                check_mode_results[
                    "msg"
                ] = "Check Mode: Cohesity Protection Migrate Job is not registered or Finished."

        else:
            check_mode_results[
                "msg"
            ] = "Cohesity Migrate: This feature (absent) has not be implemented yet."
        module.exit_json(**check_mode_results)

    elif module.params.get("state") == "present":
        check_mode_results = dict(msg="")
        if not task_name:
            results = dict(
                changed=False, msg="Couldn't find migration task in the cluster"
            )
        elif task_status != "kInProgress":
            results = dict(
                changed=False,
                msg="The Restore Job status is %s, skipping." % task_status,
                id=task_status,
            )
        else:
            task_details["task_id"] = task_id
            response = sync_objects(module, task_details)

            results = dict(
                changed=True,
                msg="Updation of Cohesity Migrate Job Complete",
            )

    elif module.params.get("state") == "absent":
        results = dict(
            changed=False,
            msg="Cohesity Migrate: This feature (absent) has not be implemented yet.",
            name=module.params.get("task_name"),
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
