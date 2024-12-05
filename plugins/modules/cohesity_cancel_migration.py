#!/usr/bin/python
# Copyright (c) 2023 Cohesity Inc


from __future__ import absolute_import, division, print_function

__metaclass__ = type

# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = """
---
author: Naveena (@naveena-maplelabs)
description:
  - Ansible Module used to Cancel a Cohesity Migration Job on a Cohesity Cluster.
  - When executed in a playbook, the Cohesity migration Job will be Canceld.
module: cohesity_cancel_migration
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
short_description: Cancel the VM migration
version_added: 1.3.0
"""

EXAMPLES = """

# Cancel migration.
- name: Cancel a Virtual Machine Migration
  cohesity_cancel_migration:
    cluster: cohesity.lab
    username: admin
    password: password
    state: present
    task_name: "Ansible Test VM Restore"

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
        get__restore_task_status__by_id,
        get_cohesity_client,
    )
except ImportError:
    pass


class ParameterViolation(Exception):
    pass


def check__protection_restore__exists(module, self):
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = get__cohesity_auth__token(module)
    try:
        uri = "https://" + server + "/v2/data-protect/recoveries"
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
            "user-agent": "cohesity-ansible/v1.3.0",
        }
        response = open_url(
            url=uri,
            headers=headers,
            validate_certs=validate_certs,
            method="GET",
            timeout=REQUEST_TIMEOUT,
        )
        response = json.loads(response.read())
        restore_tasks = response["recoveries"]
        if not restore_tasks:
            return False, False
        if module.params.get("task_name"):
            for task in restore_tasks:
                if task["name"] == self["name"]:
                    return task["status"], task["id"], task["name"]
        if module.params.get("task_id"):
            for task in restore_tasks:
                if task["id"] == module.params.get("task_id"):
                    return task["status"], task["id"], task["name"]
        return False, False, False
    except urllib_error.URLError as e:
        # => Capture and report any error messages.
        raise__cohesity_exception__handler(e.read(), module)
        return None, None, None
    except Exception as error:
        raise__cohesity_exception__handler(error, module)
        return None, None, None


def cancel_migration(module, task_id):
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
        uri = "https://" + server + "/v2/data-protect/recoveries/%s/cancel" % task_id
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
            "user-agent": "cohesity-ansible/v1.3.0",
        }
        response = open_url(
            url=uri,
            headers=headers,
            validate_certs=validate_certs,
            method="POST",
            data=json.dumps({}),
            timeout=REQUEST_TIMEOUT,
        )
        return response.code == 204
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
            state=dict(choices=["present", "absent"], default="present"),
            task_name=dict(type="str"),
            task_id=dict(type="str"),
        )
    )

    # => Create a new module object
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    global cohesity_client
    cohesity_client = get_cohesity_client(module)
    results = dict(
        changed=False,
        msg="Attempting to Cancel migration",
        state=module.params.get("state"),
    )

    task_details = dict(
        token=get__cohesity_auth__token(module),
        name=module.params.get("task_name"),
        id=module.params.get("task_id"),
    )

    task_status, task_id, task_name = check__protection_restore__exists(
        module, task_details
    )
    if not task_details["id"]:
        task_details["id"] = task_id

    if module.check_mode:
        check_mode_results = dict(
            changed=False,
            msg="Check Mode: Cohesity Migrate Job is not currently registered",
            id="",
        )
        if module.params.get("state") == "present":
            if task_status == "Running":
                check_mode_results[
                    "msg"
                ] = "Check Mode: Cohesity Migrate Job currently registered will be cancelled."
            else:
                check_mode_results[
                    "msg"
                ] = "Check Mode: Cohesity Migrate Job is not registered or Finished."

        else:
            check_mode_results[
                "msg"
            ] = "Cohesity Migrate: This feature (absent) has not be implemented yet."
        module.exit_json(**check_mode_results)

    elif module.params.get("state") == "present":
        check_mode_results = dict(msg="")
        if not task_status:
            results = dict(
                changed=False,
                msg="Couldn't find the Restore Job '%s'"
                % (module.params.get("task_name") or module.params.get("task_id")),
            )
        else:
            if task_status not in ["Running", "Accepted"]:
                results = dict(
                    msg="Cohesity Migration Job status is '%s', skipping cancelation"
                    % task_status,
                    name=task_name,
                )
            else:
                cancel_migration(module, task_id)
                # Poll for cancellation status.
                status = get__restore_task_status__by_id(module, task_details)
                results = dict(
                    msg="Succesfully cancelling the cohesity migrate job",
                    status=status,
                    name=task_name,
                )
            module.exit_json(**results)

    elif module.params.get("state") == "absent":
        results = dict(
            changed=False,
            msg="Cohesity Migrate: This feature (absent) has not be implemented yet.",
            name=task_name,
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
