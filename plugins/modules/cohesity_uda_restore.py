#!/usr/bin/python
# Copyright (c) 2022 Cohesity Inc

from __future__ import absolute_import, division, print_function

__metaclass__ = type

# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = """
---
author: "Naveena (@naveena-maplelabs)"
description:
  - "Ansible Module used to start a Cohesity Recovery Job on a Cohesity Cluster."
  - "When executed in a playbook, the Cohesity Recovery Job will be validated and the appropriate state action"
  - "will be applied."
module: cohesity_uda_restore
options:
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
      - Determines if the UDA recovery should be C(present) or C(absent).
      - absent is currently not implemented.
    type: str
  object:
    type: str
    description:
      - "Name of the UDA object (tables or databases) to be restored."
  overwrite:
    default: false
    description: Enabling this option will overwrite the database, if already available.
    type: bool
  source_server:
    description: Specifies the source server name where database is located.
    required: true
    type: str
  target_server:
    description: 'Specifies the uda server where database is restored.'
    type: str
  group_name:
    required: true
    description: 'Specifies the name of the protection group to fetch snapshot details.'
    type: str
  task_name:
    aliases:
     - name
    description: 'Specifies the restore task name'
    type: str
  rename_to:
    type: str
    description: New name of the object to be recovered.

extends_documentation_fragment:
- cohesity.dataprotect.cohesity
short_description: "Restore UDA object from Cohesity Protection Groups"
version_added: 1.0.0
"""

EXAMPLES = """
# Restore UDA database.
- name: Restore UDA database.
  cohesity_uda_restore:
    task_name: recover_tasks
    object: xyz
    source_server: "x.x.x.x"
    target_server: "x.x.x.x"

"""

RETURN = """
"""


import json
import time
import traceback
from urllib.error import HTTPError

# Ansible imports
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url

try:
    # => When unit testing, we need to look in the correct location however, when run via ansible,
    # => the expectation is that the modules will live under ansible.
    from ansible_collections.cohesity.dataprotect.plugins.module_utils.cohesity_auth import (
        get__cohesity_auth__token,
    )
    from ansible_collections.cohesity.dataprotect.plugins.module_utils.cohesity_utilities import (
        cohesity_common_argument_spec,
        REQUEST_TIMEOUT,
    )
    from ansible_collections.cohesity.dataprotect.plugins.module_utils.cohesity_hints import (
        get_cohesity_client,
        get__prot_source_id__by_endpoint,
    )
except Exception:
    pass


class ParameterViolation(Exception):
    pass


class ProtectionException(Exception):
    pass


def create_recover_job(module, token, snapshot_id):
    """
    Function to create new recovery tasks.
    """
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    try:
        snapshot = dict(
            snapshotId=snapshot_id,
            objects=[
                dict(
                    objectName=module.params.get("object"),
                    overwrite=module.params.get("overwrite"),
                    renameTo=module.params.get("rename_to"),
                )
            ],
        )
        body = dict(
            name=module.params.get("task_name"),
            snapshotEnvironment="kUDA",
            udaParams=dict(
                recoveryAction="RecoverObjects",
                recoverUdaParams=dict(
                    concurrency=None,
                    mounts=1,
                    recoverTo=target_id,
                    snapshots=[snapshot],
                ),
            ),
        )

        uri = "https://" + server + "/v2/data-protect/recoveries"
        headers = {"Accept": "application/json", "Authorization": "Bearer " + token}
        response = open_url(
            url=uri,
            data=json.dumps(body),
            method="POST",
            headers=headers,
            validate_certs=validate_certs,
            timeout=REQUEST_TIMEOUT,
        )
        response = json.loads(response.read())
        return response
    except HTTPError as err:
        error = json.load(err)
        module.fail_json(
            msg='Error while recovery task creation, error message: "%s"'
            % error["message"]
        )
    except Exception as err:
        module.fail_json(
            msg='Error while recovery task creation, error message: "%s". %s' % err
        )


def check_for_status(module, task_id):
    """
    Check for the restore task status based on task id.
    """
    try:
        while True:
            resp = cohesity_client.restore_tasks.get_restore_task_by_id(id=task_id)
            if not resp:
                raise Exception("Recovery tasks not available.")
            status = resp.status
            if status in ["kCancelled", "kFinished"]:
                if resp.error:
                    raise Exception(resp.error.message)
                return status == "kFinished"
            # Wait for 15 seconds.
            time.sleep(15)
    except Exception as err:
        module.fail_json(msg="UDA restore failed, err msg '%s'" % err)


def get_protection_group_by_name(module, self):
    """
    Function to get protection group is by name.
    return: group id.
    """
    server = module.params.get("cluster")
    group_name = module.params.get("group_name")
    validate_certs = module.params.get("validate_certs")
    try:
        uri = (
            "https://"
            + server
            + "/v2/data-protect/protection-groups?names=%s&isDeleted=False"
            % (group_name)
        )
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + self["token"],
        }
        response = open_url(
            url=uri,
            method="GET",
            headers=headers,
            validate_certs=validate_certs,
            timeout=REQUEST_TIMEOUT,
        )
        response = json.loads(response.read())
        if not response.get("protectionGroups", None):
            raise Exception("Protection group '%s' not available." % group_name)
        for group in response["protectionGroups"]:
            if group["name"] == group_name:
                return group["id"]
    except HTTPError as err:
        error = json.load(err)
        module.fail_json(msg='Error message: "%s"' % error["message"])
    except Exception as err:
        module.fail_json(msg=str(err))


def get_snapshot_id(module, self):
    """
    Function to fetch database details if available.
    """
    server = module.params.get("cluster")
    group_name = module.params.get("group_name")
    if not group_name:
        module.fail_json(
            "Protection group '%s' is not available in the cluster" % group_name
        )
    group_id = get_protection_group_by_name(module, self)
    source_server = module.params.get("source_server")
    validate_certs = module.params.get("validate_certs")
    try:
        uri = (
            "https://"
            + server
            + "/v2/data-protect/objects/%s/snapshots?protectionGroupIds=%s"
            % (self["source_id"], group_id)
        )
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + self["token"],
        }
        response = open_url(
            url=uri,
            method="GET",
            headers=headers,
            validate_certs=validate_certs,
            timeout=REQUEST_TIMEOUT,
        )
        response = json.loads(response.read())
        if not response or not response["snapshots"]:
            module.fail_json(
                "No Snapshots available for the source '%s' and group '%s'"
                % (source_server, group_name)
            )
        snapshots = response["snapshots"]
        return snapshots[0]["id"]
    except HTTPError as err:
        error = json.load(err)
        module.fail_json(
            msg='Error while recovery task fetching snapshots, error message: "%s"'
            % error["message"]
        )
    except Exception as err:
        module.fail_json(msg=str(err))


def main():
    # => Load the default arguments including those specific to the Cohesity Protection Jobs.
    argument_spec = cohesity_common_argument_spec()
    argument_spec.update(
        dict(
            task_name=dict(type="str", aliases=["name"]),
            source_server=dict(type="str", required=True),
            target_server=dict(type="str"),
            overwrite=dict(type="bool", default=False),
            rename_to=dict(type="str", default=None),
            object=dict(type="str"),
            group_name=dict(type="str", required=True),
        )
    )

    # => Create a new module object
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    global cohesity_client
    cohesity_client = get_cohesity_client(module)

    token = get__cohesity_auth__token(module)
    if module.params.get("state") == "present":
        # Check the source and target server is reachable.
        global target_id
        source = module.params.get("source_server")
        target = module.params.get("target_server")
        job_details = dict(token=token, environment="UDA", endpoint=source)
        source_id = get__prot_source_id__by_endpoint(module, job_details)
        if not source_id:
            module.fail_json(
                msg="Source '%s' is not registered to the cluster." % source
            )
        if not target:
            # If target host is not provided, will be restore to the source host.
            target_id = source_id
        else:
            job_details["endpoint"] = target
            target_id = get__prot_source_id__by_endpoint(module, job_details)
            if not target_id:
                module.fail_json(
                    msg="Target '%s' is not registered to the cluster. Please "
                    "register the host and try again" % source
                )
        job_details["source_id"] = source_id
        snapshot_id = get_snapshot_id(module, job_details)
        resp = create_recover_job(module, token, snapshot_id)

        # Check for restore task status. Tasks id will be returned as string.
        task_id = int(resp["id"].split(":")[-1])
        status = check_for_status(module, task_id)
        if not status:
            msg = "Error occured during task recovery."
            module.fail_json(msg=msg)

        results = dict(
            changed=True,
            msg="Successfully created restore task '%s'"
            % module.params.get("task_name"),
        )
    elif module.params.get("state") == "absent":
        results = dict(
            changed=False,
            msg="Cohesity Restore: This feature (absent) has not be implemented yet.",
            name=module.params.get("job_name") + ": " + module.params.get("name"),
        )
    module.exit_json(**results)


if __name__ == "__main__":
    main()
