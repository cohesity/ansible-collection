#!/usr/bin/python
# Copyright (c) 2022 Cohesity Inc


from __future__ import absolute_import, division, print_function

__metaclass__ = type

# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = """
---
author: "Naveena (@naveena-maplelabs)"
description:
  - "Ansible Module used to clone the Virtual Machine."
module: cohesity_clone_vm
options:
  backup_timestamp:
    description:
      - "Option to identify backups based on a timestamp"
    required: false
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
      - Formats,
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
  end_timestamp:
    description:
      - "Option to identify backups based on a end timestamp"
    required: false
    type: str
  environment:
    choices:
    - VMware
    default: VMware
    description:
      - "Optional directory path to which the installer will be downloaded.  If not selected, then a temporary"
      - "directory will be created in the default System Temp Directory.  When choosing an alternate directory,"
      - "the directory and installer will not be deleted at the end of the execution."
    type: str
  job_name:
    description: "Name of the Protection Job"
    required: true
    type: str
  name:
    description:
      - "Descriptor to assign to the Recovery Job.  The Recovery Job name will consist of the job_name:name format."
    required: true
    type: str
  network_connected:
    default: true
    description:
      - "Specifies whether the network should be left in disabled state. Attached network is enabled by default. Set this flag to true to disable it."
    type: bool
  power_on:
    default: true
    description:
      - "Specifies the power state of the cloned or recovered objects. By default, the cloned or recovered objects are powered off."
    type: bool
  prefix:
    description:
      - "Specifies a prefix to prepended to the source object name to derive a new name for the recovered or cloned object."
    type: str
  resource_pool:
    required: true
    description:
      - "Specifies the resource pool where the cloned or recovered objects are attached."
    type: str
  start_timestamp:
    description:
      - "Option to identify backups based on a start timestamp."
    required: false
    type: str
  state:
    choices:
      - present
      - absent
    default: present
    description:
      - "Determines if the clone vm should be C(present) or C(absent) from the cluster"
    type: str
  suffix:
    description: "Specifies a suffix to appended to the original source object name to derive a new name      for the recovered or cloned object."
    type: str
  view_name:
    description:
      - "Name of the view"
    type: str
  vm_names:
    description:
      - "List of virtual machines"
    type: list
    elements: str
    required: true
  wait_for_job:
    default: true
    description:
      - "Should wait until the Restore Job completes"
    type: bool
  wait_minutes:
    default: 30
    type: int
    description:
      - "Number of minutes to wait until the job completes."
extends_documentation_fragment:
- cohesity.dataprotect.cohesity
short_description: "Management of Cohesity VM Clone"
version_added: 1.1.5
"""


EXAMPLES = """

# Restore a single Virtual Machine
- name: Restore a Virtual Machine
  cohesity_clone_vm:
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
  cohesity_clone_vm:
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


import json
import time

from ansible.module_utils.basic import AnsibleModule
from cohesity_management_sdk.controllers.base_controller import BaseController
from cohesity_management_sdk.models.clone_task_request import CloneTaskRequest
from cohesity_management_sdk.models.vmware_clone_parameters import VmwareCloneParameters
from cohesity_management_sdk.models.restore_object_details import RestoreObjectDetails
from cohesity_management_sdk.exceptions.api_exception import APIException
from datetime import datetime


try:
    from ansible_collections.cohesity.dataprotect.plugins.module_utils.cohesity_utilities import (
        cohesity_common_argument_spec,
        raise__cohesity_exception__handler,
    )
    from ansible_collections.cohesity.dataprotect.plugins.module_utils.cohesity_hints import (
        get_cohesity_client,
    )
except Exception:
    pass


SLEEP_TIME_SECONDS = 90
MICRO_SECONDS = 1000000
cohesity_client = None


def get_clone_task(module, wait_request):
    """
    Get clone task details
    :param module: object that holds parameters passed to the module
    :param wait_request: boolean to determine if request is made during wait time
    :return:
    """
    try:
        environment = "k" + module.params.get("environment")
        restore_tasks = cohesity_client.restore_tasks.get_restore_tasks(
            task_types=["kCloneVMs"], environment=environment
        )
        if restore_tasks:
            for task in restore_tasks:
                if task.name == module.params.get("name"):
                    return True, task
        return False, ""
    except APIException as ex:
        if not wait_request:
            raise__cohesity_exception__handler(
                str(json.loads(ex.context.response.raw_body)), module
            )
        else:
            return False, ""
    except Exception as error:
        if not wait_request:
            raise__cohesity_exception__handler(error, module)
        else:
            return False, ""


def get_protection_job_details(module):
    """
    Get protection job details
    :param module: object that holds parameters passed to the module
    :return:
    """
    try:
        protection_job_name = module.params.get("job_name")
        environment = "k" + module.params.get("environment")
        protection_jobs = cohesity_client.protection_jobs.get_protection_jobs(
            names=protection_job_name, environments=[environment]
        )
        if protection_jobs:
            return protection_jobs[0]
        else:
            if module.check_mode:
                return False
            raise__cohesity_exception__handler(
                "Failed to find the job name for the selected environment type", module
            )
    except APIException as ex:
        raise__cohesity_exception__handler(
            str(json.loads(ex.context.response.raw_body)), module
        )
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def get_snapshot_details(module, timestamp, vm_name, job_id):
    """
    function to search and get the snapshot details of a vm
    :param module: object that holds parameters passed to the module
    :param timestamp: backup timestamp
    :param vm_name: vm to search
    :param job_id: protection job id
    :return:
    """
    try:
        restore_object = RestoreObjectDetails()
        object_details = cohesity_client.restore_tasks.search_objects(
            search=vm_name, job_ids=[job_id]
        )
        if module.params.get("start_timestamp") and module.params.get("end_timestamp"):
            object_details = cohesity_client.restore_tasks.search_objects(
                search=vm_name,
                job_ids=[job_id],
                start_time_usecs=module.params.get("start_timestamp"),
                end_time_usecs=module.params.get("end_timestamp"),
            )
        if object_details.total_count == 0:
            raise__cohesity_exception__handler(
                "There are no existing snapshots for " + str(vm_name), module
            )
        else:
            if not timestamp:
                restore_object.job_id = job_id
                restore_object.protection_source_id = (
                    object_details.object_snapshot_info[0].snapshotted_source.id
                )
            else:
                restore_object.job_id = job_id
                restore_object.protection_source_id = (
                    object_details.object_snapshot_info[0].snapshotted_source.id
                )
                for snapshot in object_details.object_snapshot_info[0].versions:
                    requested_timestamp = datetime.strptime(
                        timestamp, "%Y-%m-%d:%H:%M"
                    ).replace(second=0)
                    snapshot_timestamp = datetime.strptime(
                        time.ctime(snapshot.started_time_usecs / MICRO_SECONDS),
                        "%a %b %d %H:%M:%S %Y",
                    ).replace(second=0)
                    if requested_timestamp == snapshot_timestamp:
                        restore_object.job_run_id = snapshot.job_run_id
                        restore_object.started_time_usecs = snapshot.started_time_usecs
                if not restore_object.job_run_id:
                    raise__cohesity_exception__handler(
                        "Failed to get the snapshot of "
                        + vm_name
                        + " backed up at "
                        + str(timestamp),
                        module,
                    )
        return restore_object
    except APIException as ex:
        raise__cohesity_exception__handler(
            str(json.loads(ex.context.response.raw_body)), module
        )
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def get_resource_pool_id(module, resource_pool, protection_source_id):
    """
    function to get the resource pool id, parsing the protection source nodes tree structure
    :param module: object that holds parameters passed to the module
    :param resource_pool: resource pool name
    :param protection_source_id: protection source id, parent source where we search for resource pool
    :return:
    """
    try:
        nodes = []
        protection_sources = cohesity_client.protection_sources.list_protection_sources(
            id=protection_source_id, exclude_types=["kVirtualMachine"]
        )
        for node in protection_sources[0].nodes:
            if "nodes" in node:
                nodes.append(node["nodes"])
            if (
                ("protectionSource" in node)
                and (node["protectionSource"]["name"] == resource_pool)
                and node["protectionSource"]["vmWareProtectionSource"]["type"]
                == "kResourcePool"
            ):
                return node["protectionSource"]["id"]
        while len(nodes) != 0:
            objects = nodes.pop()
            for node in objects:
                if "nodes" in node:
                    nodes.append(node["nodes"])
                if (
                    ("protectionSource" in node)
                    and (node["protectionSource"]["name"] == resource_pool)
                    and node["protectionSource"]["vmWareProtectionSource"]["type"]
                    == "kResourcePool"
                ):
                    return node["protectionSource"]["id"]
        if module.check_mode:
            return False
        raise__cohesity_exception__handler(
            "Failed to find the resource pool " + str(resource_pool), module
        )
    except APIException as ex:
        raise__cohesity_exception__handler(
            str(json.loads(ex.context.response.raw_body)), module
        )
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def wait(module):
    """
    function to wait for clone task, waits for wait minutes passed to the module
    :param module: object that holds parameters passed to the module
    :return:
    """
    if module.params.get("wait_for_job"):
        wait_time = module.params.get("wait_minutes")
        while wait_time > 0:
            clone_exist, clone_details = get_clone_task(module, True)
            if not clone_exist:
                return "The clone VMs request is accepted. Failed to check clone status during wait time"
            elif clone_exist and clone_details.error:
                raise__cohesity_exception__handler("The clone VMs task failed", module)
            elif (
                clone_exist
                and clone_details.status == "kFinished"
                and not clone_details.error
            ):
                return "The clone VMs task is successful"
            time.sleep(SLEEP_TIME_SECONDS)
            wait_time = wait_time - 1
        return "The clone VMs request is accepted. The task is not finished in the wait time"
    else:
        return "The clone VMs request is accepted"


def clone_vm(module):
    """
    function to clone the VMs
    :param module: object that holds parameters passed to the module
    :return:
    """
    try:
        protection_job_details = get_protection_job_details(module)
        objects = []
        timestamp = module.params.get("backup_timestamp")
        resource_pool = module.params.get("resource_pool")
        for vm in module.params.get("vm_names"):
            object_details = get_snapshot_details(
                module, timestamp, vm, protection_job_details.id
            )
            objects.append(object_details)
        clone_request = CloneTaskRequest()
        clone_request.name = module.params.get("name")
        clone_request.target_view_name = module.params.get("view_name")
        clone_request.mtype = "kCloneVMs"
        clone_request.new_parent_id = protection_job_details.parent_source_id
        clone_request.vmware_parameters = VmwareCloneParameters()
        if module.params.get("suffix"):
            clone_request.vmware_parameters.suffix = module.params.get("suffix")
        if module.params.get("prefix"):
            clone_request.vmware_parameters.prefix = module.params.get("prefix")
        clone_request.vmware_parameters.powered_on = module.params.get("power_on")
        clone_request.vmware_parameters.resource_pool_id = get_resource_pool_id(
            module, resource_pool, protection_job_details.parent_source_id
        )
        clone_request.objects = objects
        clone_details = cohesity_client.restore_tasks.create_clone_task(
            body=clone_request
        )
        if not clone_details:
            raise__cohesity_exception__handler("Failed to clone VMs", module)
        status_message = wait(module)
        result = dict(
            changed=True,
            msg=status_message,
            id=clone_details.id,
            task_name=module.params.get("name"),
        )
        module.exit_json(**result)
    except APIException as ex:
        raise__cohesity_exception__handler(
            str(json.loads(ex.context.response.raw_body)), module
        )
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def destroy_clone(module, clone_id):
    """
    function to tear down clone
    :param module: object that holds parameters passed to the module
    :param clone_id: clone task id
    :return:
    """
    try:
        cohesity_client.restore_tasks.delete_public_destroy_clone_task(id=clone_id)
    except APIException as ex:
        if "destroyed" in json.loads(ex.context.response.raw_body)["message"]:
            status = dict(
                changed=False,
                msg="Cohesity clone task is already destroyed",
                task_name=module.params.get("name"),
            )
            module.exit_json(**status)
        else:
            raise__cohesity_exception__handler(
                str(json.loads(ex.context.response.raw_body)), module
            )
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def main():
    # => Load the default arguments including those specific to the Cohesity clone task.
    argument_spec = cohesity_common_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            state=dict(choices=["present", "absent"], default="present"),
            job_name=dict(type="str", required=True),
            view_name=dict(type="str"),
            backup_timestamp=dict(type="str", default=""),
            start_timestamp=dict(type="str", default=""),
            end_timestamp=dict(type="str", default=""),
            environment=dict(choices=["VMware"], default="VMware"),
            vm_names=dict(type="list", required=True, elements="str"),
            wait_for_job=dict(type="bool", default=True),
            prefix=dict(type="str", default=""),
            suffix=dict(type="str", default=""),
            power_on=dict(type="bool", default=True),
            network_connected=dict(type="bool", default=True),
            wait_minutes=dict(type="int", default=30),
            resource_pool=dict(type="str", required=True),
        )
    )

    # => Create a new module object
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    results = dict(
        changed=False,
        msg="Attempting to manage Cohesity Clone",
        state=module.params.get("state"),
    )

    global cohesity_client
    base_controller = BaseController()
    base_controller.global_headers["user-agent"] = "cohesity-ansible/v1.1.5"
    cohesity_client = get_cohesity_client(module)
    clone_exists, clone_details = get_clone_task(module, False)

    if module.check_mode:
        check_mode_results = dict(
            changed=False, msg="Check Mode: Cohesity clone task doesn't exist", id=""
        )
        if module.params.get("state") == "present":
            if clone_exists:
                check_mode_results[
                    "msg"
                ] = "Check Mode: Cohesity clone task is already present. No changes"
                check_mode_results["id"] = clone_details.id
            else:
                check_mode_results["changed"] = True
                check_mode_results[
                    "msg"
                ] = "Check Mode: Cohesity clone task doesn't exist. This action would clone VMs"
                job_details = get_protection_job_details(module)
                if not job_details:
                    check_mode_results[
                        "msg"
                    ] += "Job '%s' doesn't exist in the cluster" % module.params.get(
                        "job_name"
                    )
                    check_mode_results["changed"] = False
                resource_pool_id = get_resource_pool_id(
                    module,
                    module.params.get("resource_pool"),
                    job_details.parent_source_id,
                )
                if not resource_pool_id:
                    check_mode_results["msg"] += (
                        "Resource pool '%s' is not available in "
                        "the server" % module.params.get("resource_pool")
                    )
                    check_mode_results["changed"] = False

        else:
            if clone_exists:
                check_mode_results["msg"] = (
                    "Check Mode: Cohesity clone task is present."
                    "This action would tear down the Cohesity Clone."
                )
                check_mode_results["id"] = clone_details.id
                check_mode_results["changed"] = True
            else:
                check_mode_results[
                    "msg"
                ] = "Check Mode: Cohesity Clone task doesn't exist. No changes."
        module.exit_json(**check_mode_results)

    elif module.params.get("state") == "present":
        if clone_exists:
            results = dict(
                changed=False,
                msg="The clone task with specified name is already present",
                id=clone_details.id,
                name=module.params.get("name"),
            )
        else:
            clone_vm(module)

    elif module.params.get("state") == "absent":
        if clone_exists:
            destroy_clone(module, clone_details.id)
            results = dict(
                changed=True,
                msg="Cohesity clone is destroyed",
                id=clone_details.id,
                task_name=module.params.get("name"),
            )
        else:
            results = dict(
                changed=False,
                msg="Cohesity clone task doesn't exist",
                task_name=module.params.get("name"),
            )
    else:
        module.fail_json(
            msg="Invalid State selected: {0}".format(module.params.get("state")),
            changed=False,
        )

    module.exit_json(**results)


if __name__ == "__main__":
    main()
