#!/usr/bin/python
# Copyright (c) 2023 Cohesity Inc


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
  backup_id:
    description:
      - "Optional Cohesity ID to use as source for the Restore operation.  If not selected, the most recent RunId will be used"
    type: int
  backup_timestamp:
    description:
      - "Future option to identify backups based on a timestamp"
      - "Currently not implemented."
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
  datastore_name:
    description:
      - "Specifies the datastore where the files should be recovered to. This field is required to recover objects to"
      - "a different resource pool or to a different parent source. If not specified, objects are recovered to their original"
      - "datastore locations in the parent source."
    type: str
  endpoint:
    description:
      - "Specifies the network endpoint of the Protection Source where it is reachable. It could"
      - "be an URL or hostname or an IP address of the Protection Source or a NAS Share/Export Path."
    required: true
    type: str
  environment:
    choices:
      - VMware
    default: VMware
    description:
      - "Specifies the environment type (such as VMware) of the Protection Source this Job"
      - "is protecting. Supported environment types include 'VMware'"
    required: false
    type: str
  interface_group_name:
    description:
      - "Specifies the interface name to connect after restoring the VM."
    type: str
  job_name:
    description:
      - "Name of the Protection Job"
    required: false
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
  network_name:
    description:
      - "Specifies a network name to be attached to the cloned or recovered object."
    type: str
  power_state:
    default: true
    description:
      - "Specifies the power state of the cloned or recovered objects. By default, the cloned or recovered objects are powered off."
    type: bool
  prefix:
    description:
      - "Specifies a prefix to prepended to the source object name to derive a new name for the recovered or cloned object."
    type: str
  recovery_process_type:
    default: InstantRecovery
    description:
      - "Specifies the recovery type."
    type: str
  resource_pool_name:
    description:
      - "Specifies the resource pool name where the cloned or recovered objects are attached."
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
  suffix:
    description:
      - "Specifies a suffix to appended to the original source object name to derive a new name for the recovered or cloned object"
    type: str
  vm_folder_name:
    description:
      - "Specifies a folder name where the VMs should be restored."
    type: str
  vm_names:
    description:
      - "Array of Virtual Machines to restore"
    elements: str
    required: false
    type: list
  wait_for_job:
    default: true
    description:
      - "Should wait until the Restore Job completes"
    type: bool
  wait_minutes:
    default: 20
    description:
      - "Number of minutes to wait until the job completes."
    type: int
extends_documentation_fragment:
- cohesity.dataprotect.cohesity
short_description: "Migrate one or more Virtual Machines from Cohesity Protection Jobs"
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


def get_source_details(module):
    """
    Get VMware protection source details
    :param module: object that holds parameters passed to the module.
    :return:
    """
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = get__cohesity_auth__token(module)
    try:
        uri = (
            "https://"
            + server
            + "/irisservices/api/v1/public/protectionSources/rootNodes?environments=kVMware"
        )
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
            "user-agent": "cohesity-ansible/v2.3.4",
        }
        response = open_url(
            url=uri,
            headers=headers,
            validate_certs=validate_certs,
            method="GET",
            timeout=REQUEST_TIMEOUT,
        )
        response = json.loads(response.read())
        source_details = dict()
        for source in response:
            if source["protectionSource"][
                "name"
            ] == module.params.get("endpoint"):
                source_details["id"] = source["protectionSource"]["id"]
        if not source_details:
            module.fail_json(
                changed=False, msg="Can't find the endpoint on the cluster"
            )
        return source_details
    except urllib_error.URLError as e:
        # => Capture and report any error messages.
        raise__cohesity_exception__handler(e.read(), module)
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def get_backup_job_run_id(module, job_id):
    """
    Get Backup job run Id.
    :param module: object that holds parameters passed to the module
    :param job_id: id of the backup job.
    :return:
    """
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = get__cohesity_auth__token(module)
    try:
        uri = (
            "https://"
            + server
            + "/v2/data-protect/protection-groups/%s/runs" % str(job_id)
        )
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
            "user-agent": "cohesity-ansible/v2.3.4",
        }
        response = open_url(
            url=uri,
            headers=headers,
            validate_certs=validate_certs,
            method="GET",
            timeout=REQUEST_TIMEOUT,
        )
        response = json.loads(response.read())
        if response["runs"]:
            return response["runs"][0]["id"], response["runs"][0]["protectionGroupInstanceId"]
        else:
            return None, None
    except urllib_error.URLError as e:
        # => Capture and report any error messages.
        raise__cohesity_exception__handler(e.read(), module)
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def get_vmware_source_objects(module, source_id):
    """
    :param module: object that holds parameters passed to the module
    :param source_id: protection source id
    :return:
    """
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = get__cohesity_auth__token(module)
    try:
        uri = (
            "https://"
            + server
            + "/irisservices/api/v1/public/protectionSources?id="
            + str(source_id)
            + "&excludeTypes=kVirtualMachine"
            + "&includeDatastores=true"
            + "&includeNetworks=true"
            + "&includeVMFolders=true"
        )
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
            "user-agent": "cohesity-ansible/v2.3.4",
        }

        response = open_url(
            url=uri,
            method="GET",
            headers=headers,
            validate_certs=validate_certs,
            timeout=REQUEST_TIMEOUT,
        )
        response = json.loads(response.read())
        return response
    except urllib_error.URLError as e:
        # => Capture and report any error messages.
        raise__cohesity_exception__handler(e.read(), module)
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def get_vmware_object_id(source_objects, object_name, object_type):
    """
    :param source_objects: protection source object tree
    :param object_name: resource pool name or datastore name
    :param object_type: type of the object like kResourcePool, kDatastore
    :return:
    """
    nodes = []
    for node in source_objects:
        if "nodes" in node:
            nodes.append(node["nodes"])
        if (
            ("protectionSource" in node)
            and (node["protectionSource"]["name"] == object_name)
            and node["protectionSource"]["vmWareProtectionSource"]["type"]
            == object_type
        ):
            return node["protectionSource"]["id"]

    while len(nodes) != 0:
        objects = nodes.pop()
        for node in objects:
            if "nodes" in node:
                nodes.append(node["nodes"])
            if (
                ("protectionSource" in node)
                and (node["protectionSource"]["name"] == object_name)
                and node["protectionSource"]["vmWareProtectionSource"]["type"]
                == object_type
            ):
                return node["protectionSource"]["id"]
    return None


def get__vmware_snapshot_information__by_source(module, self, source_details):
    """
    Get the snapshot information using environment, VMname and source id filters
    :param module: object that holds parameters passed to the module
    :param self: restore task details
    :param source_details: parent protection source details
    :return:
    """
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = self["token"]
    try:
        uri = (
            "https://"
            + server
            + "/irisservices/api/v1/public/restore/objects"
            + "?environments=kVMware&search="
            + quote(self["restore_obj"]["vmname"])
            + "&registeredSourceIds="
            + str(source_details["id"])
        )

        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
            "user-agent": "cohesity-ansible/v2.3.4",
        }
        objects = open_url(
            url=uri,
            headers=headers,
            validate_certs=validate_certs,
            timeout=REQUEST_TIMEOUT,
        )
        objects = json.loads(objects.read())
        return objects
    except urllib_error.URLError as e:
        # => Capture and report any error messages.
        raise__cohesity_exception__handler(e.read(), module)
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


# => Return the Protection Job information based on the Environment and Job Name
def get__job_information__for_restore(module, self):
    # => Gather the Protection Jobs by Environment to allow us
    # => to verify that the Job exists and feed that into the
    # => snapshot collection.
    job_output = get__protection_jobs__by_environment(module, self)

    # => There will be a lot of potential jobs.  Return only the
    # => one that matches our job_name
    job_data = [job for job in job_output if job["name"] == self["job_name"]]

    if not job_data:
        failure = dict(
            changed=False,
            job_name=self["job_name"],
            environment=self["environment"],
            msg="Failed to find chosen Job name for the selected Environment Type.",
        )
        module.fail_json(**failure)
    else:
        # => Since we are filtering out any job that matches our name
        # => we will need to properly just grab the first element as
        # => it is returned as an array.
        return job_data[0]


def get_snapshot_information_for_vmname(module, self):
    restore_objects = []
    job_data = dict()
    job_data["uid"] = dict(clusterId="", clusterIncarnationId="", id="")
    if self["job_name"]:
        # => Return the Protection Job information based on the Environment and Job Name
        job_data = get__job_information__for_restore(module, self)
    else:
        source_details = get_source_details(module)
    # => Create a restore object for each Virtual Machine
    for vmname in self["vm_names"]:
        # => Build the Restore Dictionary Object
        restore_details = dict(
            jobRunId="",
            jobUid=dict(
                clusterId=job_data["uid"]["clusterId"],
                clusterIncarnationId=job_data["uid"]["clusterIncarnationId"],
                id=job_data["uid"]["id"],
            ),
            startedTimeUsecs="",
        )
        self["restore_obj"] = restore_details.copy()
        self["restore_obj"]["vmname"] = vmname
        if self["job_name"]:
            output = get__vmware_snapshot_information__by_vmname(module, self)
        else:
            output = get__vmware_snapshot_information__by_source(
                module, self, source_details
            )

        if not output or output["totalCount"] == 0:
            failure = dict(
                changed=False,
                job_name=self["job_name"],
                vmname=vmname,
                environment=self["environment"],
                msg="Failed to find a snapshot on the cluster",
            )
            module.fail_json(**failure)

        # => TODO: Add support for selecting a previous backup.
        # => For now, let's just grab the most recent snapshot.
        success = False
        # when job name is given, select the most recent snapshot from the job
        if self["job_name"]:
            for snapshot_info in output.get("objectSnapshotInfo", []):
                if snapshot_info["objectName"] == vmname:
                    snapshot_detail = snapshot_info["versions"][0]
                    if "jobRunId" in self:
                        snapshot_detail = [
                            jobRun
                            for jobRun in snapshot_info["versions"]
                            if jobRun["jobRunId"] == int(self["jobRunId"])
                        ][0]

                    restore_details["protectionSourceId"] = snapshot_info[
                        "snapshottedSource"
                    ]["id"]
                    restore_details["jobRunId"] = snapshot_detail["jobRunId"]
                    restore_details["startedTimeUsecs"] = snapshot_detail[
                        "startedTimeUsecs"
                    ]
                    success = True
        else:
            # when job name is not given, select the most recent snapshot across all the jobs
            timestamp = 0
            for snapshot_info in output["objectSnapshotInfo"]:
                if (
                    snapshot_info["objectName"] == vmname
                    and snapshot_info["versions"][0]["startedTimeUsecs"] >= timestamp
                ):
                    timestamp = snapshot_info["versions"][0]["startedTimeUsecs"]
                    restore_details["protectionSourceId"] = snapshot_info[
                        "snapshottedSource"
                    ]["id"]
                    restore_details["jobRunId"] = snapshot_info["versions"][0][
                        "jobRunId"
                    ]
                    restore_details["jobUid"] = snapshot_info["jobUid"]
                    restore_details["startedTimeUsecs"] = snapshot_info["versions"][0][
                        "startedTimeUsecs"
                    ]
                    success = True
        if not success:
            module.fail_json(msg="No Snapshot Found for the VM: " + vmname)
        restore_objects.append(restore_details)
    return restore_objects


# => Perform the Restore of a Virtual Machine to the selected ProtectionSource Target
def start_restore__vms(module, self):
    payload = self.copy()
    payload.pop("vm_names", None)
    return start_restore(module, "/irisservices/api/v1/public/restore/recover", payload)


def start_restore(module, uri, self):
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = self["token"]
    try:
        uri = "https://" + server + uri
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
            "user-agent": "cohesity-ansible/v2.3.4",
        }
        payload = self.copy()

        # => Remove the Authorization Token from the Payload
        payload.pop("token", None)

        data = json.dumps(payload)

        response = open_url(
            url=uri,
            data=data,
            headers=headers,
            validate_certs=validate_certs,
            timeout=REQUEST_TIMEOUT,
        )

        response = json.loads(response.read())

        # => Remove the Job name as it will be duplicated back to our process.
        response.pop("name")

        return response
    except urllib_error.URLError as e:
        # => Capture and report any error messages.
        raise__cohesity_exception__handler(e.read(), module)
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def create_migration_task(module, body):
    """
    """
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = get__cohesity_auth__token(module)
    try:
        uri = (
            "https://"
            + server
            + "/v2/data-protect/recoveries"
        )
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
            "user-agent": "cohesity-ansible/v2.3.4",
        }
        response = open_url(
            url=uri,
            headers=headers,
            validate_certs=validate_certs,
            method="POST",
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
            name=dict(type="str", required=True),
            state=dict(choices=["present", "absent"], default="present"),
            endpoint=dict(type="str", required=True),
            job_name=dict(type="str", default=""),
            backup_id=dict(type="int"),
            backup_timestamp=dict(type="str"),
            # => Currently, the only supported environments types are list in the choices
            # => For future enhancements, the below list should be consulted.
            # => 'SQL', 'View', 'Puppeteer', 'Pure', 'Netapp', 'HyperV', 'Acropolis', 'Azure'
            environment=dict(choices=["VMware"], default="VMware"),
            vm_names=dict(type="list", elements="str"),
            wait_for_job=dict(type="bool", default=True),
            wait_minutes=dict(type="int", default=20),
            datastore_name=dict(type="str", default=""),
            interface_group_name=dict(type="str"),
            network_connected=dict(type="bool", default=True),
            network_name=dict(type="str"),
            power_state=dict(type="bool", default=True),
            prefix=dict(type="str"),
            resource_pool_name=dict(type="str", default=""),
            recovery_process_type=dict(type="str", default="InstantRecovery"),
            suffix=dict(type="str"),
            vm_folder_name=dict(type="str", required=False),
        )
    )

    # => Create a new module object
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    results = dict(
        changed=False,
        msg="Attempting to manage Protection Source",
        state=module.params.get("state"),
    )

    job_details = dict(
        token=get__cohesity_auth__token(module),
        endpoint=module.params.get("endpoint"),
        job_name=module.params.get("job_name"),
        environment=module.params.get("environment"),
    )
    if module.params.get("job_name"):
        job_details["name"] = (
            module.params.get("job_name") + ": " + module.params.get("name")
        )
    else:
        job_details["name"] = module.params.get("name")

    if module.params.get("backup_id"):
        job_details["jobRunId"] = module.params.get("backup_id")

    if module.params.get("backup_timestamp"):
        job_details["backup_timestamp"] = module.params.get("backup_timestamp")

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
                check_mode_results["id"] = job_exists
                restore_to_source_details = get_source_details(module)
                restore_to_source_objects = get_vmware_source_objects(
                    module, restore_to_source_details["id"]
                )

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

            run_params = list()
            if environment != "kVMware":
                # => This error should never happen based on the set assigned to the parameter.
                # => However, in case, we should raise an appropriate error.
                module.fail_json(
                    msg="Invalid Environment Type selected: {0}".format(
                        module.params.get("environment")
                    ),
                    changed=False,
                )

            job_details["vm_names"] = module.params.get("vm_names")
            # Get the job run id and object Id.
            source_details = get_source_details(module)
            source_id = source_details["id"]
            protected_objects = (
                cohesity_client.protection_sources.list_protected_objects(
                    environment=environment, id=source_id
                )
            )
            vm_names = module.params.get("vm_names")
            restore_to_source_objects = get_vmware_source_objects(module, source_id)
            for obj in protected_objects:
                if obj.protection_source.name in vm_names:
                    # Check if job name if provided or else select the first job from the list.
                    job_id = None
                    for job in obj.protection_jobs:
                        if (
                            not job_details["job_name"]
                            or job.name == job_details["job_name"]
                        ):
                            job_id = job.id
                            vm_names.remove(obj.protection_source.name)
                            break
                    if not job_id:
                        module.fail_json(msg="Backup Job is not available")
                    run_id, instance_id = get_backup_job_run_id(module, job_id)
                    obj_dict = dict(
                        protectionGroupRunId=run_id,
                        protectionGroupInstanceId=instance_id
                    )
                    run_params.append(obj_dict)
            if module.params.get("resource_pool_name"):
                resource_pool_id = get_vmware_object_id(
                    restore_to_source_objects,
                    module.params.get("resource_pool_name"),
                    "kResourcePool",
                )
                if not resource_pool_id:
                    check_mode_results["msg"] += (
                        "Resource Pool %s is not available in the source"
                        % module.params.get("resource_pool_name")
                    )
            if module.params.get("datastore_name"):
                datastore_id = get_vmware_object_id(
                    restore_to_source_objects,
                    module.params.get("datastore_name"),
                    "kDatastore",
                )
                if not datastore_id:
                    check_mode_results["msg"] += (
                        "Datastore %s is not available in the source"
                        % module.params.get("datastore_name")
                    )
            datastores = [dict(id=datastore_id, parentId=source_id)]
            new_network_config = dict(disableNetwork=False, preserveMacAddress=False)
            if module.params.get("network_name"):
                network_name = module.params.get("network_name")
                network_id = get_vmware_object_id(
                    restore_to_source_objects, network_name, "kNetwork"
                )
                if not network_id:
                    module.fail_json(
                        msg="Failed to find network with name %s" % network_name,
                        changed=False,
                    )
                new_network_config["networkPortGroup"] = dict(id=network_id)
            v_center_params = dict(
                source=dict(id=source_id),
                networkConfig=dict(
                    detachNetwork=True, newNetworkConfig=new_network_config
                ),
                datastores=datastores,
                resourcePool=dict(id=resource_pool_id)
            )
            if module.params.get("vm_folder_name"):
                vm_folder_name = module.params.get("vm_folder_name")
                vm_folder_id = get_vmware_object_id(
                    restore_to_source_objects, vm_folder_name, "kFolder"
                )
                if not vm_folder_id:
                    module.fail_json(
                        msg="Failed to find folder with name %s"
                        % vm_folder_name,
                        changed=False,
                    )
                v_center_params["vmFolder"] = dict(id=vm_folder_id)
            new_source_config = dict(
                sourceType="kVCenter", vCenterParams=v_center_params
            )
            recovery_target_config = dict(
                recoverToNewSource=True, newSourceConfig=new_source_config
            )
            vmware_target_params = dict(
                recoveryTargetConfig=recovery_target_config,
                recoveryProcessType="CopyRecovery",
                powerOnVms=True,
                diskProvisionType="kBackedUpDiskType",
                continueOnError=False,
                isMultiStageRestore=True,
            )
            rename_recovered_vms_params = dict()
            if module.params.get("prefix"):
                rename_recovered_vms_params["prefix"] = module.params.get("prefix")
            if module.params.get("suffix"):
                rename_recovered_vms_params["suffix"] = module.params.get("suffix")
            if rename_recovered_vms_params:
                vmware_target_params["renameRecoveredVmsParams"] = rename_recovered_vms_params
            if module.params.get("interface_group_name"):
                iface_group = module.params.get("interface_group_name")
                vlans = cohesity_client.vlan.get_vlans()
                for vlan in vlans:
                    if vlan.iface_group_name == iface_group:
                        vlan_id = vlan.id
                        vmware_target_params["vlanConfig"] = dict(id=vlan_id)
                        break
            recover_vm_params = dict(
                targetEnvironment=environment,
                recoverProtectionGroupRunsParams=run_params,
                vmwareTargetParams=vmware_target_params,
            )
            body = dict(
                name=task_name,
                snapshotEnvironment=environment,
                vmwareParams=dict(
                    recoveryAction="RecoverVMs", recoverVmParams=recover_vm_params
                ),
            )
            response = create_migration_task(module, body)

            results = dict(
                changed=True,
                msg="Registration of Cohesity Migrate Job Complete",
                name=task_name,
            )

    elif module.params.get("state") == "absent":

        results = dict(
            changed=False,
            msg="Cohesity Restore: This feature (absent) has not be implemented yet.",
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
