#!/usr/bin/python
# Copyright (c) 2023 Cohesity Inc


from __future__ import absolute_import, division, print_function

__metaclass__ = type

# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = """
---
author: Naveena (@naveena-maplelabs)
description:
  - Ansible Module used to start a Cohesity Migration Job on a Cohesity Cluster.
  - When executed in a playbook, the Cohesity migration Job will be validated
    and the appropriate state action
  - will be applied.
module: cohesity_migrate_vm
options:
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
  cluster_compute_resource:
    description:
      - If the cluster compute resource is specified, VM will be recovered to resource pool
        under the specified compute resource.
    type: str
  datacenter:
    description:
      - If multiple datastore exists, datacenter and cluster resource details
        are used to uniquely identify the resourcepool.
    type: str
  datastore_name:
    description:
      - Specifies the datastore where the files should be recovered to. This
        field is required to recover objects to
      - a different resource pool or to a different parent source. If not
        specified, objects are recovered to their original
      - datastore locations in the parent source.
    type: str
    required: true
  detach_network:
    default: false
    description:
      - If this is set to true, then the network will be detached from the
        recovered VMs. All the other networking parameters set will be ignored
        if set to true
    type: bool
  enable_network:
    default: true
    description:
      - Specifies whether the attached network should be left in enabled state
    type: bool
  endpoint:
    description:
      - Specifies the network endpoint of the Protection Source where it is
        reachable. It could
      - be an URL or hostname or an IP address of the Protection Source or a NAS
        Share/Export Path.
    required: true
    type: str
  environment:
    choices:
      - VMware
    default: VMware
    description:
      - Specifies the environment type (such as VMware) of the Protection Source
        this Job
      - is protecting. Supported environment types include 'VMware'
    required: false
    type: str
  interface_group_name:
    description:
      - Specifies the interface name to connect after restoring the VM.
    type: str
  name:
    description:
      - Descriptor to assign to the Recovery Job.  The Recovery Job name will
        consist of the name_date_time format.
    required: false
    type: str
  network_name:
    description:
      - Specifies a network name to be attached to the migrated object.
    type: str
  power_state:
    default: true
    description:
      - Specifies the power state of the recovered objects. By default, the
        migrated objects are powered off.
    type: bool
  prefix:
    description:
      - Specifies a prefix to prepended to the source object name to derive a
        new name for the recovered object.
    type: str
  preserve_mac_address:
    default: false
    description:
      - Specifies whether to preserve the MAC address of the migrated VM.
    type: bool
  recovery_process_type:
    default: CopyRecovery
    description:
      - Specifies the recovery type.
    type: str
    choices:
      - "CopyRecovery"
      - "InstantRecovery"
  resource_pool_name:
    description:
      - Specifies the resource pool name where the migrated objects are attached.
    type: str
    required: true
  start_time:
    description:
      - Restore tasks will be filtered by a start time specified. If not
        provided the start time is set to the last week.
    type: str
  end_time:
    description:
      - Restore tasks will be filtered by a start time specified. If not
        provided the end time is the current time.
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
  suffix:
    description:
      - Specifies a suffix to appended to the original source object name to
        derive a new name for the migrated object
    type: str
  vm_folder_name:
    description:
      - Specifies a folder name where the VMs should be restored.
    type: str
  job_vm_pair:
    description:
      - Key value pair with job names as key and list of Virtual Machines to
        migrate
    required: true
    type: dict
extends_documentation_fragment:
  - cohesity.dataprotect.cohesity
short_description: Migrate one or more Virtual Machines from Cohesity Migrate Jobs
version_added: 1.1.6
"""

EXAMPLES = """

# Migrate a single Virtual Machine
- name: Migrate a Virtual Machine
  cohesity_migrate_vm:
    cluster: cohesity.lab
    username: admin
    password: password
    state: present
    name: "Ansible Test VM Migrate"
    endpoint: "myvcenter.cohesity.demo"
    environment: "VMware"
    job_vm_pair:
      "Backup_job":
        - chs-win-01
        - chs-win-02

# Migrate multiple Virtual Machines from a specific snapshot with a new prefix and disable the network
- name: Migrate a Virtual Machine
  cohesity_migrate_vm:
    cluster: cohesity.lab
    username: admin
    password: password
    state: present
    name: "Ansible Test VM Migrate"
    endpoint: "myvcenter.cohesity.demo"
    environment: "VMware"
    job_vm_pair:
      "Backup_job":
        - chs-win-01
        - chs-win-02
      "Protect_VM":
        - chs-ubun-01
        - chs-ubun-02
    prefix: "rst-"

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
    # payload["count"] = 1

    restore_tasks = get__restore_job__by_type(module, payload)

    if restore_tasks:
        task_list = [task for task in restore_tasks if task["name"] == self["name"]]
        for task in task_list:
            if task["status"] not in ["kFinished", "kCancelled"]:
                return True, task["status"]
    return False, None


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
            "user-agent": "cohesity-ansible/v1.1.6",
        }
        response = open_url(
            url=uri,
            headers=headers,
            validate_certs=validate_certs,
            method="GET",
            timeout=REQUEST_TIMEOUT,
        )
        response = json.loads(response.read())
        source_details = {}
        for source in response:
            if source["protectionSource"]["name"] == module.params.get("endpoint"):
                source_details["id"] = source["protectionSource"]["id"]
        if not source_details:
            module.fail_json(
                changed=False,
                msg="Protection Source '%s' is not currently registered"
                % module.params.get("endpoint"),
            )
        return source_details
    except urllib_error.URLError as e:
        # => Capture and report any error messages.
        raise__cohesity_exception__handler(e.read(), module)
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def get_vm_folder_id(module, source_id, resource_pool_id):
    """
    Check VM folder name exists in the source.

    :param module: Source Id of the Vcenter source.
    :return vm folder id.
    """
    folder_id = None
    folder_name = module.params.get("vm_folder_name")
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = get__cohesity_auth__token(module)
    try:
        uri = (
            "https://"
            + server
            + "/irisservices/api/v1/vmwareFolders?vCenterId=%s&resourcePoolId=%s" % (
                source_id, resource_pool_id)
        )
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
            "user-agent": "cohesity-ansible/v1.1.6",
        }
        response = open_url(
            url=uri,
            headers=headers,
            validate_certs=validate_certs,
            method="GET",
            timeout=REQUEST_TIMEOUT,
        )
        response = json.loads(response.read())
        for obj in response.get("vmFolders", []):
            if obj.get("displayName") == folder_name:
               folder_id = obj["id"]
               break
        if not folder_id:
            module.fail_json(
                changed=False,
                msg="Couldn't find VM folder with name %s" % folder_name,
            )
        return folder_id
    except urllib_error.URLError as e:
        # => Capture and report any error messages.
        raise__cohesity_exception__handler(e.read(), module)
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def get_resource_pool_id(module, source_id):
    """
    Check resource pool name exists in the source.
    1) If Cluster Compute Resource is provided, resource pool name under
    cluster will be returned.
    2) If multiple datastore exists, datacenter and cluster resource details
    are used to uniquely identify the resourcepool.

    :param module: Source Id of the Vcenter source.
    :return resource pool id.
    """
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = get__cohesity_auth__token(module)
    try:
        uri = (
            "https://"
            + server
            + "/irisservices/api/v1/resourcePools?vCenterId=%s" % source_id
        )
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
            "user-agent": "cohesity-ansible/v1.1.6",
        }
        response = open_url(
            url=uri,
            headers=headers,
            validate_certs=validate_certs,
            method="GET",
            timeout=REQUEST_TIMEOUT,
        )
        pool_id = None
        response = json.loads(response.read())
        name = module.params.get("resource_pool_name")
        cluster = module.params.get("cluster_compute_resource")
        datacenter = module.params.get("datacenter")
        res_pool_count = 0
        for obj in response:
            if (cluster and obj.get("cluster", {}).get("displayName") != cluster) or (
                datacenter
                and obj.get("dataCenter", {}).get("displayName") != datacenter
            ):
                continue
            if obj["resourcePool"]["displayName"] == name:
                pool_id = obj["resourcePool"]["id"]
                res_pool_count += 1
        if res_pool_count > 1:
            module.fail_json(
                changed=False,
                msg="Multiple resource pools are available in the name '%s', "
                "Please provide cluster_compute_resource and datacenter field "
                "to uniquely identify a resource pool." % name,
            )
        return pool_id
    except urllib_error.URLError as e:
        # => Capture and report any error messages.
        raise__cohesity_exception__handler(e.read(), module)
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def get_datastore_id(module, source_id, resource_pool_id):
    """
    Check datastore exists in the source.

    :param module: Source Id and resource pool id of the Vcenter source.
    :return datastore id.
    """
    data_store_id = None
    data_store_name = module.params.get("datastore_name")
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = get__cohesity_auth__token(module)
    try:
        uri = (
            "https://"
            + server
            + "/irisservices/api/v1/datastores?vCenterId=%s&resourcePoolId=%s" % (
                source_id, resource_pool_id)
        )
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
            "user-agent": "cohesity-ansible/v1.1.6",
        }
        response = open_url(
            url=uri,
            headers=headers,
            validate_certs=validate_certs,
            method="GET",
            timeout=REQUEST_TIMEOUT,
        )
        response = json.loads(response.read())
        for obj in response:
            if obj.get("displayName") == data_store_name:
               data_store_id = obj["id"]
               break
        if not data_store_id:
            module.fail_json(
                changed=False,
                msg="Couldn't find datastore with name %s" % data_store_name,
            )
        return data_store_id
    except urllib_error.URLError as e:
        # => Capture and report any error messages.
        raise__cohesity_exception__handler(e.read(), module)
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def get_network_id(module, source_id, resource_pool_id):
    """
    Check network exists in the source.

    :param module: Source Id and resource pool id of the Vcenter source.
    :return network id.
    """
    network_id = None
    network_name = module.params.get("network_name")
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = get__cohesity_auth__token(module)
    try:
        uri = (
            "https://"
            + server
            + "/irisservices/api/v1/networkEntities?vCenterId=%s&resourcePoolId=%s" % (
                source_id, resource_pool_id)
        )
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
            "user-agent": "cohesity-ansible/v1.1.6",
        }
        response = open_url(
            url=uri,
            headers=headers,
            validate_certs=validate_certs,
            method="GET",
            timeout=REQUEST_TIMEOUT,
        )
        response = json.loads(response.read())
        for obj in response:
            if obj.get("displayName") == network_name:
               network_id = obj["id"]
               break
        if not network_id:
            module.fail_json(
                changed=False,
                msg="Couldn't find network with name %s" % network_name,
            )
        return network_id
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
            + "/v2/data-protect/protection-groups/%s/runs?includeObjectDetails=true"
            % str(job_id)
        )
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
            "user-agent": "cohesity-ansible/v1.1.6",
        }
        response = open_url(
            url=uri,
            headers=headers,
            validate_certs=validate_certs,
            method="GET",
            timeout=REQUEST_TIMEOUT,
        )
        response = json.loads(response.read())
        if response.get("runs", []):
            return response["runs"][0]
        else:
            return None
    except urllib_error.URLError as e:
        # => Capture and report any error messages.
        raise__cohesity_exception__handler(e.read(), module)
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def get_backup_job_ids(module, job_names):
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
            + "/v2/data-protect/protection-groups?names=%s" % str(",".join(job_names))
        )
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
            "user-agent": "cohesity-ansible/v1.1.6",
        }
        response = open_url(
            url=uri,
            headers=headers,
            validate_certs=validate_certs,
            method="GET",
            timeout=REQUEST_TIMEOUT,
        )
        response = json.loads(response.read())
        if response["protectionGroups"]:
            return {job["name"]: job["id"] for job in response["protectionGroups"]}
        else:
            return {}
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
            "user-agent": "cohesity-ansible/v1.1.6",
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


def start_restore(module, uri, self):
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = self["token"]
    try:
        uri = "https://" + server + uri
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
            "user-agent": "cohesity-ansible/v1.1.6",
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
    Function to trigger the API call to create a the migration task.
    """
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = get__cohesity_auth__token(module)
    try:
        uri = "https://" + server + "/v2/data-protect/recoveries"
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
            "user-agent": "cohesity-ansible/v1.1.6",
        }
        # module.fail_json(msg=body)
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


def get_objects(module, backup_job_ids):
    """
    Function to get the list of virtual machine run id and snapshot id of
    the protected jobs.
    : return
    """
    try:
        error_list = ""
        objects = []
        run_params = []
        for jobname, vms in module.params.get("job_vm_pair").items():
            if not backup_job_ids.get(jobname, None):
                error_list += (
                    "Backup job '%s' is not available in the cluster." % jobname
                )
                continue
            # If VM list is empty, all the virtual machine objects
            # protected in the job is selected.
            response = get_backup_job_run_id(module, backup_job_ids[jobname])
            if not vms:
                # If only job name is provided without any virtual machines,
                # job run id will be used.
                run_id, instance_id = (
                    response["id"],
                    response["protectionGroupInstanceId"],
                )
                obj_dict = dict(
                    protectionGroupRunId=run_id,
                    protectionGroupInstanceId=instance_id,
                )
                run_params.append(obj_dict)
            else:
                # If object list is provided, snapshot id of the object is
                # fetched.
                available_vms = []
                for obj in response["objects"]:
                    if obj["object"]["name"] in vms:
                        snapshot_id = obj["localSnapshotInfo"]["snapshotInfo"][
                            "snapshotId"
                        ]
                        objects.append(dict(snapshotId=snapshot_id))
                        available_vms.append(obj["object"]["name"])
                        continue
                if len(vms) != len(available_vms):
                    missing_vms = set(vms) - set(available_vms)
                    error_list += (
                        "Couldn't find snapshot Id for following VM(s) %s"
                        % ",".join(missing_vms)
                    )
        return objects, run_params, error_list
    except urllib_error.URLError as e:
        # => Capture and report any error messages.
        raise__cohesity_exception__handler(e.read(), module)
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def get_protection_groups(module):
    """
    Function to get list of protection backup groups.
    :return response
    """
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = get__cohesity_auth__token(module)
    try:
        uri = "https://" + server + "/v2/data-protect/protection-groups?isDeleted=false"
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
            "user-agent": "cohesity-ansible/v1.1.6",
        }
        response = open_url(
            url=uri,
            headers=headers,
            validate_certs=validate_certs,
            method="GET",
            timeout=REQUEST_TIMEOUT,
        )
        response = json.loads(response.read())
        if response and response.get("protectionGroups", None):
            return {
                job["id"].split(":")[-1]: job["id"]
                for job in response["protectionGroups"]
            }
        return response
    except urllib_error.URLError as e:
        # => Capture and report any error messages.
        raise__cohesity_exception__handler(e.read(), module)
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def main():
    # => Load the default arguments including those specific to the Cohesity migrate tasks.
    argument_spec = cohesity_common_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=False),
            state=dict(choices=["present", "absent"], default="present"),
            endpoint=dict(type="str", required=True),
            environment=dict(choices=["VMware"], default="VMware"),
            job_vm_pair=dict(type="dict", required=True),
            datastore_name=dict(type="str", required=True),
            interface_group_name=dict(type="str"),
            network_name=dict(type="str"),
            cluster_compute_resource=dict(type="str"),
            datacenter=dict(type="str"),
            power_state=dict(type="bool", default=True),
            preserve_mac_address=dict(type="bool", default=False),
            enable_network=dict(type="bool", default=True),
            detach_network=dict(type="bool", default=False),
            prefix=dict(type="str"),
            start_time=dict(type="str"),
            end_time=dict(type="str"),
            resource_pool_name=dict(type="str", required=True),
            recovery_process_type=dict(
                type="str",
                choices=["CopyRecovery", "InstantRecovery"],
                default="CopyRecovery",
            ),
            suffix=dict(type="str"),
            vm_folder_name=dict(type="str", required=False),
        )
    )

    # => Create a new module object
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    global cohesity_client
    cohesity_client = get_cohesity_client(module)
    results = dict(
        changed=False,
        msg="Attempting to manage Protection Source",
        state=module.params.get("state"),
    )

    job_details = dict(
        token=get__cohesity_auth__token(module),
        endpoint=module.params.get("endpoint"),
        environment=module.params.get("environment"),
    )
    job_details["name"] = module.params.get("name")

    job_exists, task_status = check__protection_restore__exists(module, job_details)
    source_details = get_source_details(module)
    source_id = source_details["id"] if source_details else None
    if not source_id:
        msg = "Check Mode: " if module.check_mode else ""
        module.fail_json(
            changed=False,
            msg=msg
            + "Protection Source '%s' is not currently registered"
            % job_details["endpoint"],
        )

    if module.check_mode:
        check_mode_results = dict(
            changed=False,
            msg="Check Mode: Cohesity Migrate Job is not currently registered",
            id="",
        )
        error_list = ""
        if module.params.get("state") == "present":
            if job_exists:
                check_mode_results[
                    "msg"
                ] = "Check Mode: Cohesity Migrate Job is currently registered.  No changes"
            else:
                check_mode_results[
                    "msg"
                ] = "Check Mode: Cohesity Migrate Job is not currently registered.  This action would register the Cohesity Migrate Job."
                resource_pool_id = None
                check_mode_results["id"] = job_exists
                restore_to_source_objects = get_vmware_source_objects(module, source_id)
                if module.params.get("resource_pool_name"):
                    job_details["sourceId"] = source_id
                    resource_pool_id = get_resource_pool_id(module, source_id)
                    if not resource_pool_id:
                        error_list += (
                            "Failed to find Resource Pool '%s'"
                            % module.params.get("resource_pool_name")
                        )
                        datacenter = module.params.get("datacenter")
                        cluster_resource = module.params.get("cluster_compute_resource")
                        if datacenter or cluster_resource:
                            error_list += " associated with "
                            error_list += (
                                "datacenter '%s'" % datacenter if datacenter else ""
                            )
                            error_list += (
                                ", " if datacenter and cluster_resource else ""
                            )
                            error_list += (
                                "cluster_compute_resource '%s'." % cluster_resource
                                if cluster_resource
                                else ""
                            )
                if module.params.get("datastore_name") and resource_pool_id:
                    datastore_id = get_datastore_id(module, source_id, resource_pool_id)
                    if not datastore_id:
                        error_list += (
                            "Datastore '%s' is not available in the source."
                            % module.params.get("datastore_name")
                        )
                if module.params.get("network_name") and resource_pool_id:
                    network_name = module.params.get("network_name")
                    network_id = get_network_id(module, source_id, resource_pool_id)
                    if not network_id:
                        error_list += (
                            "Failed to find network with name '%s'." % network_name
                        )
                if module.params.get("vm_folder_name") and resource_pool_id:
                    vm_folder_name = module.params.get("vm_folder_name")
                    vm_folder_id = get_vm_folder_id(
                        module, source_id, resource_pool_id)
                    if not vm_folder_id:
                        error_list += (
                            "Failed to find folder with name '%s'." % vm_folder_name
                        )
                if module.params.get("interface_group_name"):
                    vlan_id = None
                    iface_group = module.params.get("interface_group_name")
                    vlans = cohesity_client.vlan.get_vlans()
                    for vlan in vlans:
                        if vlan.iface_group_name == iface_group:
                            vlan_id = vlan.id
                            break
                    if not vlan_id:
                        error_list += (
                            "Failed to find interface group '%s'" % iface_group
                        )
                backup_job_ids = get_backup_job_ids(
                    module, module.params.get("job_vm_pair").keys()
                )
                objects, run_params, errors = get_objects(module, backup_job_ids)
                error_list += errors
        else:
            if job_exists:
                check_mode_results[
                    "msg"
                ] = "Check Mode: Cohesity Migrate Job is currently registered.  This action would unregister the Cohesity Migrate Job."
                check_mode_results["id"] = job_exists
            else:
                check_mode_results[
                    "msg"
                ] = "Check Mode: Cohesity Migrate Job is not currently registered.  No changes."
        if error_list:
            check_mode_results["msg"] = error_list
        module.exit_json(**check_mode_results)

    elif module.params.get("state") == "present":
        check_mode_results = dict(msg="")
        if job_exists:
            results = dict(
                changed=False,
                msg="The Migrate Job for is already registered, task status %s" % task_status,
                id=job_exists,
                name=job_details["name"],
            )
        else:
            environment = "k" + module.params.get("environment")
            response = []
            t_name = "Migrate_VM" + "_" + datetime.now().strftime("%b_%d_%Y_%I_%M_%p")
            task_name = job_details["name"] or t_name

            if environment != "kVMware":
                # => This error should never happen based on the set assigned to the parameter.
                # => However, in case, we should raise an appropriate error.
                module.fail_json(
                    msg="Invalid Environment Type selected: {0}".format(
                        module.params.get("environment")
                    ),
                    changed=False,
                )

            # Get the job run id and object Id.
            restore_to_source_objects = get_vmware_source_objects(module, source_id)

            job_vm_pair = module.params.get("job_vm_pair")
            # Get the list of job names and ids.
            backup_job_ids = get_backup_job_ids(module, job_vm_pair.keys())
            objects, run_params, errors = get_objects(module, backup_job_ids)
            if errors:
                module.fail_json(errors)
            if module.params.get("resource_pool_name"):
                job_details["sourceId"] = source_id
                resource_pool_id = get_resource_pool_id(module, source_id)
                if not resource_pool_id:
                    error_list = (
                        "Failed to find Resource Pool '%s'"
                        % module.params.get("resource_pool_name")
                    )
                    datacenter = module.params.get("datacenter")
                    cluster_resource = module.params.get("cluster_compute_resource")
                    if datacenter or cluster_resource:
                        error_list += " associated with "
                        error_list += (
                            "datacenter '%s', " % datacenter if datacenter else ""
                        )
                        error_list += (
                            "cluster_compute_resource '%s'." % cluster_resource
                            if cluster_resource
                            else ""
                        )
                    module.fail_json(error_list)
            if module.params.get("datastore_name"):
                datastore_id = get_datastore_id(module, source_id, resource_pool_id)
                if not datastore_id:
                    module.fail_json(
                        "Datastore '%s' is not available in the source"
                        % module.params.get("datastore_name")
                    )
            datastores = [dict(id=datastore_id, parentId=source_id)]
            new_network_config = dict(
                disableNetwork=not module.params.get("enable_network"),
                preserveMacAddress=module.params.get("preserve_mac_address"),
            )
            if module.params.get("network_name"):
                network_name = module.params.get("network_name")
                network_id = get_network_id(module, source_id, resource_pool_id)
                if not network_id:
                    module.fail_json(
                        msg="Failed to find network with name '%s'" % network_name,
                        changed=False,
                    )
                new_network_config["networkPortGroup"] = dict(id=network_id)
            v_center_params = dict(
                source=dict(id=source_id),
                networkConfig=dict(
                    detachNetwork=module.params.get("detach_network"),
                    newNetworkConfig=new_network_config,
                ),
                datastores=datastores,
                resourcePool=dict(id=resource_pool_id),
            )
            if module.params.get("vm_folder_name"):
                vm_folder_name = module.params.get("vm_folder_name")
                vm_folder_id = get_vm_folder_id(
                    module, source_id, resource_pool_id)
                if not vm_folder_id:
                    module.fail_json(
                        msg="Failed to find folder with name '%s'" % vm_folder_name,
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
                recoveryProcessType=module.params.get("recovery_process_type"),
                powerOnVms=True,
                diskProvisionType="kBackedUpDiskType",
                continueOnError=False,
                isMultiStageRestore=True,
            )
            rename_recovered_vms_params = {}
            if module.params.get("prefix"):
                rename_recovered_vms_params["prefix"] = module.params.get("prefix")
            if module.params.get("suffix"):
                rename_recovered_vms_params["suffix"] = module.params.get("suffix")
            if rename_recovered_vms_params:
                vmware_target_params[
                    "renameRecoveredVmsParams"
                ] = rename_recovered_vms_params
            if module.params.get("interface_group_name"):
                vlan_id = None
                iface_group = module.params.get("interface_group_name")
                vlans = cohesity_client.vlan.get_vlans()
                for vlan in vlans:
                    if vlan.iface_group_name == iface_group:
                        vlan_id = vlan.id
                        vmware_target_params["vlanConfig"] = dict(id=vlan_id)
                        break
                if not vlan_id:
                    module.fail_json(
                        msg="Failed to find interface group '%s'" % iface_group,
                        changed=False,
                    )
            recover_vm_params = dict(
                targetEnvironment=environment,
                recoverProtectionGroupRunsParams=run_params,
                vmwareTargetParams=vmware_target_params,
            )
            if not run_params and not objects:
                module.fail_json(
                    msg="Failed to find the VM(s) protected in the cluster."
                )
            body = dict(
                name=task_name,
                snapshotEnvironment=environment,
                vmwareParams=dict(
                    objects=objects,
                    recoveryAction="RecoverVMs",
                    recoverVmParams=recover_vm_params,
                ),
            )
            response = create_migration_task(module, body)

            results = dict(
                changed=True,
                msg="Registration of Cohesity Migrate Job Complete",
                name=task_name,
                id=response["id"],
            )

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
