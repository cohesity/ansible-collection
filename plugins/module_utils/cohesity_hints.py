#
# cohesity_hints
#
# Copyright (c) 2022 Cohesity Inc

#

from __future__ import absolute_import, division, print_function
from http.client import REQUEST_TIMEOUT

__metaclass__ = type

DOCUMENTATION = """
module_utils: cohesity_hints
short_description: The **CohesityHints** utils module provides standard methods for returning query data
from Cohesity Platforms.
version_added: 1.0.3
description:
    - The **CohesityHints** utils module provides standard methods for returning query data
from Cohesity Platforms.

"""


import json
import traceback

try:
    from urllib import quote
except ImportError:
    from urllib.parse import quote

from ansible.module_utils.urls import open_url, urllib_error
from ansible.module_utils.six.moves import urllib_parse

try:
    # => TODO:  Find a better way to handle this!!!
    # => When unit testing, we need to look in the correct location however, when run via ansible,
    # => the expectation is that the modules will live under ansible.
    from cohesity_management_sdk.cohesity_client import CohesityClient
    from ansible_collections.cohesity.dataprotect.plugins.module_utils.cohesity_utilities import (
        raise__cohesity_exception__handler,
    )
except Exception:
    pass


class ParameterViolation(Exception):
    pass


class ProtectionException(Exception):
    pass


class HTTPException(Exception):
    pass


def get_cohesity_client(module):
    """
    function to get cohesity cohesity client
    :param module: object that holds parameters passed to the module
    :return:
    """
    try:
        cluster_vip = module.params.get("cluster")
        username = module.params.get("username")
        password = module.params.get("password")
        domain = "LOCAL"
        if "/" in username:
            user_domain = username.split("/")
            username = user_domain[1]
            domain = user_domain[0]

        elif "@" in username:
            user_domain = username.split("@")
            username = user_domain[0]
            domain = user_domain[1]

        global cohesity_client
        cohesity_client = CohesityClient(
            cluster_vip=cluster_vip, username=username, password=password, domain=domain
        )
        return cohesity_client
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def get__cluster(self):

    try:
        uri = (
            "https://" + self["server"] + "/irisservices/api/v1/public/basicClusterInfo"
        )
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + self["token"],
        }
        cluster = open_url(
            url=uri, headers=headers, validate_certs=self["validate_certs"], timeout=120
        )
        cluster = json.loads(cluster.read())
    except urllib_error.HTTPError as e:
        try:
            json.loads(e.read())["message"]
        except Exception:
            # => For HTTPErrors that return no JSON with a message (bad errors), we
            # => will need to handle this by setting the msg variable to some default.
            # msg = "no-json-data"
            pass
        else:
            raise HTTPException(e.read())
    return cluster


def get__nodes(self):

    try:
        uri = "https://" + self["server"] + "/irisservices/api/v1/public/nodes"
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + self["token"],
        }
        nodes = open_url(
            url=uri, headers=headers, validate_certs=self["validate_certs"], timeout=120
        )
        nodes = json.loads(nodes.read())
    except urllib_error.HTTPError as e:
        try:
            json.loads(e.read())["message"]
        except Exception:
            # => For HTTPErrors that return no JSON with a message (bad errors), we
            # => will need to handle this by setting the msg variable to some default.
            # msg = "no-json-data"
            pass
        else:
            raise HTTPException(e.read())
    return nodes


def get__prot_source__all(self):
    try:
        if self["environment"] in ["UDA", "VMware"]:
            uri = (
                "https://"
                + self["server"]
                + "/irisservices/api/v1/public/protectionSources/rootNodes"
            )
        else:
            uri = (
                "https://"
                + self["server"]
                + "/irisservices/api/v1/public/protectionSources"
            )

        if "environment" in self:
            uri = uri + "?environments=k" + self["environment"]
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + self["token"],
        }
        objects = open_url(
            url=uri, headers=headers, validate_certs=self["validate_certs"], timeout=120
        )
        objects = json.loads(objects.read())
        if len(objects) and self["environment"] not in ["UDA", "VMware"]:
            objects = objects[0]
        return objects
    except urllib_error.URLError as error:
        raise HTTPException(error.read())


def get__prot_source__roots(self):
    try:
        uri = (
            "https://"
            + self["server"]
            + "/irisservices/api/v1/public/protectionSources/rootNodes"
        )

        if "environment" in self:
            uri = uri + "?environments=k" + self["environment"]
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + self["token"],
        }
        objects = open_url(
            url=uri, headers=headers, validate_certs=self["validate_certs"], timeout=120
        )
        objects = json.loads(objects.read())
        return objects
    except urllib_error.URLError as error:
        raise HTTPException(error.read())


def get__prot_policy__all(self):
    try:
        uri = (
            "https://"
            + self["server"]
            + "/irisservices/api/v1/public/protectionPolicies"
        )

        if "policyId" in self:
            uri = uri + "?" + urllib_parse.urlencode({"names": self["policyId"]})
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + self["token"],
        }
        objects = open_url(
            url=uri, headers=headers, validate_certs=self["validate_certs"], timeout=120
        )
        objects = json.loads(objects.read())
        return objects
    except urllib_error as error:
        raise HTTPException(error.read())


def get__prot_job__all(self):
    try:
        uri = "https://" + self["server"] + "/irisservices/api/v1/public/protectionJobs"
        if "environment" in self:
            uri = uri + "?environments=k" + self["environment"]
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + self["token"],
        }
        objects = open_url(
            url=uri, headers=headers, validate_certs=self["validate_certs"], timeout=120
        )
        objects = json.loads(objects.read())

        if "is_deleted" in self:
            if not self["is_deleted"]:
                objects = [
                    objects_item
                    for objects_item in objects
                    if not objects_item.get("name").startswith("_DELETED_")
                ]
        return objects
    except urllib_error as error:
        raise HTTPException(error.read())


def get__storage_domain_id__all(self):
    try:
        uri = "https://" + self["server"] + "/irisservices/api/v1/public/viewBoxes"
        if "viewBoxId" in self:
            if "type" not in self:
                self["type"] = "name"
                if isinstance(self["viewBoxId"], int):
                    self["type"] = "id"
            uri = uri + "?" + urllib_parse.urlencode({self["type"]: self["viewBoxId"]})

        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + self["token"],
        }
        objects = open_url(
            url=uri, headers=headers, validate_certs=self["validate_certs"], timeout=120
        )
        objects = json.loads(objects.read())
        return objects
    except urllib_error.URLError as error:
        raise HTTPException(error.read())


def get__protection_run__all(self):
    try:
        uri = "https://" + self["server"] + "/irisservices/api/v1/public/protectionRuns"

        if "id" in self:
            uri = uri + "?jobId=" + str(self["id"])
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + self["token"],
        }
        objects = open_url(
            url=uri, headers=headers, validate_certs=self["validate_certs"], timeout=120
        )
        objects = json.loads(objects.read())

        if "is_deleted" in self:
            if not self["is_deleted"]:
                objects = [
                    objects_item
                    for objects_item in objects
                    if not objects_item.get("jobName").startswith("_DELETED_")
                ]

        if "active_only" in self:
            if self["active_only"]:
                objects = [
                    objects_item
                    for objects_item in objects
                    if objects_item["backupRun"].get("status")
                    in ["kAccepted", "kRunning"]
                ]
        return objects
    except urllib_error.URLError as error:
        raise HTTPException(error.read())


# => Filtered Queries


def get__prot_source_root_id__by_environment(module, self):
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = self["token"]
    try:
        source_obj = dict(
            server=server,
            token=token,
            validate_certs=validate_certs,
            environment=self["environment"],
        )

        root_nodes = get__prot_source__roots(source_obj)

        for node in root_nodes:
            if (
                node["protectionSource"]["environment"] == ("k" + self["environment"])
                and node["protectionSource"]["environment"] != "kVMware"
            ):
                return node["protectionSource"]["id"]
            elif node["protectionSource"]["environment"] == "kVMware":
                return node["protectionSource"]["id"]

        raise ProtectionException(
            "There was a very serious situation where the chosen environment did not return a valid Root Node ID"
        )
    except Exception:
        module.fail_json(
            msg="Unexpected error caused while managing the Cohesity Protection Source.",
            exception=traceback.format_exc(),
        )


def get__prot_policy_id__by_name(module, self):
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = self["token"]
    try:
        source_obj = dict(
            server=server,
            token=token,
            validate_certs=validate_certs,
            policyId=self["policyId"],
        )
        objects = get__prot_policy__all(source_obj)
        for obj in objects:
            if obj["name"] == self["policyId"]:
                return obj["id"]

        raise ProtectionException(
            "There was a very serious situation where the chosen Protection Policy Name ("
            + self["policyId"]
            + ") did not return a valid ID"
        )
    except Exception:
        module.fail_json(
            msg="Unexpected error caused while managing the Cohesity Protection Source.",
            exception=traceback.format_exc(),
        )


def get__storage_domain_id__by_name(module, self):
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = self["token"]
    try:
        source_obj = dict(
            server=server,
            token=token,
            validate_certs=validate_certs,
            viewBoxId=self["viewBoxId"],
        )
        for obj_type in ["names", "ids"]:
            source_obj["type"] = obj_type
            objects = get__storage_domain_id__all(source_obj)
            if objects:
                break

        for obj in objects:
            if obj["name"] == self["viewBoxId"]:
                return int(obj["id"])
            elif obj["id"] == int(self["viewBoxId"]):
                return int(obj["id"])
            else:
                # => We really should land here but if so then
                pass

        raise ProtectionException(
            "There was a very serious situation where the chosen Storage Domain Name ("
            + self["viewBoxId"]
            + ") did not return a valid ID"
        )
    except Exception:
        module.fail_json(
            msg="Unexpected error caused while managing the Cohesity Protection Source.",
            exception=traceback.format_exc(),
        )


def get__prot_source_id__by_endpoint(module, self):
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = self["token"]
    try:
        source_obj = dict(
            server=server,
            token=token,
            validate_certs=validate_certs,
            environment=self["environment"],
        )
        source = get__prot_source__all(source_obj)
        if source:
            env_types = ["Physical", "GenericNas"]
            if self["environment"] in env_types:
                for node in source["nodes"]:
                    if self["endpoint"] in [
                        node["registrationInfo"]["accessInfo"]["endpoint"],
                        node["protectionSource"]["name"],
                    ]:
                        return node["protectionSource"]["id"]
            else:
                for node in source:
                    if self["environment"] == "UDA" and node["protectionSource"]["name"] == self["endpoint"]:
                        return node["protectionSource"]["id"]
                        
                    if (
                        node["registrationInfo"]["accessInfo"]["endpoint"]
                        == self["endpoint"]
                    ):
                        return node["protectionSource"]["id"]

        return False
    except Exception:
        module.fail_json(
            msg="Unexpected error caused while managing the Cohesity Protection Source.",
            exception=traceback.format_exc(),
        )


def get__protection_jobs__by_environment(module, self):

    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = self["token"]
    try:
        source_obj = dict(
            server=server,
            token=token,
            validate_certs=validate_certs,
            environment=self["environment"],
        )
        return get__prot_job__all(source_obj)

    except Exception:
        module.fail_json(
            msg="Unexpected error caused while managing the Cohesity Protection Jobs.",
            exception=traceback.format_exc(),
        )


def get__protection_run__all__by_id(module, self):

    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = self["token"]
    try:
        source_obj = dict(
            server=server, token=token, validate_certs=validate_certs, id=self["id"]
        )
        if "active_only" in self:
            source_obj["active_only"] = self["active_only"]

        if "is_deleted" in self:
            source_obj["is_deleted"] = self["is_deleted"]

        return get__protection_run__all(source_obj)

    except Exception:
        module.fail_json(
            msg="Unexpected error caused while managing the Cohesity Protection Jobs.",
            exception=traceback.format_exc(),
        )


def get__file_snapshot_information__by_filename(module, self):

    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = self["token"]
    try:
        # => We need to make this a safe querystring filename
        filename = urllib_parse.quote_plus(self["restore_obj"]["filename"])
        uri = (
            "https://"
            + server
            + "/irisservices/api/v1/public/restore/files/snapshotsInformation?jobId="
            + str(self["restore_obj"]["jobUid"]["id"])
            + "&clusterId="
            + str(self["restore_obj"]["jobUid"]["clusterId"])
            + "&clusterIncarnationId="
            + str(self["restore_obj"]["jobUid"]["clusterIncarnationId"])
            + "&sourceId="
            + str(self["restore_obj"]["protectionSourceId"])
            + "&filename="
            + filename
        )

        headers = {"Accept": "application/json", "Authorization": "Bearer " + token}
        objects = open_url(
            url=uri, headers=headers, validate_certs=validate_certs, timeout=120
        )
        objects = json.loads(objects.read())

        # => Returns an array of snapshots that contain that file.
        return objects
    except urllib_error.URLError as error:
        raise HTTPException(error.read())


def get__vmware_snapshot_information__by_vmname(module, self):

    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = self["token"]
    try:
        uri = (
            "https://"
            + server
            + "/irisservices/api/v1/public/restore/objects"
            + "?environments[]=kVMware&search="
            + quote(self["restore_obj"]["vmname"])
            + "&jobIds[]="
            + str(self["restore_obj"]["jobUid"]["id"])
        )

        headers = {"Accept": "application/json", "Authorization": "Bearer " + token}
        objects = open_url(
            url=uri, headers=headers, validate_certs=validate_certs, timeout=120
        )
        objects = json.loads(objects.read())

        # => Returns an array of snapshots that contain that file.
        return objects
    except urllib_error.URLError as error:
        raise HTTPException(error.read())


def get__restore_job__by_type(module, self):

    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = self["token"]
    try:
        uri = (
            "https://"
            + server
            + "/irisservices/api/v1/public/restore/tasks?taskTypes="
            + self["restore_type"]
        )

        if "count" in self:
            uri = uri + "&pageCount=" + str(self["count"])

        headers = {"Accept": "application/json", "Authorization": "Bearer " + token}
        objects = open_url(
            url=uri, headers=headers, validate_certs=validate_certs, timeout=120
        )
        objects = json.loads(objects.read())

        # => Returns an array of snapshots that contain that file.
        return objects
    except urllib_error.URLError as error:
        raise HTTPException(error.read())


# => Unregister an existing Cohesity Protection Source.
def unregister_source(module, self):
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = self["token"]
    try:
        uri = (
            "https://"
            + server
            + "/irisservices/api/v1/public/protectionSources/"
            + str(self["id"])
        )
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
            "user-agent": "cohesity-ansible/v1.0.3",
        }

        response = open_url(
            url=uri,
            method="DELETE",
            headers=headers,
            validate_certs=validate_certs,
            timeout=REQUEST_TIMEOUT,
        )

        return response
    except urllib_error.URLError as e:
        # => Capture and report any error messages.
        raise__cohesity_exception__handler(e.read(), module)


def get__prot_policy_id__by_name(module):
    try:
        name = module.params.get("protection_policy")
        resp = cohesity_client.protection_policies.get_protection_policies(names=name)
        if not resp:
            module.exit_json(output="Please provide a valid protection policy name")
        return resp[0].id
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def get__storage_domain_id__by_name(module):
    try:
        name = module.params.get("storage_domain")
        resp = cohesity_client.view_boxes.get_view_boxes(names=name)
        if not resp:
            module.exit_json(output="Please provide a valid storage domain name")
        return resp[0].id
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def get_protection_run__status__by_id(module, group_id):
    try:
        group_run = cohesity_client.protection_runs.get_protection_runs(group_id=group_id)
        if not group_run:
            return False, "", ""
        # Fetch the status of last group run.
        last_run = group_run[0]
        status = last_run.backup_run.status
        if status == "kAccepted":
            return True, status, last_run
        elif status in ["kCanceled", "kSuccess"]:
            return False, status, last_run
        return False, status, ""
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def check__protection_group__exists(module, self):
    try:
        name = module.params.get("name")
        environment = "k" + module.params.get("environment")
        server = module.params.get("cluster")
        validate_certs = module.params.get("validate_certs")
        uri = "https://" + server + "/v2/data-protect/protection-groups?environments=" + environment
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + self["token"],
            "user-agent": "cohesity-ansible/v1.0.3",
        }
        response = open_url(
            url=uri,
            method="GET",
            headers=headers,
            validate_certs=validate_certs,
            timeout=self["timeout"],
        )
        if not response.getcode() == 200:
            raise Exception(response.read())
        group_list = json.loads(response.read())
        for group in group_list.get("protectionGroups", None):
            if group["name"] == name:
                return group["id"], group
            
        return False, ""
    except Exception as error:
        raise__cohesity_exception__handler(error, module)

