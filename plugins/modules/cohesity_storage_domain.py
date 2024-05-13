#!/usr/bin/python
# Copyright (c) 2022 Cohesity Inc


from __future__ import absolute_import, division, print_function

__metaclass__ = type

# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = r"""
---
author: "Naveena (@naveena-maplelabs)"
description:
  - "Ansible Module used to create or delete a storage domain from a Cohesity Cluster."
  - "When executed in a playbook the appropriate state action will be applied."
module: cohesity_storage_domain
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
      - "Password belonging to the selected Username. This parameter will not be logged."
    type: str
  ad_domain_name:
    description:
      - "Specifies an active directory domain that this storage domain box is mapped to."
    required: false
    type: str
  cluster_partition_id:
    default: 3
    description:
      - "Specifies the Cluster Partition id where the Storage Domain is located."
    type: int
  cluster_partition_name:
    description:
      - "Specifies the Cluster Partition Name where the Storage Domain is located."
    type: str
  default_view_quota:
    description:
      - "Specifies an optional default logical quota limit (in bytes) for the Views in this Storage Domain."
      - "Supports two fields hard_limit_bytes and alert_limit_bytes"
    type: dict
  physical_quota:
    description:
      - "Specifies an optional quota limit (in bytes) for the physical usage of this Storage Domain."
      - "Supports two fields hard_limit_bytes and alert_limit_bytes"
    type: dict
  id:
    type: int
    description:
      - "Specifies the Id of the Storage Domain."
      - "Applicable only when the domain is already created"
  kms_server_id:
    default: None
    description: "Specifies the associated KMS Server ID."
    type: int
  ldap_provider_id:
    description: "Specifies the following provides the LDAP provider the storage domain is mapped to."
    type: int
  storage_policy:
    description:
      - "Specifies the storage options applied to the Storage Domain."
    type: dict
extends_documentation_fragment:
- cohesity.dataprotect.cohesity
short_description: "Management of Cohesity Storage Domains"
version_added: 1.1.10
"""

EXAMPLES = """
# Create a Storage Domain in the cohesity cluster.
- cohesity_storage_domain:
    server: cohesity.lab
    username: admin
    password: password
    name: StorageDomain
    cluster_partition_name: DefaultPartition
    state: present

# Delete a storage domain from the cohesity cluster.
- cohesity_storage_domain:
    server: cohesity.lab
    username: admin
    password: password
    name: StorageDomain
    state: absent
"""

RETURN = """
"""
import json

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cohesity.dataprotect.plugins.module_utils.cohesity_utilities import (
    cohesity_common_argument_spec,
    raise__cohesity_exception__handler,
    REQUEST_TIMEOUT,
)
from ansible_collections.cohesity.dataprotect.plugins.module_utils.cohesity_auth import (
    get__cohesity_auth__token,
)
from ansible_collections.cohesity.dataprotect.plugins.module_utils.cohesity_hints import (
    get_cohesity_client,
)
from ansible.module_utils.urls import open_url

try:
    from cohesity_management_sdk.controllers.base_controller import BaseController
    from cohesity_management_sdk.exceptions.api_exception import APIException
    from cohesity_management_sdk.models.quota_policy import QuotaPolicy
    from cohesity_management_sdk.models.storage_policy import StoragePolicy
    from cohesity_management_sdk.models.erasure_coding_info import ErasureCodingInfo
    from cohesity_management_sdk.models.create_view_box_params import CreateViewBoxParams

except Exception:
    pass


cohesity_client = None
TWENTY_GiB = 20 * (1024**3)
EIGHTEEN_GiB = 18 * (1024**3)


def get_domain_details(module):
    """
    function to get the storage domain details
    :param module: object that holds parameters passed to the module
    :return:
    """
    try:
        domain_name = module.params.get("name")
        storage_domains = cohesity_client.view_boxes.get_view_boxes(names=domain_name)
        if storage_domains:
            for domain in storage_domains:
                if domain.name == domain_name:
                    return True, domain
        return False, None
    except APIException as ex:
        raise__cohesity_exception__handler(
            str(json.loads(ex.context.response.raw_body)), module
        )
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def set_quota(storage_domain_details, module):
    """
    function to set the logical quota and alert threshold
    :param view_request: request body
    :param module: object that holds parameters passed to the module
    :return:
    """
    try:
        quota_policy = QuotaPolicy()
        physical_quota_policy = QuotaPolicy()
        if module.params.get("default_view_quota"):
            quota_policy.hard_limit_bytes = module.params.get("default_view_quota").get(
                "hard_limit_bytes", TWENTY_GiB
            )
            quota_policy.alert_limit_bytes = module.params.get(
                "default_view_quota"
            ).get("alert_limit_bytes", EIGHTEEN_GiB)
            storage_domain_details.default_view_quota = quota_policy
        if module.params.get("physical_quota"):
            physical_quota_policy.hard_limit_bytes = module.params.get(
                "physical_quota"
            ).get("hard_limit_bytes", TWENTY_GiB)
            physical_quota_policy.alert_limit_bytes = module.params.get(
                "physical_quota"
            ).get("alert_limit_bytes", EIGHTEEN_GiB)
            storage_domain_details.physical_quota = physical_quota_policy
        return storage_domain_details
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def set_storage_policy(module):
    try:
        storage_policy = StoragePolicy()
        if module.params.get("storage_policy").get("duplicate", False):
            storage_policy.deduplication_enabled = module.params.get(
                "storage_policy"
            ).get("duplicate", True)
        if module.params.get("storage_policy").get("compression", False):
            storage_policy.compression_policy = module.params.get("storage_policy").get(
                "compression", "kCompressionNone"
            )
        if module.params.get("storage_policy").get("erasure_coding", False):
            storage_policy.erasure_coding_info = erasure_coding_params(module)
        return storage_policy
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def erasure_coding_params(module):
    try:
        erasure = ErasureCodingInfo()
        if module.params.get("storage_policy").get("erasure_coding", False):
            if (
                module.params.get("storage_policy")
                .get("erasure_coding")
                .get("enabled", False)
            ):
                erasure.erasure_coding_enabled = (
                    module.params.get("storage_policy")
                    .get("erasure_coding", False)
                    .get("enabled", False)
                )
            if (
                module.params.get("storage_policy")
                .get("erasure_coding")
                .get("inline_erasure", False)
            ):
                erasure.inline_erasure_coding = (
                    module.params.get("storage_policy")
                    .get("erasure_coding", False)
                    .get("inline_erasure", False)
                )
            if (
                module.params.get("storage_policy")
                .get("erasure_coding")
                .get("num_coded_stripes", False)
            ):
                erasure.num_coded_stripes = (
                    module.params.get("storage_policy")
                    .get("erasure_coding", False)
                    .get("num_coded_stripes", 0)
                )
            if (
                module.params.get("storage_policy")
                .get("erasure_coding")
                .get("data_stripe", False)
            ):
                erasure.num_data_stripes = (
                    module.params.get("storage_policy")
                    .get("erasure_coding", False)
                    .get("data_stripe", 0)
                )
        return erasure

    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def get_partition_id(module):
    """
    function to fetch partition by name.
    :param module: object that holds parameters passed to the module
    :return:
    """
    partition_name = module.params.get("cluster_partition_name")
    nodes = cohesity_client.nodes.get_nodes()
    for node in nodes:
        if partition_name and node.cluster_partition_name == partition_name:
            return node.cluster_partition_id
    if partition_name:
        module.fail_json(
            msg="Couldn't find cluster partition %s"
            % module.params.get("cluster_partition_name")
        )
    return node.cluster_partition_id


def create_update_domain(module, domain_details=False):
    """
    function to create a storage domain
    :param module: object that holds parameters passed to the module
    :return:
    """
    try:
        storage_domain_details = CreateViewBoxParams(name=module.params.get("name"))
        if module.params.get("ad_domain_name"):
            storage_domain_details.ad_domain_name = (
                module.params.get("ad_domain_name"),
            )
        if module.params.get("kms_server_id"):
            storage_domain_details.kms_server_id = module.params.get("kms_server_id")
        if module.params.get("ldap_provider_id"):
            storage_domain_details.ldap_provider_id = module.params.get(
                "ldap_provider_id"
            )
        storage_domain_details.cluster_partition_id = get_partition_id(module)
        if module.params.get("cluster_partition_id"):
            storage_domain_details.cluster_partition_id = module.params.get(
                "cluster_partition_id"
            )
        if module.params.get("default_view_quota"):
            storage_domain_details = set_quota(storage_domain_details, module)
        if module.params.get("physical_quota"):
            storage_domain_details = set_quota(storage_domain_details, module)
        if module.params.get("storage_policy"):
            storage_domain_details.storage_policy = set_storage_policy(module)
        if domain_details:
            domain_response = cohesity_client.view_boxes.update_view_box(
                domain_details.id, storage_domain_details
            )
        else:
            domain_response = cohesity_client.view_boxes.create_view_box(
                storage_domain_details
            )
        return domain_response

    except APIException as ex:
        raise__cohesity_exception__handler(
            str(json.loads(ex.context.response.raw_body)), module
        )
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def delete_storage_domain(module, domain_id):
    """
    function to delete the storage domain
    :param module: object that holds parameters passed to the module
    :param : domain id
    :return:
    """

    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = get__cohesity_auth__token(module)
    try:
        uri = "https://" + server + "/v2/storage-domains/%s" % str(domain_id)
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
            "user-agent": "cohesity-ansible/v1.1.10",
        }
        open_url(
            url=uri,
            headers=headers,
            validate_certs=validate_certs,
            method="DELETE",
            timeout=REQUEST_TIMEOUT,
        )
        results = dict(
            changed=True,
            msg="Cohesity storage domain is deleted successfully",
            id=domain_id,
            domain_name=module.params.get("name"),
        )
        module.exit_json(**results)
    except APIException as ex:
        raise__cohesity_exception__handler(
            str(json.loads(ex.context.response.raw_body)), module
        )
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def main():
    # => Load the default arguments including those specific to the Cohesity storage domain.
    argument_spec = cohesity_common_argument_spec()
    argument_spec.update(
        dict(
            id=dict(type="int", default=None),
            name=dict(type="str", required=False),
            state=dict(choices=["present", "absent"], default="present"),
            ad_domain_name=dict(type="str", default=""),
            cluster_partition_id=dict(type="int", default=3),
            cluster_partition_name=dict(type="str"),
            default_view_quota=dict(type="dict", required=False),
            kms_server_id=dict(type="int", default=None),
            ldap_provider_id=dict(type="int", default=None),
            storage_policy=dict(type="dict", required=False),
            physical_quota=dict(type="dict", required=False),
        )
    )

    # => Create a new module object
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    results = dict(
        changed=False,
        msg="Attempting to manage Cohesity storage domain",
        state=module.params.get("state"),
    )

    global cohesity_client
    base_controller = BaseController()
    base_controller.global_headers["user-agent"] = "cohesity-ansible/v1.1.10"
    cohesity_client = get_cohesity_client(module)
    domain_exists, domain_details = get_domain_details(module)

    if module.check_mode:
        check_mode_results = dict(
            changed=False,
            msg="Check Mode: Cohesity storage domain doesn't exist",
            id="",
        )
        if module.params.get("state") == "present":
            if module.params.get("cluster_partition_name"):
                cluster_partition_id = get_partition_id(module)
                if not cluster_partition_id:
                    module.fail_json(
                        msg="Check Mode: Couldn't find cluster partition %s"
                        % module.params.get("cluster_partition_name")
                    )
            if domain_exists:
                check_mode_results["msg"] = (
                    "Check Mode: Cohesity storage domain is already present. This action will update the storage domain."
                )
                check_mode_results["id"] = domain_details.id
            else:
                check_mode_results["msg"] = (
                    "Check Mode: Cohesity storage domain doesn't exist."
                    " This action would create a storage domain "
                )
                check_mode_results["id"] = domain_exists
        else:
            if domain_exists:
                check_mode_results["msg"] = (
                    "Check Mode: Storage domain is available. This action would delete the storage domain."
                )
                check_mode_results["id"] = domain_exists
            else:
                check_mode_results["msg"] = (
                    "Check Mode: Storage domain is available. No changes."
                )
        module.exit_json(**check_mode_results)

    if module.params.get("state") == "present":
        if domain_exists:
            domain_details = create_update_domain(module, domain_details)
            results = dict(
                changed=False,
                msg="Successfully updated the Cohesity storage domain",
                id=domain_details.id,
                domain_name=module.params.get("name"),
            )
        else:
            domain_response = create_update_domain(module)
            result = dict(
                changed=True,
                msg="Cohesity storage domain is created successfully",
                id=domain_response.id,
                task_name=module.params.get("name"),
            )
            module.exit_json(**result)

    elif module.params.get("state") == "absent":
        storage_domain_id = module.params.get("id")
        if domain_details:
            storage_domain_id = domain_details.id
        if storage_domain_id:
            delete_storage_domain(module, storage_domain_id)
        else:
            results = dict(
                changed=False,
                msg="Cohesity storage domain doesn't exist",
                domain_name=module.params.get("name"),
            )
    else:
        module.fail_json(
            msg="Invalid State selected: {0}".format(module.params.get("state")),
            changed=False,
        )

    module.exit_json(**results)


if __name__ == "__main__":
    main()
