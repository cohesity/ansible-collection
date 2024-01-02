import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url, urllib_error

from cohesity_management_sdk.controllers.base_controller import BaseController
from cohesity_management_sdk.exceptions.api_exception import APIException
from cohesity_management_sdk.models.quota_policy import QuotaPolicy
from cohesity_management_sdk.models.storage_policy import StoragePolicy
from cohesity_management_sdk.models.erasure_coding_info import ErasureCodingInfo
from cohesity_management_sdk.models.create_view_box_params import CreateViewBoxParams


try:
    # => When unit testing, we need to look in the correct location however, when run via ansible,
    # => the expectation is that the modules will live under ansible.
    from ansible_collections.cohesity.dataprotect.plugins.module_utils.cohesity_auth import (
        get__cohesity_auth__token,
    )
    from ansible_collections.cohesity.dataprotect.plugins.module_utils.cohesity_utilities import (
        cohesity_common_argument_spec,
        raise__cohesity_exception__handler,
    )
    from ansible_collections.cohesity.dataprotect.plugins.module_utils.cohesity_hints import (
        get_cohesity_client,
    )

except Exception:
    pass

cohesity_client = None
TWENTY_GiB = 20 * (1024**3)
EIGHTEEN_GiB = 18 * (1024**3)


DOCUMENTATION = """
---
author: Naveena (@naveena-maplelabs)
description:
  - Ansible Module used to create or remove a storage domain from a Cohesity Cluster.
  - When executed in a playbook the appropriate state action will be applied.
module: cohesity_storage_domain
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
      - Password belonging to the selected Username. This parameter will not be
        logged.
    type: str
  ad_domain_name:
    description:
      - Specifies the active directory name that the view box is mapped to.
    required: false
    type: str
  cluster_partition_id:
    default: 3
    description:
      - The Cluster Partition id where the Storage Domain (View Box) will be created.
    type: int
  state:
    choices:
      - present
      - absent
    default: present
    description:
      - Determines the state of the storage domain.
    type: str
  cluster_partition_name:
    default: DefaultPartition
    description:
      - Name of the cluster partition where the Storage Domain (View Box) will be created.
    type: str
  default_view_quota:
    default: false
    description:
      - Specifies an optional default logical quota limit (in bytes) for the Views in this Storage Domain (View Box).
    type: str
  kms_Server_id:
    description:
      - Specifies the associated KMS Server ID.
    type: str
  validate_certs:
    aliases:
      - cohesity_validate_certs
    default: true
    description:
      - Switch determines if SSL Validation should be enabled.
    type: bool
  ldap_provider_id:
    description:
      - When set, the following provides the LDAP provider the view box is mapped to.
    type: str
  storage_policy:
    type: dict
    description:
      - Specifies the storage options applied to the Storage Domain (View Box).
      - Supports keys duplicate and compression_policy.
  erasure_coding_params:
    type: dict
    description:
      - Specifies information for erasure coding.
# extends_documentation_fragment:
#   - cohesity.dataprotect.cohesity
short_description: Management of Cohesity Storage Domains.
version_added: 1.1.6
"""

EXAMPLES = """
# Create a view box in the cohesity cluster.
- cohesity_storage_domain:
    server: cohesity.lab
    username: admin
    password: password
    name: Custom
    partition_name: DefaultPartition
    state: present

# Remove a viewbox from the cohesity cluster.
- cohesity_storage_domain:
    server: cohesity.lab
    username: admin
    password: password
    name: Custom
    state: absent
"""

RETURN = """
"""


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


def set_quota(module, storage_domain_details):
    """
    function to set the logical quota and alert threshold
    :param view_request: request body
    :param module: object that holds parameters passed to the module
    :return:
    """
    try:
        quota_policy = QuotaPolicy()
        if module.params.get("hard_limit_bytes"):
            quota_policy.hard_limit_bytes = module.params.get(
                "hard_limit_bytes", TWENTY_GiB
            )
        if module.params.get("alert_limit_bytes"):
            quota_policy.alert_limit_bytes = module.params.get(
                "alert_limit_bytes", EIGHTEEN_GiB
            )
        storage_domain_details.physical_quota = quota_policy
        return storage_domain_details
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def set_storage_policy(module):
    try:
        storage_policy = StoragePolicy()
        if module.params.get("storage_policy").get("duplicate", True):
            storage_policy.deduplication_enabled = module.params.get("duplicate", True)
        if module.params.get("storage_policy").get("compression_policy", True):
            storage_policy.compression_policy = module.params.get(
                "compression_policy", "kCompressionNone"
            )
        if module.params.get("erasure_coding_params"):
            erasure = ErasureCodingInfo()
            if module.params.get("erasure_coding_params"):
                coding_params = module.params.get("erasure_coding_params")
                erasure.erasure_coding_enabled = coding_params.get("enabled", False)
                erasure.inline_erasure_coding = coding_params.get(
                    "inline_erasure", False
                )
                erasure.num_coded_stripes = coding_params.get("num_coded_stripes", 0)
                erasure.num_data_stripes = coding_params.get("num_data_stripes", 0)
            storage_policy.erasure_coding_info = erasure
        return storage_policy
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def fetch_cluster_partition_by_name(module):
    """
    Function to fetch cluster partition by name.
    :param module: object that holds parameters passed to the module
    returns Partition Id.
    """
    name = module.params.get("cluster_partition_name")
    partitions = cohesity_client.cluster_partitions.get_cluster_partitions(names=name)
    for partition in partitions:
        if partition.name == name:
            return partition.id


def create_domain(module):
    """
    function to create a storage domain
    :param module: object that holds parameters passed to the module
    :return:
    """
    try:
        storage_domain_details = CreateViewBoxParams(
            name=module.params.get("name"),
        )
        if module.params.get("ad_domain_name"):
            storage_domain_details.ad_domain_name = module.params.get("ad_domain_name")
        if not (
            module.params.get("cluster_partition_name")
            or module.params.get("cluster_partition_id")
        ):
            module.fail_json(
                msg="Cluster partition name or Id is required for viewbox creation.",
                changed=False,
            )
        # Find the partition Id.
        if module.params.get("cluster_partition_name"):
            partition_id = fetch_cluster_partition_by_name(module)
            if not partition_id:
                name = module.params.get("cluster_partition_name")
                module.fail_json(
                    msg="Failed to find cluster partition with name '%s'" % name,
                    changed=False,
                )
            storage_domain_details.cluster_partition_id = partition_id
        if module.params.get("cluster_partition_id"):
            storage_domain_details.cluster_partition_id = module.params.get(
                "cluster_partition_id"
            )
        if module.params.get("kms_server_id"):
            storage_domain_details.kms_server_id = module.params.get("kms_server_id")
        if module.params.get("ldap_provider_id"):
            storage_domain_details.ldap_provider_id = module.params.get(
                "ldap_provider_id"
            )
        if module.params.get("view_quota_policy"):
            storage_domain_details.default_view_quota_policy = set_quota(
                storage_domain_details, module
            )
        if module.params.get("storage_policy"):
            storage_domain_details.storage_policy = set_storage_policy(module)
        domain_response = cohesity_client.view_boxes.create_view_box(
            storage_domain_details
        )
        result = dict(
            changed=True,
            msg="Cohesity storage domain is created successfully",
            id=domain_response.id,
            task_name=module.params.get("name"),
        )
        module.exit_json(**result)

    except APIException as ex:
        raise__cohesity_exception__handler(
            str(json.loads(ex.context.response.raw_body)), module
        )
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def delete_domain(module, domain_id):
    """
    function to delete the domain
    :param module: object that holds parameters passed to the module
    :param policy_id: domain id
    :return:
    """
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = get__cohesity_auth__token(module)
    try:
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
            "user-agent": "cohesity-ansible/v1.1.6",
        }
        uri = "https://" + server + "/v2/storage-domains/%s" % domain_id
        open_url(
            url=uri,
            headers=headers,
            method="DELETE",
            validate_certs=validate_certs,
            timeout=module.params.get("timeout"),
        )
        results = dict(
            changed=True,
            msg="Successfully deleted the storage domain '%s'."
            % module.params.get("name"),
        )
        module.exit_json(**results)
    except urllib_error.URLError as e:
        # => Capture and report any error messages.
        raise__cohesity_exception__handler(e.read(), module)
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def main():
    # => Load the default arguments including those specific to the Cohesity storage domain.
    argument_spec = cohesity_common_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            state=dict(choices=["present", "absent"], default="present"),
            ad_domain_name=dict(type="str", default=""),
            cluster_partition_id=dict(type="int", default=3),
            cluster_partition_name=dict(type="str", default="DefaultPartition"),
            view_quota_policy=dict(type="dict", required=False),
            kms_server_id=dict(type="int", required=False),
            ldap_provider_id=dict(type="int", required=False),
            storage_policy=dict(type="dict", required=False),
            erasure_coding_params=dict(type="dict", required=False),
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
    base_controller.global_headers["user-agent"] = "cohesity-ansible/v1.1.6"
    cohesity_client = get_cohesity_client(module)
    domain_exists, domain_details = get_domain_details(module)

    if module.check_mode:
        check_mode_results = dict(
            changed=False,
            msg="Check Mode: Cohesity storage domain doesn't exist",
            id="",
        )
        if module.params.get("state") == "present":
            if domain_exists:
                check_mode_results[
                    "msg"
                ] = "Check Mode: Cohesity storage domain is already present. No changes"
                check_mode_results["id"] = domain_details.id
            else:
                check_mode_results["msg"] = (
                    "Check Mode: Cohesity storage domain doesn't exist."
                    " This action would create a storage domain "
                )
                check_mode_results["id"] = domain_exists
        else:
            if domain_exists:
                partition_id = fetch_cluster_partition_by_name(module)
                if not partition_id:
                    name = module.params.get("cluster_partition_name")
                    module.fail_json(
                        msg="Check Mode: Failed to find cluster partition with name '%s'" % name,
                        changed=False,
                    )
                check_mode_results[
                    "msg"
                ] = "Check Mode: Cohesity Protection Job is currently registered.  This action would unregister the Cohesity Protection Job."
                check_mode_results["id"] = domain_exists
            else:
                check_mode_results[
                    "msg"
                ] = "Check Mode: Cohesity Protection Job is not currently registered.  No changes."
        module.exit_json(**check_mode_results)

    if module.params.get("state") == "present":
        if domain_exists:
            results = dict(
                changed=False,
                msg="The Cohesity storage domain with specified name is already present",
                id=domain_details.id,
                domain_name=module.params.get("name"),
            )
        else:
            create_domain(module)

    elif module.params.get("state") == "absent":
        if domain_exists:
            delete_domain(module, domain_details.id)
            results = dict(
                changed=True,
                msg="Cohesity storage domain is deleted",
                id=domain_details.id,
                domain_name=module.params.get("name"),
            )
        else:
            results = dict(
                changed=False,
                msg="Cohesity storage domain doesn't exist, skipping deletion",
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
