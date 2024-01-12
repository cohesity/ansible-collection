import json
from ansible.module_utils.basic import AnsibleModule
from cohesity_management_sdk.controllers.base_controller import BaseController
from cohesity_management_sdk.exceptions.api_exception import APIException
from cohesity_management_sdk.models.quota_policy import QuotaPolicy 
from cohesity_management_sdk.models.storage_policy import StoragePolicy
from cohesity_management_sdk.models.erasure_coding_info import ErasureCodingInfo



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
        storage_domains = (
            cohesity_client.storage_domain.get_storage_domains(
                names=domain_name
            )
        )
        if storage_domains:
            for domain in storage_domains:
                if domain.name == domain_name:   
                    return True,domain
        return False,None     
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
        if module.params.get("default_view_quota").get("set_logical_quota", False):
            quota_policy.hard_limit_bytes = module.params.get("default_view_quota").get(
                "hard_limit_bytes", TWENTY_GiB
            )
            storage_domain_details.default_view_quota = quota_policy
        if module.params.get("default_view_quota").get("set_alert_threshold", False):
            quota_policy.alert_limit_bytes = module.params.get("default_view_quota").get(
                "alert_limit_bytes", EIGHTEEN_GiB
            )
            storage_domain_details.default_view_quota = quota_policy
        if module.params.get("physical_quota").get("set_physical_quota", False):
            quota_policy.hard_limit_bytes = module.params.get("physical_quota").get(
                "hard_limit_bytes", TWENTY_GiB
            )
            storage_domain_details.physical_quota = quota_policy
        if module.params.get("physical_quota").get("set_alert_threshold", False):
            quota_policy.alert_limit_bytes = module.params.get("physical_quota").get(
                "alert_limit_bytes", EIGHTEEN_GiB
            )
            storage_domain_details.physical_quota = quota_policy
        return storage_domain_details
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def set_storage_policy(module):
    try:
        storage_policy = StoragePolicy()
        if module.params.get("storage_policy").get("duplicate",False):
            storage_policy.deduplication_enabled = module.params.get("storage_policy").get("duplicate",True)
        if module.params.get("storage_policy").get("compression",False):
            storage_policy.compression_policy=module.params.get("storage_policy").get("duplicate",True)
        if module.params.get("storage_policy").get("erasure_coding_info",False):
            storage_policy.erasure_coding_info=erasure_coding_params(module)
        return storage_policy
    except Exception as error:
        raise__cohesity_exception__handler(error,module)


def erasure_coding_params(module):
    try:
        erasure = ErasureCodingInfo()
        if module.params.get("storage_policy").get("erasure_coding",False):
            erasure.erasure_coding_enabled = module.params.get("storage_policy").get("erasure_coding",False).get("enabled",False)
            erasure.inline_erasure_coding = module.params.get("storage_policy").get("erasure_coding",False).get("inline_erasure",False)
            erasure.num_coded_stripes = module.params.get("storage_policy").get("erasure_coding",False).get("inline_erasure",0)
            erasure.num_data_stripes = module.params.get("storage_policy").get("erasure_coding",False).get("data_stripe",0)
        return erasure

    except Exception as error:
        raise__cohesity_exception__handler(error,module)

def create_domain(module):
    """
    function to create a storage domain
    :param module: object that holds parameters passed to the module
    :return:
    """
    try:
        storage_domain_details = dict(
            name=module.params.get("name"),
            description=module.params.get("description"),
            state=module.params.get("state"),
            stats=module.params.get("stats"),
            encryption=module.params.get("encryption"),
            ad_domain_name=module.params.get("ad_domain_name"),
            cluster_partition_id=module.params.get("cluster_partion_id"),
            cluster_partition_name=module.params.get("cluster_partition_name"),
            id=module.params.get("id"),
            kms_server_id=module.params.get("kms_server_id"),
            ldap_provider_id=module.params.get("ldap_provider_id"),
        )
        if module.params.get("default_view_quota"):
            storage_domain_details = set_quota(storage_domain_details, module)
        if module.params.get("physical_quota"):
            storage_domain_details = set_quota(storage_domain_details, module)
        if module.params.get("storage_policy"):
            storage_domain_details.storage_policy=set_storage_policy(module)
        domain_response = cohesity_client.storage_domain.create_storage_domain(
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
    try:
        cohesity_client.storage_domain.delete_storage_domain(id=domain_id)
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
            name=dict(type="str", required=True),
            description=dict(type="str", default=""),
            state=dict(choices=["present", "absent"], default="present"),
            ad_domain_name=dict(type="str", default=""),
            cluster_partition_id=dict(type="int", default=3),
            cluster_partition_name=dict(type="str", default="DefaultPartition"),
            default_view_quota=dict(type="dict", required=False),
            id=dict(type="int",default=None),
            stats=dict(type="dict",required=False),
            kms_server_id=dict(type="int",default=None),
            ldap_provider_id=dict(type="int",default=None),
            storage_policy=dict(type="dict", required=False),
            duplicate=dict(default=True, type="bool"),
            compression=dict(default=True,type="bool"),
            encryption=dict(default=False,type="bool"),
            logical_quota=dict(type="dict", required=False),
            physical_quota=dict(type="dict", required=False),
            inline_deduplication=dict(type="bool", default=True),
            inline_compression=dict(type="bool", default=True),
            erasure_coding_params=dict(type="dict",required=False),
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
    base_controller.global_headers["user-agent"] = "cohesity-ansible/v1.1.2"
    cohesity_client = get_cohesity_client(module)
    domain_exists,domain_details = get_domain_details(module)

    """ To be done later
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
                check_mode_results[
                    "msg"
                ] = "Check Mode: Cohesity Protection Job is currently registered.  This action would unregister the Cohesity Protection Job."
                check_mode_results["id"] = domain_exists
            else:
                check_mode_results[
                    "msg"
                ] = "Check Mode: Cohesity Protection Job is not currently registered.  No changes."
        module.exit_json(**check_mode_results)
    """
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
