#!/usr/bin/python
# Copyright (c) 2022 Cohesity Inc

from __future__ import absolute_import, division, print_function

__metaclass__ = type

# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = """
---
author: "Naveena (@naveena-maplelabs)"
description:
  - "Ansible Module used to create/update/remove protection policy on a Cohesity Cluster."
  - "When executed in a playbook, the Cohesity Policy will be validated and the appropriate state action"
  - "will be applied."
module: cohesity_policy
options:
  archival_copy:
    description: Specifies the list of external targets to be added while creating policy.
    elements: dict
    type: list
  blackout_window:
    description: "Specifies the list of blackout windows."
    elements: dict
    type: list
  bmr_backup_schedule:
    description: " BMR backup schedule."
    type: dict
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
  days_to_retain:
    default: 90
    description: "Specifies the number of retention days."
    type: int
  description:
    default: ""
    description: "Specifies the description for the policy created"
    type: str
  extended_retention:
    description: "Specifies the extended retention"
    elements: dict
    type: list
  full_backup_schedule:
    description: "Specifies the full backup schedule for policy creation"
    type: dict
  incremental_backup_schedule:
    description: "Specifies the incremental backup schedule for policy creation"
    required: true
    type: dict
  log_backup_schedule:
    description: "Specifies the log backup schedule for policy creation"
    type: dict
  name:
    description: "Specifies the name of the protection policy."
    required: true
    type: str
  replication_copy:
    description: Specifies the list of replication cluster to be added while creating policy.
    elements: dict
    type: list
  retries:
    default: 3
    description: "Specifies the retry count while policy creation."
    type: int
  retry_interval:
    default: 30
    description: "Specifies the retry interval."
    type: int
  state:
    choices:
      - present
      - absent
    default: present
    description:
      - "Determines the state of the Policy."
      - "(C)present a policy will be created."
      - "(C)absent will remove the policy."
    type: str
extends_documentation_fragment:
- cohesity.dataprotect.cohesity
short_description: "Cohesity Protection Policy"
version_added: 1.3.0
"""

EXAMPLES = """
# Create a protection policy.
- cohesity_policy:
    cluster: cohesity.lab
    username: admin
    password: password
    state: present
    name: 'Ansible'
    incremental_backup_schedule:
      periodicity: Daily

# Delete a protection policy.

- cohesity_policy:
    cluster: cohesity.lab
    username: admin
    password: password
    state: present
    name: 'Ansible'
"""

import json

from ansible.module_utils.basic import AnsibleModule

try:
    from ansible_collections.cohesity.dataprotect.plugins.module_utils.cohesity_utilities import (
        cohesity_common_argument_spec,
        raise__cohesity_exception__handler,
    )
    from ansible_collections.cohesity.dataprotect.plugins.module_utils.cohesity_hints import (
        get_cohesity_client,
    )
    from ansible_collections.cohesity.dataprotect.plugins.module_utils.cohesity_constants import (
        RELEASE_VERSION,
    )
    from cohesity_management_sdk.controllers.base_controller import BaseController
    from cohesity_management_sdk.exceptions.api_exception import APIException
    from cohesity_management_sdk.models.archival_external_target import (
        ArchivalExternalTarget,
    )
    from cohesity_management_sdk.models.blackout_period import BlackoutPeriod
    from cohesity_management_sdk.models.continuous_schedule import ContinuousSchedule
    from cohesity_management_sdk.models.daily_schedule import DailySchedule
    from cohesity_management_sdk.models.extended_retention_policy import (
        ExtendedRetentionPolicy,
    )
    from cohesity_management_sdk.models.monthly_schedule import MonthlySchedule
    from cohesity_management_sdk.models.protection_policy_request import (
        ProtectionPolicyRequest,
    )
    from cohesity_management_sdk.models.replication_target_settings import (
        ReplicationTargetSettings,
    )
    from cohesity_management_sdk.models.scheduling_policy import SchedulingPolicy
    from cohesity_management_sdk.models.snapshot_replication_copy_policy import (
        SnapshotReplicationCopyPolicy,
    )
    from cohesity_management_sdk.models.snapshot_archival_copy_policy import (
        SnapshotArchivalCopyPolicy,
    )
    from cohesity_management_sdk.models.time_of_day import TimeOfDay

except Exception:
    pass


cohesity_client = None


def get_policy_details(module):
    """
    function to get the protection policy details
    :param module: object that holds parameters passed to the module
    :return:
    """
    try:
        policy_name = module.params.get("name")
        protection_policies = (
            cohesity_client.protection_policies.get_protection_policies(
                names=policy_name
            )
        )
        if protection_policies:
            for policy in protection_policies:
                if policy.name == policy_name:
                    return True, policy
        return False, None
    except APIException as ex:
        raise__cohesity_exception__handler(
            str(json.loads(ex.context.response.raw_body)), module
        )
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def blackout_window(module):
    """
    function to construct a list of blackout windows
    :param module: object that holds parameters passed to the module
    :return:
    """
    try:
        blackout_windows = []
        for window in module.params.get("blackout_window"):
            blackout_period = BlackoutPeriod()
            blackout_period.day = "k" + window.get("day", "Wednesday")
            start_time = TimeOfDay()
            end_time = TimeOfDay()
            start_time.hour = int(window.get("start_time", "12:00").split(":")[0])
            start_time.minute = int(window.get("start_time", "12:00").split(":")[1])
            end_time.hour = int(window.get("end_time", "12:30").split(":")[0])
            end_time.minute = int(window.get("end_time", "12:30").split(":")[1])
            blackout_period.start_time = start_time
            blackout_period.end_time = end_time
            blackout_windows.append(blackout_period)
        return blackout_windows
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def policy_schedule(module, scheduling_policy):
    """
    utility function to construct the scheduling policy for different backups
    :param module: object that holds parameters passed to the module
    :param scheduling_policy: dictionary that has the scheduing details
    :return:
    """
    try:
        schedule = SchedulingPolicy()
        schedule.periodicity = "k" + scheduling_policy["periodicity"]
        if scheduling_policy["periodicity"] == "Daily":
            daily_schedule = DailySchedule()
            daily_schedule.days = [
                "k" + day for day in scheduling_policy.get("days", [])
            ]
            schedule.daily_schedule = daily_schedule
        if scheduling_policy["periodicity"] == "Monthly":
            monthly_schedule = MonthlySchedule()
            monthly_schedule.day = "k" + scheduling_policy["day"]
            monthly_schedule.day_count = "k" + scheduling_policy["day_count"]
            schedule.monthly_schedule = monthly_schedule
        if scheduling_policy["periodicity"] == "Continuous":
            continuous_schedule = ContinuousSchedule()
            continuous_schedule.backup_interval_mins = scheduling_policy[
                "backup_interval_mins"
            ]
            schedule.continuous_schedule = continuous_schedule
        return schedule
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def extended_retention(module):
    """
    function to construct the list of extended retention policies
    :param module: object that holds parameters passed to the module
    :return:
    """
    try:
        extended_retentions = []
        for retention in module.params.get("extended_retention"):
            retention_policy = ExtendedRetentionPolicy()
            if module.params.get("full_backup_schedule") and retention.get(
                "backup_run_type", ""
            ):
                retention_policy.backup_run_type = "k" + retention.get(
                    "backup_run_type", "Full"
                )
            retention_policy.periodicity = "k" + retention.get(
                "retention_periodicity", "Week"
            )
            retention_policy.days_to_keep = retention.get(
                "days_to_retain", module.params.get("days_to_retain")
            )
            retention_policy.multiplier = retention.get("multiplier", 1)
            extended_retentions.append(retention_policy)
        return extended_retentions
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def get_remote_cluster_id(module, cluster_name):
    """
    function to get the remote cluster id
    :param module: object that holds parameters passed to the module
    :param target_name: remote cluster name
    :return:
    """
    try:
        clusters = cohesity_client.remote_cluster.get_remote_clusters(
            cluster_names=cluster_name
        )
        for cluster in clusters:
            if cluster.name == cluster_name:
                return cluster.cluster_id
        if module.check_mode:
            return None
        raise__cohesity_exception__handler(
            "Failed to find replication cluster " + str(cluster_name), module
        )
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def get_external_target_id(module, target_name):
    """
    function to get the external target id
    :param module: object that holds parameters passed to the module
    :param target_name: external target name
    :return:
    """
    try:
        vaults = cohesity_client.vaults.get_vaults(name=target_name)
        for vault in vaults:
            if vault.name == target_name:
                return vault.id
        if module.check_mode:
            return None
        raise__cohesity_exception__handler(
            "Failed to find external target " + str(target_name), module
        )
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def replication_copy_policies(module):
    """
    :param module: object that holds parameters passed to the module
    :return:
    """
    try:
        replication_policies = []
        for policy in module.params.get("replication_copy"):
            replication_policy = SnapshotReplicationCopyPolicy()
            replication_policy.multiplier = policy.get("multiplier", 1)
            replication_policy.copy_partial = policy.get("copy_partial", True)
            replication_policy.days_to_keep = policy.get(
                "days_to_retain", module.params.get("days_to_retain")
            )
            replication_policy.periodicity = "k" + policy.get("periodicity", "Day")
            replication_target = ReplicationTargetSettings()
            replication_target.cluster_id = get_remote_cluster_id(
                module, policy.get("cluster_name")
            )
            replication_target.cluster_name = policy.get("cluster_name")
            replication_policy.target = replication_target
            replication_policies.append(replication_policy)
        return replication_policies
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def archival_copy_policies(module):
    """
    :param module: object that holds parameters passed to the module
    :return:
    """
    try:
        archival_policies = []
        for policy in module.params.get("archival_copy"):
            archival_policy = SnapshotArchivalCopyPolicy()
            archival_policy.multiplier = policy.get("multiplier", 1)
            archival_policy.copy_partial = policy.get("copy_partial", True)
            archival_policy.days_to_keep = policy.get(
                "days_to_retain", module.params.get("days_to_retain")
            )
            archival_policy.periodicity = "k" + policy.get("periodicity", "Day")
            external_target = ArchivalExternalTarget()
            external_target.vault_name = policy.get("target_name")
            external_target.vault_type = "k" + policy.get("target_type")
            vault_id = get_external_target_id(module, policy.get("target_name"))
            if not vault_id:
                module.fail_json(
                    "External target '%s' is not available" % external_target.vault_name
                )
            external_target.vault_id = vault_id
            archival_policy.target = external_target
            archival_policies.append(archival_policy)
        return archival_policies
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def create_policy(module):
    """
    function to create a protection policy
    :param module: object that holds parameters passed to the module
    :return:
    """
    try:
        policy_request = ProtectionPolicyRequest()
        policy_request.name = module.params.get("name")
        policy_request.description = module.params.get("description")
        policy_request.days_to_keep = module.params.get("days_to_retain")
        policy_request.retries = module.params.get("retries")
        policy_request.retry_interval_mins = module.params.get("retry_interval")
        if module.params.get("blackout_window"):
            policy_request.blackout_periods = blackout_window(module)

        if module.params.get("incremental_backup_schedule"):
            policy_request.incremental_scheduling_policy = policy_schedule(
                module, module.params.get("incremental_backup_schedule")
            )

        if module.params.get("full_backup_schedule"):
            policy_request.full_scheduling_policy = policy_schedule(
                module, module.params.get("full_backup_schedule")
            )

        if module.params.get("log_backup_schedule"):
            policy_request.log_scheduling_policy = policy_schedule(
                module, module.params.get("log_backup_schedule")
            )
            policy_request.days_to_keep_log = module.params.get(
                "log_backup_schedule"
            ).get("days_to_retain", module.params.get("days_to_retain"))

        if module.params.get("bmr_backup_schedule"):
            policy_request.system_scheduling_policy = policy_schedule(
                module, module.params.get("bmr_backup_schedule")
            )
            policy_request.days_to_keep_system = module.params.get(
                "bmr_backup_schedule"
            ).get("days_to_retain", module.params.get("days_to_retain"))

        if module.params.get("extended_retention"):
            policy_request.extended_retention_policies = extended_retention(module)

        if module.params.get("replication_copy"):
            policy_request.snapshot_replication_copy_policies = (
                replication_copy_policies(module)
            )
        if module.params.get("archival_copy"):
            policy_request.snapshot_archival_copy_policies = archival_copy_policies(
                module
            )

        policy_response = cohesity_client.protection_policies.create_protection_policy(
            policy_request
        )

        result = dict(
            changed=True,
            msg="Cohesity protection policy is created successfully",
            id=policy_response.id,
            task_name=module.params.get("name"),
        )
        module.exit_json(**result)
    except APIException as ex:
        raise__cohesity_exception__handler(
            str(json.loads(ex.context.response.raw_body)), module
        )
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def update_policy(module, policy):
    """
    Function to update a protection policy.
    :param module: object that holds parameters passed to the module
    :param policy: existing policy object.
    :return:
    """
    try:
        policy.name = module.params.get("name")
        policy.description = module.params.get("description")
        policy.days_to_keep = module.params.get("days_to_retain")
        policy.retries = module.params.get("retries")
        policy.retry_interval_mins = module.params.get("retry_interval")
        if module.params.get("blackout_window"):
            policy.blackout_periods = blackout_window(module)

        if module.params.get("incremental_backup_schedule"):
            policy.incremental_scheduling_policy = policy_schedule(
                module, module.params.get("incremental_backup_schedule")
            )

        if module.params.get("full_backup_schedule"):
            policy.full_scheduling_policy = policy_schedule(
                module, module.params.get("full_backup_schedule")
            )

        if module.params.get("log_backup_schedule"):
            policy.log_scheduling_policy = policy_schedule(
                module, module.params.get("log_backup_schedule")
            )
            policy.days_to_keep_log = module.params.get("log_backup_schedule").get(
                "days_to_retain", module.params.get("days_to_retain")
            )

        if module.params.get("bmr_backup_schedule"):
            policy.system_scheduling_policy = policy_schedule(
                module, module.params.get("bmr_backup_schedule")
            )
            policy.days_to_keep_system = module.params.get("bmr_backup_schedule").get(
                "days_to_retain", module.params.get("days_to_retain")
            )

        if module.params.get("extended_retention"):
            policy.extended_retention_policies = extended_retention(module)

        if module.params.get("replication_copy"):
            policy.snapshot_replication_copy_policies = replication_copy_policies(
                module
            )
        if module.params.get("archival_copy"):
            policy.snapshot_archival_copy_policies = archival_copy_policies(module)
        policy_response = cohesity_client.protection_policies.update_protection_policy(
            policy, policy.id
        )
        result = dict(
            changed=True,
            msg="Cohesity protection policy is updated successfully",
            id=policy_response.id,
            task_name=module.params.get("name"),
        )
        module.exit_json(**result)
    except APIException as ex:
        raise__cohesity_exception__handler(
            str(json.loads(ex.context.response.raw_body)), module
        )
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def delete_policy(module, policy_id):
    """
    function to delete the protection policy
    :param module: object that holds parameters passed to the module
    :param policy_id: protection policy id
    :return:
    """
    try:
        cohesity_client.protection_policies.delete_protection_policy(id=policy_id)
    except APIException as ex:
        raise__cohesity_exception__handler(
            str(json.loads(ex.context.response.raw_body)), module
        )
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def main():
    # => Load the default arguments including those specific to the Cohesity protection policy.
    argument_spec = cohesity_common_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            description=dict(type="str", default=""),
            state=dict(choices=["present", "absent"], default="present"),
            days_to_retain=dict(type="int", default=90),
            incremental_backup_schedule=dict(type="dict", required=True),
            full_backup_schedule=dict(type="dict"),
            blackout_window=dict(type="list", elements="dict"),
            retries=dict(type="int", default=3),
            retry_interval=dict(type="int", default=30),
            bmr_backup_schedule=dict(type="dict"),
            log_backup_schedule=dict(type="dict"),
            extended_retention=dict(type="list", elements="dict"),
            archival_copy=dict(type="list", elements="dict"),
            replication_copy=dict(type="list", elements="dict"),
        )
    )

    # => Create a new module object
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    results = dict(
        changed=False,
        msg="Attempting to manage Cohesity protection policy",
        state=module.params.get("state"),
    )

    global cohesity_client
    base_controller = BaseController()
    base_controller.global_headers["user-agent"] = "cohesity-ansible/v{}".format(RELEASE_VERSION)
    cohesity_client = get_cohesity_client(module)
    policy_exists, policy_details = get_policy_details(module)

    if module.check_mode:
        check_mode_results = dict(
            changed=False,
            msg="Check Mode: Cohesity protection policy doesn't exist",
            id="",
        )
        if module.params.get("state") == "present":
            if policy_exists:
                check_mode_results["msg"] = (
                    "Check Mode: Cohesity protection policy is already present. No changes"
                )
                check_mode_results["id"] = policy_details.id
            else:
                check_mode_results["msg"] = ""
                message = (
                    "Check Mode: Cohesity protection policy doesn't exist."
                    " This action would create a protection policy."
                )

                if module.params.get("archival_copy"):
                    unavailable_targets = []
                    for target in module.params.get("archival_copy"):
                        if not get_external_target_id(target["target_name"]):
                            unavailable_targets.append(target["target_name"])
                    if unavailable_targets:
                        check_mode_results["msg"] += (
                            "Following list of external targets "
                            "are not available, '%s'" % ", ".join(unavailable_targets)
                        )
                if module.params.get("replication_copy"):
                    unavailable_remote_clusters = []
                    for cluster in module.params.get("replication_copy"):
                        if not get_remote_cluster_id(module, cluster["cluster_name"]):
                            unavailable_remote_clusters.append(cluster["cluster_name"])
                    if unavailable_remote_clusters:
                        check_mode_results["msg"] += (
                            "Following list of remote clusters "
                            "are not available, '%s'"
                            % ", ".join(unavailable_remote_clusters)
                        )
                # If there aren't any errors, display the default message.
                if not check_mode_results["msg"]:
                    check_mode_results["msg"] = message
                check_mode_results["changed"] = True
        else:
            if policy_exists:
                check_mode_results["msg"] = (
                    "Check Mode: Cohesity protection policy is present."
                    "This action would delete the policy."
                )
                check_mode_results["id"] = policy_details.id
                check_mode_results["changed"] = True
            else:
                check_mode_results["msg"] = (
                    "Check Mode: Cohesity protection policy doesn't exist. No changes."
                )
        module.exit_json(**check_mode_results)

    elif module.params.get("state") == "present":
        if policy_exists:
            update_policy(module, policy_details)
        else:
            create_policy(module)

    elif module.params.get("state") == "absent":
        if policy_exists:
            delete_policy(module, policy_details.id)
            results = dict(
                changed=True,
                msg="Cohesity protection policy is deleted",
                id=policy_details.id,
                policy_name=module.params.get("name"),
            )
        else:
            results = dict(
                changed=False,
                msg="Cohesity protection policy doesn't exist",
                policy_name=module.params.get("name"),
            )
    else:
        module.fail_json(
            msg="Invalid State selected: {0}".format(module.params.get("state")),
            changed=False,
        )

    module.exit_json(**results)


if __name__ == "__main__":
    main()
