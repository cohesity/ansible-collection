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
module: cohesity_oracle_restore
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
      - Determines if the oracle recovery should be C(present) or C(absent).
      - absent is currently not implemented.
    type: str

  audit_path:
    default: ''
    description: Yet to be implemented.
    type: str
  bct_file:
    default: ''
    description: Yet to be implemented.
    type: str
  channels:
    description: Yet to be implemented.
    required: false
    type: str
  clone_app_view:
    default: false
    description: Enabling this option will clone app view.
    type: bool
  control_file:
    default: ''
    description: Yet to be implemented.
    type: str
  diag_path:
    default: ''
    description: Yet to be implemented.
    type: str
  fra_path:
    default: ''
    description: Fra Path.  Yet to be implemented.
    type: str
  fra_size_mb:
    default: 2048
    description: Specifies the Fra size Mb.
    type: int
  log_time:
    default: ''
    description: Log Time. Yet to be implemented.
    type: str
  no_recovery:
    default: false
    description: No recovery. Yet to be implemented.
    type: bool
  oracle_base:
    description: Specifies the oracle base directory.
    required: true
    type: str
  oracle_data:
    description: Oracle Data. Yet to be implemented.
    required: true
    type: str
  oracle_home:
    description: Specifies the Oracle home directory path.
    required: true
    type: str
  overwrite:
    default: false
    description: Enabling this option will overwrite the database, if already available.
    type: bool
  redo_log_path:
    default: ''
    description: Redo Log Path. Yet to be implemented.
    type: str
  source_db:
    description: Specifies the name of the database which needs to be recovered.
    required: true
    type: str
  source_server:
    description: Specifies the source server name where database is located.
    required: true
    type: str
  target_db:
    description:
      - Specifies the name of the target database that will be restored.
      - If the database is not already available new database will be created.
    required: true
    type: str
  target_server:
    description: 'Specifies the oracle server where database is restored.'
    required: true
    type: str
  task_name:
    description: 'Specifies the restore task name'
    type: str

extends_documentation_fragment:
- cohesity.dataprotect.cohesity
short_description: "Restore one or more Virtual Machines from Cohesity Protection Jobs"
version_added: 1.1.6
"""

EXAMPLES = """
# Restore Oracle database.
- name: Restore Oracle database.
  cohesity_oracle_restore:
    source_db: cdb1
    task_name: recover_tasks
    source_server: "192.168.1.1"
    target_server: "192.168.1.1"
    target_db: cdb2
    oracle_home: /u01/app/oracle/product/12.1.0.2/db_1
    oracle_base: /u01/app/oracle
    oracle_data: /u01/app/oracle/product/12.1.0.2/db_1

"""

import json
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
        get__prot_source_id__by_endpoint,
        get_cohesity_client,
    )
except Exception:
    pass


class ParameterViolation(Exception):
    pass


class ProtectionException(Exception):
    pass


def create_recover_job(module, token, database_info):
    """
    Fucntion to create new oracle recovery tasks.
    """
    # Fetch latest successful run id.
    job_run_id = None
    action = "kRecoverApp"
    vm_action = "kRecoverVMs"
    job_id = database_info["vmDocument"]["objectId"]["jobId"]
    resp = cohesity_client.protection_runs.get_protection_runs(job_id=job_id)
    if not resp:
        module.exit_json(msg="Job %s is currently not available." % job_id)

    for job in resp:
        status = job.backup_run.status
        if status == "kSuccess":
            job_run_id = job.backup_run.job_run_id
            start_time = job.backup_run.stats.start_time_usecs
    if not job_run_id:
        module.exit_json(msg="No successful run available for job %s." % job_id)

    owner_object = dict(
        jobUid=database_info["vmDocument"]["objectId"]["jobUid"],
        jobId=database_info["vmDocument"]["objectId"]["jobId"],
        jobInstanceId=job_run_id,
        startTimeUsecs=start_time,
        entity=dict(id=database_info["vmDocument"]["objectId"]["entity"]["parentId"]),
    )
    oracle_db_config = dict(
        controlFilePathVec=[],
        enableArchiveLogMode=True,
        redoLogConf=dict(groupMemberVec=[], memberPrefix="redo", sizeMb=20),
        fraSizeMb=module.params.get("fra_size_mb"),
    )

    # Alternate location params.
    alternate_location_params = None
    server = module.params.get("cluster")
    clone_app_view = module.params.get("clone_app_view")
    source_db = module.params.get("source_db")
    source_server = module.params.get("source_server")
    validate_certs = module.params.get("validate_certs")
    target_db = module.params.get("target_db")
    target_server = module.params.get("target_server")
    oracle_restore_params = dict(captureTailLogs=False)
    restore_params = dict()

    if clone_app_view:
        action = "kCloneAppView"
        vm_action = "kCloneVMs"
        oracle_restore_params["oracleCloneAppViewParamsVec"] = [dict()]

    elif source_server != target_server or source_db != target_db:
        module_params = dict(
            token=token, environment="Physical", endpoint=target_server
        )
        target_source_id = get__prot_source_id__by_endpoint(module, module_params)
        if not target_source_id:
            error_msg = "Failed to find target server '%s'" % target_server
            if module.check_mode:
                module.exit_json(msg="Check Mode " + error_msg)
            module.fail_json(msg=error_msg)
        alternate_location_params = dict(
            newDatabaseName=module.params.get("target_db"),
            homeDir=module.params.get("oracle_home"),
            baseDir=module.params.get("oracle_base"),
            oracleDBConfig=oracle_db_config,
            databaseFileDestination=module.params.get("oracle_home"),
        )
        restore_params["targetHost"] = dict(id=target_source_id)
        oracle_restore_params["alternateLocationParams"] = alternate_location_params
    restore_params["oracleRestoreParams"] = oracle_restore_params
    restore_obj_vec = dict(
        appEntity=database_info["vmDocument"]["objectId"]["entity"],
        restoreParams=restore_params,
    )
    owner_restore_info = dict(
        ownerObject=owner_object,
        ownerRestoreParams=dict(action=vm_action),
        performRestore=False,
    )

    body = dict(
        name=module.params.get("task_name"),
        action=action,
        restoreAppParams=dict(
            type=19,
            ownerRestoreInfo=owner_restore_info,
            restoreAppObjectVec=[restore_obj_vec],
        ),
    )
    if module.check_mode:
        module.exit_json(msg="Check Mode: This action will create new recover task")
    try:
        uri = "https://" + server + "/irisservices/api/v1/recoverApplication"
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
    except Exception as err:
        module.fail_json(
            msg='Error while recovery task creation, error message: "%s".' % err
        )


def check_for_status(module, task_id):
    try:
        while True:
            resp = cohesity_client.restore_tasks.get_restore_tasks(task_ids=task_id)
            if not resp:
                raise Exception("Recovery tasks not available")
            status = resp[0].status
            if status in ["kCancelled", "kFinished"]:
                return status == "kFinished"
    except Exception as err:
        module.exit_json(msg=err)


def search_for_database(token, module):
    """
    Function to fetch database details if available.
    """
    server = module.params.get("cluster")
    sourcedb = module.params.get("source_db")
    source_server = module.params.get("source_server")
    validate_certs = module.params.get("validate_certs")
    try:
        uri = (
            "https://"
            + server
            + "/irisservices/api/v1/searchvms?entityTypes=kOracle&vmName=%s" % sourcedb
        )
        headers = {"Accept": "application/json", "Authorization": "Bearer " + token}
        response = open_url(
            url=uri,
            method="GET",
            headers=headers,
            validate_certs=validate_certs,
            timeout=REQUEST_TIMEOUT,
        )

        response = json.loads(response.read())
        if not response:
            if module.check_mode:
                module.exit_json(msg="Source database %s not available." % sourcedb)
            raise Exception("Source database %s not available." % sourcedb)
        vms = response["vms"]
        snapshot_timesecs = 0
        search_info = ""
        for vm in vms:
            time_secs = vm["vmDocument"]["versions"][0]["snapshotTimestampUsecs"]
            if (
                source_server in vm["vmDocument"]["objectAliases"]
                and time_secs > snapshot_timesecs
            ):
                snapshot_timesecs = time_secs
                search_info = vm
        if not search_info:
            err_msg = "Source database %s not available in source %s." % (
                sourcedb,
                source_server,
            )
            if module.check_mode:
                module.exit_json(msg="Check Mode: %s" % err_msg)
            raise Exception(err_msg)
        return search_info
    except Exception as err:
        module.fail_json(msg=str(err))


def main():
    # => Load the default arguments including those specific to the Cohesity Protection Jobs.
    argument_spec = cohesity_common_argument_spec()
    argument_spec.update(
        dict(
            task_name=dict(type="str"),
            source_db=dict(type="str", required=True),
            source_server=dict(type="str", required=True),
            target_db=dict(type="str", required=True),
            target_server=dict(type="str", required=True),
            oracle_home=dict(type="str", required=True),
            oracle_base=dict(type="str", required=True),
            oracle_data=dict(type="str", required=True),
            channels=dict(type="str", required=False),
            control_file=dict(type="str", default=""),
            redo_log_path=dict(type="str", default=""),
            audit_path=dict(type="str", default=""),
            diag_path=dict(type="str", default=""),
            fra_path=dict(type="str", default=""),
            fra_size_mb=dict(type="int", default=2048),
            bct_file=dict(type="str", default=""),
            log_time=dict(type="str", default=""),
            clone_app_view=dict(type="bool", default=False),
            overwrite=dict(type="bool", default=False),
            no_recovery=dict(type="bool", default=False),
        )
    )

    # => Create a new module object
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    global cohesity_client
    cohesity_client = get_cohesity_client(module)

    token = get__cohesity_auth__token(module)
    database_info = search_for_database(token, module)
    resp = create_recover_job(module, token, database_info)

    # Check for restore task status.
    task_id = resp["restoreTask"]["performRestoreTaskState"]["base"]["taskId"]
    status = check_for_status(module, task_id)
    if not status:
        msg = "Error occured during task recovery."
        module.fail_json(msg=msg)

    results = dict(
        changed=True,
        msg="Successfully created restore task '%s'" % module.params.get("task_name"),
    )
    module.exit_json(**results)


if __name__ == "__main__":
    main()
