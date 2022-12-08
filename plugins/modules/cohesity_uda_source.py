#!/usr/bin/python
# Copyright (c) 2022 Cohesity Inc


from __future__ import absolute_import, division, print_function

__metaclass__ = type

# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = """
---
author: "Naveena (@naveena-maplelabs)"
description:
  - "Ansible Module used to register or remove the Cohesity Protection Sources to/from a Cohesity Cluster."
  - "When executed in a playbook, the Cohesity Protection Source will be validated and the appropriate"
  - "state action will be applied."
module: cohesity_uda_source
options:
  cluster:
    aliases:
      - cohesity_server
    description:
      - "IP or FQDN for the Cohesity Cluster"
    type: str
  hosts:
    type: list
    elements: str
    description:
      - Specifies the list of Ips/hostnames for the nodes forming UDA Source Cluster.
  mount_view:
    type: bool
    default: False
    description: Specifies if SMB/NFS view mounting should be enabled or not.
  state:
    type: str
    choices:
      - present
      - absent
    default: present
    description:
      - "Determines the state of the Protection Source"
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
  os_type:
    type: str
    description:
      - Type of the UDA source to be registered.
      - Field is applicable for few cluster versions.
  source_type:
    type: str
    description:
      - Type of the UDA source to be registered.
    default: Linux
    choices:
      - Linux
      - Windows
      - Aix
      - Solaris
      - SapHana
      - SapOracle
      - CockroachDB
      - MySQL
      - VMWareCDPFilter
      - PostgreSQL
      - Other
  cohesity_password:
    aliases:
      - password
      - admin_pass
    description:
      - "Password belonging to the selected Username.  This parameter will not be logged."
    type: str
  db_username:
    type: str
    description:
      - Username of the database.
  db_password:
    type: str
    description:
      - Password of the database.
  scripts_dir:
    type: str
    description:
      - Absolute path of the scripts used to interact with the UDA source.
    default: /opt/cohesity/postgres/scripts/
  source_registration_args:
    type: str
    description:
      - Specifies the custom arguments to be supplied to the source registration scripts.
  source_name:
    type: str
    required: True
    description:
      - Specifies the name of the protection source while registering.
  endpoint:
    description:
      - "Specifies the network endpoint of the Protection Source where it is reachable. It could"
      - "be an URL or hostname or an IP address of the Protection Source"
    required: true
    type: str
  update_source:
    type: bool
    default: False
    description:
      - Specifies whether to update the source, if the source is already registered.
extends_documentation_fragment:
- cohesity.dataprotect.cohesity
short_description: "Management of UDA Protection Sources"
version_added: 1.0.9
"""

EXAMPLES = """
# Unegister an existing Cohesity Protection Source on a selected endpoint
- cohesity_source:
    server: cohesity.lab
    username: admin
    password: password
    endpoint: myvcenter.host.lab
    state: absent
"""

RETURN = """
"""

import json
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
        get__prot_source__all, unregister_source
    )
    from ansible_collections.cohesity.dataprotect.plugins.modules.cohesity_source import unregister_source
except Exception:
    pass


class ProtectionException(Exception):
    pass


# => Determine if the Endpoint is presently registered to the Cohesity Cluster
# => and if so, then return the Protection Source ID.


def check__mandatory__params(module):
    """
    This method will perform validations of optionally mandatory parameters
    required for specific states and environments.
    """
    success = True
    missing_params = list()

    if module.params.get("state") == "present":
        action = "creation"
        if not module.params.get("hosts"):
            success = False
            missing_params.append("hosts")
    else:
        action = "remove"

    if not success:
        module.fail_json(
            msg="The following variables are mandatory for this action ("
            + action
            + ")",
            missing=missing_params,
            changed=False,
        )


def register_source(module, self):
    """
    Register the new Endpoint as a Cohesity Protection Source.
    """
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = self["token"]
    try:
        uri = "https://" + server + "/v2/data-protect/sources/registrations"
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
            "user-agent": "cohesity-ansible/v1.0.9",
        }
        payload = dict(
            environment="kUDA",
            udaParams=dict(
                sourceType='k' + module.params.get("source_type"),
                hosts=module.params.get("hosts"),
                credentials=dict(
                    username=module.params.get("db_username"),
                    password=module.params.get("db_password"),
                ),
                scriptDir=module.params.get("scripts_dir"),
                mountView=module.params.get("mount_view"),
                sourceRegistrationArgs=module.params.get("source_registration_args"),
            ),
        )
        if module.params.get("os_type", None):
            payload["osType"] = 'k' + module.params.get("os_type")
        data = json.dumps(payload)
        request_method = "POST"
        if module.params.get("update_source"):
            request_method = "PUT"
            uri += "/" + str(self["sourceId"])
        response = open_url(
            url=uri,
            method=request_method,
            data=data,
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
        # => Capture and report any error messages.
        raise__cohesity_exception__handler(error, module)


def get__protection_source_registration__status(module, self):
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = self["token"]
    try:
        source_obj = dict(
            server=server,
            token=token,
            validate_certs=validate_certs,
            environment="UDA",
        )

        source = get__prot_source__all(source_obj)

        if not source:
            return False
        for node in source:
            if node["protectionSource"]["name"] == self["source_name"]:
                return node["protectionSource"]["id"]
    except urllib_error.URLError as e:
        # => Capture and report any error messages.
        raise__cohesity_exception__handler(e.read(), module)
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def main():
    argument_spec = cohesity_common_argument_spec()
    argument_spec.update(
        dict(
            state=dict(choices=["present", "absent"], default="present"),
            source_type=dict(
                type="str",
                choices=[
                    "Linux",
                    "Windows",
                    "Aix",
                    "Solaris",
                    "SapHana",
                    "SapOracle",
                    "CockroachDB",
                    "MySQL",
                    "VMWareCDPFilter",
                    "PostgreSQL",
                    "Other",
                ],
                default="Linux",
            ),
            os_type=dict(type="str", required=False),
            endpoint=dict(type="str", required=True),
            hosts=dict(type="list", default=[], elements="str"),
            mount_view=dict(default=False, type="bool"),
            scripts_dir=dict(default="/opt/cohesity/postgres/scripts/", type="str"),
            db_username=dict(type="str", default=""),
            db_password=dict(type="str", default="", no_log=True),
            source_registration_args=dict(type="str"),
            source_name=dict(type="str", required=True),
            update_source=dict(type="bool", default=False),
        )
    )

    # => Create a new module object
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    results = dict(
        changed=False,
        msg="Attempting to manage UDA Protection Source",
        state=module.params.get("state"),
    )

    prot_sources = dict(
        token=get__cohesity_auth__token(module),
        source_name=module.params.get("source_name"),
    )
    current_status = get__protection_source_registration__status(module, prot_sources)

    if module.check_mode:
        check_mode_results = dict(
            changed=False,
            msg="Check Mode: Cohesity Protection Source is not currently registered",
            id="",
        )
        if module.params.get("state") == "present":
            if current_status:
                check_mode_results[
                    "msg"
                ] = "Check Mode: Cohesity Protection Source is currently registered.  No changes"
            else:
                check_mode_results[
                    "msg"
                ] = "Check Mode: Cohesity Protection Source is not currently registered.  This action would register the Protection Source."
                check_mode_results["id"] = current_status
        else:
            if current_status:
                check_mode_results[
                    "msg"
                ] = "Check Mode: Cohesity Protection Source is currently registered.  This action would unregister the Protection Source."
                check_mode_results["id"] = current_status
            else:
                check_mode_results[
                    "msg"
                ] = "Check Mode: Cohesity Protection Source is not currently registered.  No changes."
        module.exit_json(**check_mode_results)

    elif module.params.get("state") == "present":
        check__mandatory__params(module)
        results["changed"] = True

        if current_status and not module.params.get("update_source"):
            results = dict(
                changed=False,
                msg="The Protection Source for this host is already registered",
                id=current_status,
                endpoint=module.params.get("endpoint"),
            )
        else:
            prot_sources["sourceId"] = current_status
            response = register_source(module, prot_sources)
            if not response:
                module.fail_json(
                    changed=False,
                    msg="Error while registering UDA source to the cluster")
            msg = "Registration of Cohesity Protection Source Complete"
            if module.params.get("update_source"):
                msg = "Updation of Cohesity Protection Source Complete"
            results = dict(changed=True, msg=msg, **response)

    elif module.params.get("state") == "absent":
        if current_status:
            prot_sources["id"] = current_status
            prot_sources["timeout"] = REQUEST_TIMEOUT
            response = unregister_source(module, prot_sources)

            results = dict(
                changed=True,
                msg="Unregistration of Cohesity Protection Source Complete",
                id=current_status,
                endpoint=module.params.get("endpoint"),
            )
        else:
            results = dict(
                changed=False,
                msg="The Protection Source for this host is currently not registered",
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
