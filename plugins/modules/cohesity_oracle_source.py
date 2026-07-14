#!/usr/bin/python
# Copyright (c) 2021 Cohesity Inc


from __future__ import absolute_import, division, print_function

__metaclass__ = type

# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = r"""
---
author: "Naveena (@naveena-maplelabs)"
description:
  - "Ansible Module used to register or remove the Oracle Sources to/from a Cohesity Cluster."
  - "When executed in a playbook, the Cohesity Protection Source will be validated and the appropriate"
  - "state action will be applied."
  - "Supports both Oracle Standalone and Oracle RAC (Real Application Clusters) deployments."
module: cohesity_oracle_source
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
  endpoint:
    description:
      - "Specifies the network endpoint of the Protection Source where it is reachable. It could"
      - "be an URL or hostname or an IP address of the Protection Source or a NAS Share/Export Path."
      - "Required when I(source_type=standalone)."
      - "Optional when I(source_type=rac). Use as a reachable agent host when the Cohesity cluster"
      - "cannot reach the SCAN/VIP in I(scan_vip_address); sent as the connection endpoint during"
      - "RAC physical registration."
    required: false
    default: ""
    type: str
  scan_vip_address:
    description:
      - "Oracle RAC SCAN/VIP address. Same label as C(SCAN/VIP Address) in the Cohesity UI."
      - "Required when I(source_type=rac)."
      - "Used as the registered physical source name during RAC registration."
    aliases:
      - rac_agent_node
    type: str
    default: ""
  source_type:
    description:
      - "Specifies the type of Oracle deployment being registered."
      - "Use C(standalone) for a single-node Oracle host. This is the default."
      - "Use C(rac) for Oracle RAC with I(scan_vip_address) as SCAN/VIP and optional I(endpoint)"
      - "as a reachable host when the cluster cannot reach the SCAN/VIP."
    choices:
      - standalone
      - rac
    default: standalone
    type: str
  force_register:
    default: false
    description:
      - "Enabling this option will force the registration of the Cohesity Protection Source."
    type: bool
  refresh:
    default: false
    description:
      - "Switch determines whether to refresh the existing source."
      - "Applicable only when source is already registered."
    type: bool
  db_password:
    default: ""
    description:
      - "Specifies the password to access the target source database."
      - "This parameter will not be logged."
      - "Applicable only when state is set to present."
    type: str
  db_username:
    default: ""
    description:
      - "Specifies username to access the target source database."
      - "Applicable only when state is set to present."
    type: str
  state:
    choices:
      - present
      - absent
    default: present
    description:
      - "Determines the state of the Protection Source"
    type: str

extends_documentation_fragment:
- cohesity.dataprotect.cohesity
short_description: "Management of Cohesity Protection Sources"
version_added: 1.3.0
"""


EXAMPLES = """
# Register a Physical Cohesity Protection Source and register the physical source
# as Oracle server.
- cohesity_oracle:
    server: cohesity-cluster-vip
    username: admin
    password: password
    endpoint: endpoint
    state: present
# Unegister an existing Cohesity Protection Source on a selected endpoint
- cohesity_oracle:
    server: cohesity-cluster-vip
    username: admin
    password: password
    endpoint: endpoint
    state: absent

# Register an Oracle standalone host as a Protection Source.
- cohesity.dataprotect.cohesity_oracle_source:
    cluster: cohesity-cluster-vip
    username: admin
    password: password
    endpoint: oracle-host.example.com
    source_type: standalone
    state: present

# Register an Oracle RAC cluster as a Protection Source.
- cohesity.dataprotect.cohesity_oracle_source:
    cluster: cohesity-cluster-vip
    username: admin
    password: password
    scan_vip_address: scan vip address
    endpoint: reachable host address
    source_type: rac
    state: present
"""

RETURN = """
"""

import json
import time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url
try:
    from urllib import error as urllib_error
except ImportError:
    from ansible.module_utils.urls import urllib_error

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
        get_cohesity_client,
        refresh_protection_source,
        check_source_reachability,
    )
    from cohesity_management_sdk.models.register_protection_source_parameters import (
        RegisterProtectionSourceParameters,
    )

except Exception:
    pass


def _rac_connect_address(module):
    """Reachable host for physical registration; falls back to SCAN/VIP."""
    reachable = module.params.get("endpoint") or ""
    if reachable:
        return reachable
    return module.params.get("scan_vip_address") or ""


def _build_prot_sources(module, environment):
    prot_sources = dict(
        token=get__cohesity_auth__token(module),
        endpoint=module.params.get("endpoint") or "",
        environment=environment,
    )
    if module.params.get("source_type") == "rac":
        prot_sources["source_type"] = "rac"
        rac_scan = module.params.get("scan_vip_address")
        if rac_scan:
            prot_sources["scan_vip_address"] = rac_scan
    return prot_sources


def register_rac_physical_source(module, self):
    """Register RAC physical source via /backupsources (UI-equivalent payload)."""
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = self["token"]
    scan_address = self["scan_vip_address"]
    connect_address = self.get("endpoint") or scan_address
    try:
        uri = "https://" + server + "/irisservices/api/v1/backupsources"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": "Bearer " + token,
        }
        payload = dict(
            entity=dict(
                physicalEntity=dict(
                    hostType=1,
                    name=scan_address,
                    type=6,
                ),
                type=6,
            ),
            entityInfo=dict(
                endPoint=connect_address,
                hostType=1,
                type=6,
            ),
            forceRegister=module.params.get("force_register"),
            sourceSideDedupEnabled=True,
            registeredEntityParams=dict(
                throttlingPolicy=dict(isThrottlingEnabled=False)
            ),
            connectionId=None,
        )
        response = open_url(
            url=uri,
            data=json.dumps(payload),
            headers=headers,
            validate_certs=validate_certs,
            method="POST",
            timeout=REQUEST_TIMEOUT,
        )
        return json.loads(response.read())
    except urllib_error.URLError as e:
        raise__cohesity_exception__handler(e.read(), module)
        return None
    except Exception as error:
        raise__cohesity_exception__handler(error, module)
        return None


def register_oracle_source(module, self, _id):
    """
    : To register a Oracle source, it should be already registered as Physical
    : source in the cluster.
    : Register a physical source as a Oracle source using physical source id.
    """
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = self["token"]
    endpoint = self.get("scan_vip_address") or self.get("endpoint")
    source_id = _id
    db_user = module.params.get("db_username")
    db_pwd = module.params.get("db_password")

    try:
        uri = "https://" + server + "/irisservices/api/v1/applicationSourceRegistration"
        headers = {"Accept": "application/json", "Content-Type": "application/json", "Authorization": "Bearer " + token}
        # Payload to register Oracle source.
        payload = dict(
            appEnvVec=[19], usesPersistentAgent=True, ownerEntity=dict(type=6)
        )
        payload["ownerEntity"]["id"] = source_id
        payload["ownerEntity"]["displayName"] = endpoint
        if db_user and db_pwd:
            cred = dict(username=db_user, password=db_pwd)
            payload["appCredentialsVec"] = list()
            payload["appCredentialsVec"].append(dict(credentials=cred, envType=19))
        data = json.dumps(payload)
        response = open_url(
            url=uri,
            data=data,
            headers=headers,
            validate_certs=validate_certs,
            timeout=REQUEST_TIMEOUT,
        )

        response = json.loads(response.read())
        return bool(response)
    except urllib_error.URLError as e:
        raise__cohesity_exception__handler(e.read(), module)
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def get__protection_source_registration__status(module, self):
    """
    Function to fetch the source registration status.
    """
    try:
        env = self["environment"]
        endpoint = self.get("endpoint") or ""
        scan = self.get("scan_vip_address") or ""
        resp = cohesity_client.protection_sources.list_protection_sources(
            environments=env
        )
        if resp:
            nodes = resp[0].nodes
            for node in nodes:
                if node["protectionSource"]["name"] == endpoint:
                    return node["protectionSource"]["id"]
                if self.get("source_type") == "rac":
                    reg_info = node.get("registrationInfo", {})
                    access_endpoint = reg_info.get("accessInfo", {}).get("endpoint", "")
                    source_name = node["protectionSource"]["name"]
                    if scan and source_name == scan:
                        return node["protectionSource"]["id"]
                    if endpoint and access_endpoint == endpoint:
                        return node["protectionSource"]["id"]
        return False
    except urllib_error.URLError as e:
        # => Capture and report any error messages.
        raise__cohesity_exception__handler(e.read(), module)
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


# => Register the Endpoint as a Cohesity Physical Protection Source.
def register_source(module, self):
    try:
        body = RegisterProtectionSourceParameters()
        body.endpoint = self["endpoint"]
        body.environment = self["environment"]
        body.force_register = module.params.get("force_register")
        body.physical_type = "kHost"
        body.host_type = "kLinux"
        response = cohesity_client.protection_sources.create_register_protection_source(
            body
        )
        return response
    except urllib_error.URLError as e:
        # => Capture and report any error messages.
        raise__cohesity_exception__handler(e.read(), module)
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


# => Unregister an existing Cohesity Protection Source.
def unregister_source(module, source_id):
    try:
        response = (
            cohesity_client.protection_sources.delete_unregister_protection_source(
                source_id
            )
        )
        return response
    except urllib_error.URLError as e:
        # => Capture and report any error messages.
        raise__cohesity_exception__handler(e.read(), module)
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def main():
    # => Load the default arguments including those specific to the Cohesity Agent.
    argument_spec = cohesity_common_argument_spec()
    argument_spec.update(
        dict(
            state=dict(choices=["present", "absent"], default="present"),
            endpoint=dict(type="str", default=""),
            source_type=dict(
                type="str",
                choices=["standalone", "rac"],
                default="standalone",
            ),
            scan_vip_address=dict(default="", type="str", aliases=["rac_agent_node"]),
            force_register=dict(default=False, type="bool"),
            refresh=dict(default=False, type="bool"),
            db_username=dict(default="", type="str"),
            db_password=dict(default="", type="str", no_log=True),
        )
    )

    # => Create a new module object
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    global cohesity_client
    cohesity_client = get_cohesity_client(module)

    if module.params.get("source_type") == "rac":
        if not module.params.get("scan_vip_address"):
            module.fail_json(
                msg=(
                    "scan_vip_address (SCAN/VIP Address) is required when "
                    "source_type is rac."
                )
            )
    elif not module.params.get("endpoint"):
        module.fail_json(
            msg="endpoint is required when source_type is standalone."
        )

    results = dict(
        changed=False,
        msg="Attempting to manage Protection Source",
        state=module.params.get("state"),
    )

    # Check the endpoint is already registred as a Physical source.
    prot_sources = _build_prot_sources(module, "kPhysical")
    current_status = get__protection_source_registration__status(module, prot_sources)

    if module.check_mode:
        prot_sources["environment"] = "kOracle"
        current_status = get__protection_source_registration__status(
            module, prot_sources
        )
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
                reachability_target = module.params.get("endpoint")
                if module.params.get("source_type") == "rac":
                    reachability_target = _rac_connect_address(module)
                status = check_source_reachability(reachability_target)
                if status is None:
                    check_mode_results[
                        "msg"
                    ] += "Please ensure cohesity agent is installed in the source and port 50051 is open"
                elif not status:
                    check_mode_results[
                        "msg"
                    ] += "Source '%s' is not reachable" % reachability_target

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
        if current_status:
            prot_sources = _build_prot_sources(module, "kOracle")
            oracle_status = get__protection_source_registration__status(
                module, prot_sources
            )
            if not oracle_status:
                resp = register_oracle_source(module, prot_sources, current_status)
                if resp is True:
                    results = dict(
                        changed=True,
                        msg="Registration of Cohesity Protection Source Complete",
                    )
                else:
                    results = dict(
                        changed=False,
                        msg="Error while registering Cohesity Protection Source",
                    )

            else:
                msg = "The Protection Source for this host is already registered"
                if module.params.get("refresh"):
                    refresh_protection_source(module, current_status)
                    msg = "Successfully refreshed the Oracle Source '%s'." % (
                        module.params.get("scan_vip_address")
                        if module.params.get("source_type") == "rac"
                        else module.params.get("endpoint")
                    )

                results = dict(
                    changed=False,
                    msg=msg,
                    id=current_status,
                    endpoint=module.params.get("endpoint"),
                )
        else:
            is_rac = module.params.get("source_type") == "rac"

            sleep_count = 0
            response = None

            # Register the endpoint as Physical source first.
            if is_rac:
                register_rac_physical_source(module, prot_sources)
            else:
                response = register_source(module, prot_sources)

            # Wait until Physical source is successfully registered.
            wait_sources = dict(
                environment="kPhysical",
                token=prot_sources["token"],
                endpoint=prot_sources.get("endpoint") or "",
            )
            if is_rac:
                wait_sources["source_type"] = "rac"
                wait_sources["scan_vip_address"] = prot_sources["scan_vip_address"]

            while sleep_count < 5:
                sleep_count += 1
                status = get__protection_source_registration__status(
                    module, wait_sources
                )
                time.sleep(10)

            if status is False:
                module.fail_json(
                    changed=False,
                    msg="Error while registering Cohesity Physical Protection Source",
                )

            if not is_rac and response is None:
                module.fail_json(
                    changed=False,
                    msg="Error while registering Cohesity Physical Protection Source",
                )

            source_id = status if is_rac else response.id
            response = register_oracle_source(module, prot_sources, source_id)
            if response is True:
                results = dict(
                    changed=True,
                    msg="Registration of Cohesity Protection Source Complete",
                )
            else:
                results = dict(
                    changed=False,
                    msg="Error while registering Cohesity Protection Source",
                )

    elif module.params.get("state") == "absent":
        if current_status:
            response = unregister_source(module, current_status)

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
