#!/usr/bin/python
# Copyright (c) 2022 Cohesity Inc


from __future__ import absolute_import, division, print_function

__metaclass__ = type

# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = r"""
---
author: "Naveena (@naveena-maplelabs)"
description:
  - "Ansible Module used to register or remove the Cohesity Protection Sources to/from a Cohesity Cluster."
  - "When executed in a playbook, the Cohesity Protection Source will be validated and the appropriate"
  - "state action will be applied."
module: cohesity_source
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
  endpoint:
    description:
      - "Specifies the network endpoint of the Protection Source where it is reachable. It could"
      - "be an URL or hostname or an IP address of the Protection Source or a NAS Share/Export Path."
    required: true
    type: str
  environment:
    choices:
      - VMware
      - Physical
      - GenericNas
      - SQL
    default: Physical
    description:
      - "Specifies the environment type (such as VMware or SQL) of the Protection Source this Job"
      - "is protecting. Supported environment types include 'Physical', 'VMware', 'GenericNas'"
    required: false
    type: str
  force_register:
    default: false
    description:
      - "Enabling this option will force the registration of the Cohesity Protection Source."
    type: bool
  host_type:
    choices:
      - Linux
      - Windows
      - Aix
    default: Linux
    description:
      - "Specifies the optional OS type of the Protection Source (such as C(Windows) or C(Linux))."
      - "C(Linux) indicates the Linux operating system."
      - "C(Windows) indicates the Microsoft Windows operating system."
      - "C(Aix) indicates the IBM AIX operating system."
      - "Optional when I(state=present) and I(environment=Physical)."
    type: str
  nas_password:
    type: str
    description:
      - "Specifies the password to accessthe target NAS Environment."
      - "This parameter will not be logged."
      - "Required when I(state=present) and I(environment=GenericNas) and I(nas_protocol=SMB)"
  nas_protocol:
    choices:
      - NFS
      - SMB
    default: NFS
    type: str
    description:
      - "Specifies the protocol type of connection for the NAS Mountpoint."
      - "SMB Share paths must be in \\\\server\\share format."
      - "Required when I(state=present) and I(environment=GenericNas)"
  nas_type:
    description:
      - "Specifies the type of connection for the NAS Mountpoint."
    type: str
    default: Host
  nas_username:
    type: str
    description:
      - "Specifies username to access the target NAS Environment."
      - "Supported Format is Username or username@domain or Domain/username (will be deprecated in future)."
      - "Required when I(state=present) and I(environment=GenericNas) and I(nas_protocol=SMB)"
  physical_type:
    choices:
      - Host
      - WindowsCluster
    default: Host
    description:
      - "Specifies the entity type such as C(Host) if the I(environment=Physical)."
      - "C(Host) indicates a single physical server."
      - "C(WindowsCluster) indicates a Microsoft Windows cluster."
      - "Optional when I(state=present) and I(environment=Physical)."
    type: str
  skip_validation:
    default: false
    description: "Switch for source validation during registeration."
    type: bool
  source_password:
    description:
      - "Specifies the password to access the target source."
      - "This parameter will not be logged."
      - "Required when I(state=present) and I(environment=VMware)"
    type: str
  source_username:
    description:
      - "Specifies username to access the target source."
      - "Required when I(state=present) and I(environment=VMware)"
    type: str
  state:
    choices:
      - present
      - absent
    default: present
    description:
      - "Determines the state of the Protection Source"
    type: str
  timeout:
    default: 120
    description:
      - "Wait time in seconds while registering/updating source."
    type: int
  update_source:
    default: false
    description:
      - "Switch determines whether to update the existing source."
    type: bool
  refresh:
    default: false
    description:
      - "Switch determines whether to refresh the existing source."
      - "Applicable only when source is already registered."
    type: bool
  validate_certs:
    aliases:
      - cohesity_validate_certs
    default: true
    description:
      - "Switch determines if SSL Validation should be enabled."
    type: bool
  vmware_type:
    choices:
      - VCenter
      - Folder
      - Datacenter
      - ComputeResource
      - ClusterComputeResource
      - ResourcePool
      - Datastore
      - HostSystem
      - VirtualMachine
      - VirtualApp
      - StandaloneHost
      - StoragePod
      - Network
      - DistributedVirtualPortgroup
      - TagCategory
      - Tag
    default: VCenter
    description:
      - "Specifies the entity type such as C(VCenter) if the environment is C(VMware)."
    type: str
extends_documentation_fragment:
- cohesity.dataprotect.cohesity
short_description: "Management of Cohesity Protection Sources"
version_added: 1.1.0
"""

EXAMPLES = """
# Register a Physical Cohesity Protection Source on a selected Linux endpoint using Defaults
- cohesity_source:
    server: cohesity.lab
    username: admin
    password: password
    endpoint: mylinux.host.lab
    state: present

# Register a Physical Cohesity Protection Source on a selected Windows endpoint
- cohesity_source:
    server: cohesity.lab
    username: admin
    password: password
    endpoint: mywindows.host.lab
    environment: Physical
    host_type: Windows
    state: present

# Register a VMware Cohesity Protection Source on a selected endpoint
- cohesity_source:
    server: cohesity.lab
    username: admin
    password: password
    endpoint: myvcenter.host.lab
    environment: VMware
    source_username: admin@vcenter.local
    source_password: vmware
    vmware_type: Vcenter
    state: present

# Register a NAS Cohesity Protection Source on a selected NFS mountpoint
- cohesity_source:
    server: cohesity.lab
    username: admin
    password: password
    endpoint: mynfs.host.lab:/exports
    environment: GenericNas
    state: present

# Register a NAS Cohesity Protection Source on a selected SMB share
- cohesity_source:
    server: cohesity.lab
    username: admin
    password: password
    endpoint: \\\\myfileserver.host.lab\\data
    environment: GenericNas
    nas_protocol: SMB
    nas_username: administrator
    nas_password: password
    state: present

# Unegister an existing Cohesity Protection Source on a selected endpoint
- cohesity_source:
    server: cohesity.lab
    username: admin
    password: password
    endpoint: myvcenter.host.lab
    environment: VMware
    state: absent
"""

RETURN = """
"""

import json
import subprocess
import time
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
        get__prot_source__all,
        check_source_reachability,
        unregister_source,
    )
except Exception:
    pass

SLEEP_TIME = 10


class ProtectionException(Exception):
    pass


def check__mandatory__params(module):
    """
    # => This method will perform validations of optionally mandatory parameters
    # => required for specific states and environments.
    """
    success = True
    missing_params = list()
    environment = module.params.get("environment")
    nas_protocol = module.params.get("nas_protocol")

    if module.params.get("state") == "present":
        action = "creation"
        # module.fail_json(**module.params)
        if environment == "GenericNas" and nas_protocol == "SMB":
            if not module.params.get("nas_username"):
                success = False
                missing_params.append("nas_username")
            if not module.params.get("nas_password"):
                success = False
                missing_params.append("nas_password")

    else:
        action = "remove"

    if not success:
        module.fail_json(
            msg="The following variables are mandatory for this action ("
            + action
            + ") when working with environment type ("
            + environment
            + ")",
            missing=missing_params,
            changed=False,
        )


def get__protection_source_registration__status(module, self):
    """
    # => Determine if the Endpoint is presently registered to the Cohesity Cluster
    # => and if so, then return the Protection Source ID.
    """
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
            env_types = ["Physical", "GenericNas", "SQL"]
            if self["environment"] in env_types:
                for node in source["nodes"]:
                    if node["protectionSource"]["name"] == self["endpoint"]:
                        return node["protectionSource"]["id"]
            else:
                for node in source:
                    if (
                        node["registrationInfo"]["accessInfo"]["endpoint"]
                        == self["endpoint"]
                    ):
                        return node["protectionSource"]["id"]

        return False
    except urllib_error.URLError as e:
        # => Capture and report any error messages.
        raise__cohesity_exception__handler(e.read(), module)
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def refresh_source(module, self):
    """
    Function to register Sql Source.
    """
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = self["token"]
    try:
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
            "user-agent": "cohesity-ansible/v1.1.0",
        }
        uri = (
            "https://"
            + server
            + "/irisservices/api/v1/public/protectionSources/refresh/"
            + str(self["sourceId"])
        )
        open_url(
            url=uri,
            headers=headers,
            method="POST",
            validate_certs=validate_certs,
            timeout=module.params.get("timeout"),
        )
        results = dict(
            changed=False,
            msg="Successfully refreshed the Protection Source '%s'." % self["endpoint"],
            id=self["sourceId"],
            endpoint=module.params.get("endpoint"),
        )
        module.exit_json(**results)
    except urllib_error.URLError as e:
        # => Capture and report any error messages.
        raise__cohesity_exception__handler(e.read(), module)
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def register_sql_source(module, self):
    """
    Function to register Sql Source.
    """
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = self["token"]
    try:
        uri = (
            "https://"
            + server
            + "/irisservices/api/v1/public/protectionSources/applicationServers"
        )
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
            "user-agent": "cohesity-ansible/v1.1.0",
        }
        sql_payload = dict(
            applications=["kSQL"],
            hasPersistentAgent=True,
            protectionSourceId=self["physicalSourceId"],
        )
        data = json.dumps(sql_payload)
        if self.get("refresh", False):
            uri = (
                "https://"
                + server
                + "/irisservices/api/v1/public/protectionSources/refresh/"
                + str(self["physicalSourceId"])
            )

        response = open_url(
            url=uri,
            data=data,
            headers=headers,
            validate_certs=validate_certs,
            timeout=module.params.get("timeout"),
        )
        if self.get("refresh", False):
            return
        response = json.loads(response.read())
        return response
    except urllib_error.URLError as e:
        # => Capture and report any error messages.
        raise__cohesity_exception__handler(e.read(), module)
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


# => Register the new Endpoint as a Cohesity Protection Source.
def register_source(module, self):
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = self["token"]
    try:
        uri = (
            "https://"
            + server
            + "/irisservices/api/v1/public/protectionSources/register"
        )
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
            "user-agent": "cohesity-ansible/v1.1.0",
        }
        payload = self.copy()
        payload["environment"] = "k" + self["environment"]
        if self["environment"] == "Physical":
            payload["hostType"] = "k" + self["hostType"]
            payload["physicalType"] = "k" + self["physicalType"]
        elif self["environment"] == "VMware":
            payload["vmwareType"] = "k" + self["vmwareType"]
        data = json.dumps(payload)
        request_method = "POST"
        if module.params.get("update_source"):
            if not self.get("sourceId", None):
                module.fail_json(msg="Could find the source, skipping source updation!")
            request_method = "PATCH"
            uri = (
                "https://"
                + server
                + "/irisservices/api/v1/public/protectionSources/"
                + str(self["sourceId"])
            )
        response = open_url(
            url=uri,
            method=request_method,
            data=data,
            headers=headers,
            validate_certs=validate_certs,
            timeout=module.params.get("timeout"),
        )

        response = json.loads(response.read())
        # Incase of source update, no response is returned.
        if module.params.get("update_source"):
            response = response["nodes"][0]["protectionSource"]
        # => This switcher will allow us to return a standardized output
        # => for all Protection Sources.
        if self["environment"] == "Physical":
            response = dict(ProtectionSource=response["physicalProtectionSource"])
        elif self["environment"] == "VMware":
            response = dict(ProtectionSource=response["vmWareProtectionSource"])
        elif self["environment"] == "GenericNas":
            response = dict(ProtectionSource=response["nasProtectionSource"])
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
            endpoint=dict(type="str", required=True),
            # => Currently, the only supported environments types are list in the choices
            # => For future enhancements, the below list should be consulted.
            # => 'SQL', 'View', 'Puppeteer', 'Pure', 'Netapp', 'HyperV', 'Acropolis', 'Azure'
            environment=dict(
                choices=["VMware", "Physical", "SQL", "GenericNas"], default="Physical"
            ),
            host_type=dict(choices=["Linux", "Windows", "Aix"], default="Linux"),
            physical_type=dict(choices=["Host", "WindowsCluster"], default="Host"),
            force_register=dict(default=False, type="bool"),
            vmware_type=dict(
                choices=[
                    "VCenter",
                    "Folder",
                    "Datacenter",
                    "ComputeResource",
                    "ClusterComputeResource",
                    "ResourcePool",
                    "Datastore",
                    "HostSystem",
                    "VirtualMachine",
                    "VirtualApp",
                    "StandaloneHost",
                    "StoragePod",
                    "Network",
                    "DistributedVirtualPortgroup",
                    "TagCategory",
                    "Tag",
                ],
                default="VCenter",
            ),
            source_username=dict(type="str", default=""),
            source_password=dict(type="str", no_log=True, default=""),
            nas_protocol=dict(choices=["NFS", "SMB"], default="NFS"),
            nas_username=dict(type="str", default=""),
            nas_password=dict(type="str", no_log=True, default=""),
            nas_type=dict(type="str", default="Host"),
            refresh=dict(type="bool", default=False),
            skip_validation=dict(type="bool", default=False),
            timeout=dict(type="int", default=120),
            update_source=dict(type="bool", default=False),
        )
    )

    # => Create a new module object
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    results = dict(
        changed=False,
        msg="Attempting to manage Protection Source",
        state=module.params.get("state"),
    )

    prot_sources = dict(
        token=get__cohesity_auth__token(module),
        endpoint=module.params.get("endpoint"),
        environment=module.params.get("environment"),
    )
    is_sql = False
    is_physical_source = False
    if module.params.get("environment") == "SQL":
        is_sql = True
        prot_sources["environment"] = "Physical"
    current_status = get__protection_source_registration__status(module, prot_sources)
    if current_status and is_sql:
        prot_sources["physicalSourceId"] = current_status
        is_physical_source = True
        prot_sources["environment"] = "SQL"
        current_status = get__protection_source_registration__status(
            module, prot_sources
        )

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
                status = check_source_reachability(module.params.get("endpoint"))
                if not status:
                    if status is None:
                        check_mode_results[
                            "msg"
                        ] += "Please ensure cohesity agent is installed in the source and port 50051 is open"
                    else:
                        check_mode_results[
                            "msg"
                        ] += "Source '%s' is not reachable" % module.params.get(
                            "endpoint"
                        )
                check_mode_results["id"] = current_status
        else:
            if current_status:
                check_mode_results[
                    "msg"
                ] = "Check Mode: Cohesity Protection Source is currently registered. This action would unregister the Protection Source."
                check_mode_results["id"] = current_status
            else:
                check_mode_results[
                    "msg"
                ] = "Check Mode: Cohesity Protection Source is not currently registered.  No changes."
        if check_mode_results.get("status", True):
            module.exit_json(**check_mode_results)
        else:
            module.fail_json(**check_mode_results)

    elif module.params.get("state") == "present":
        check__mandatory__params(module)
        # Incase of SQL source, register the source as physical source primarily and
        # register the Mssql using physical sourceId.
        if (prot_sources["environment"] == "Physical") or (
            is_sql and not is_physical_source
        ):
            prot_sources["hostType"] = module.params.get("host_type")
            prot_sources["physicalType"] = module.params.get("physical_type")
        if prot_sources["environment"] == "VMware":
            prot_sources["username"] = module.params.get("source_username")
            prot_sources["password"] = module.params.get("source_password")
            prot_sources["vmwareType"] = module.params.get("vmware_type")
        if prot_sources["environment"] == "GenericNas":
            prot_sources["nasMountCredentials"] = dict()
            if module.params.get("nas_protocol") == "NFS":
                prot_sources["nasMountCredentials"]["nasProtocol"] = "kNfs3"
            elif module.params.get("nas_protocol") == "SMB":
                prot_sources["nasMountCredentials"]["nasProtocol"] = "kCifs1"
                if "\\" in ["nas_username"]:
                    user_details = module.params.get("nas_username").split("\\")
                    prot_sources["nasMountCredentials"]["username"] = user_details[1]
                    prot_sources["nasMountCredentials"]["domain"] = user_details[0]
                else:
                    prot_sources["nasMountCredentials"]["username"] = module.params.get(
                        "nas_username"
                    )
                prot_sources["nasMountCredentials"]["password"] = module.params.get(
                    "nas_password"
                )
            prot_sources["nasMountCredentials"]["nasType"] = "k" + module.params.get(
                "nas_type"
            )
            prot_sources["nasMountCredentials"]["skipValidation"] = module.params.get(
                "skip_validation"
            )
        prot_sources["forceRegister"] = module.params.get("force_register")
        results["changed"] = True
        results["source_vars"] = prot_sources

        if current_status:
            if module.params.get("update_source"):
                results = dict(
                    changed=False,
                    msg="The Protection Source for this host is already registered",
                    id=current_status,
                    endpoint=module.params.get("endpoint"),
                )
            elif module.params.get("refresh"):
                prot_sources["sourceId"] = current_status
                refresh_source(module, prot_sources)
        else:
            prot_sources["sourceId"] = current_status
            if not is_sql or not is_physical_source:
                response = register_source(module, prot_sources)
                time.sleep(SLEEP_TIME)
                current_status = get__protection_source_registration__status(
                    module, prot_sources
                )
                if not current_status:
                    module.fail_json(
                        msg="Failed to register %s source" % prot_sources["environment"]
                    )
                prot_sources["physicalSourceId"] = current_status
                prot_sources["sourceId"] = current_status

            # Register the physical source as SQL source.
            if is_sql and prot_sources.get("physicalSourceId", None):
                if (
                    is_physical_source
                    and current_status
                    and module.params.get("update_source")
                ):
                    prot_sources["refresh"] = True
                response = register_sql_source(module, prot_sources)
            msg = "Registration of Cohesity Protection Source Complete"
            if current_status and module.params.get("update_source"):
                msg = "Updation of Cohesity Protection Source Complete"
            results = dict(
                changed=True,
                msg=msg,
            )

    elif module.params.get("state") == "absent":
        if current_status:
            prot_sources["id"] = current_status
            prot_sources["timeout"] = module.params.get("timeout")
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
