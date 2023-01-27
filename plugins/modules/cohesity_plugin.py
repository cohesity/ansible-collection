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
extends_documentation_fragment:
  - cohesity.dataprotect.cohesity
module: cohesity_plugin
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
      - "Username with which Ansible will connect to the Cohesity Cluster. Domain Specific credentails can be configured in following formats"
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
  download_location:
    description:
      - "Absolute path of the scripts used to store the downloaded connection plugin."
    type: str
  endpoint:
    description:
      - "Specifies the network endpoint of the Protection Source where it is reachable. It could"
      - "be an URL or hostname or an IP address of the Protection Source"
    required: true
    type: str
  netmask_bits:
    description:
      - "Applicable when the platform type is PostgreSQL and state is present."
      - "Is required to add the SapHana hosts to the cluster's global allow lists."
    type: int
  platform:
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
    default: Linux
    description:
      - "Type of the UDA source to be registered."
    type: str
  scripts_dir:
    default: /opt
    description:
      - "Absolute path of the scripts used to interact with the UDA source."
    type: str
  state:
    choices:
      - present
      - absent
    default: present
    description:
      - "Determines the state of the Protection Source"
    type: str
  upgrade:
    default: false
    description:
      - "Determines whether to upgrade the connector plugin if already installed."
    type: bool
short_description: "Management of Cohesity Datastore Plugin"
version_added: "1.0.9"
"""

EXAMPLES = """
# Install cohesity connector plugin on a postgresql host.
---
- cohesity_source:
    password: password
    platform: PostgreSQL
    server: cohesity.lab
    state: present
    username: admin
"""

RETURN = """
"""

# Builtin imports.
import os
import json

# Ansible Imports.
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url, urllib_error

from ansible_collections.cohesity.dataprotect.plugins.module_utils.cohesity_auth import (
    get__cohesity_auth__token,
)
from ansible_collections.cohesity.dataprotect.plugins.module_utils.cohesity_utilities import (
    cohesity_common_argument_spec,
    raise__cohesity_exception__handler,
    REQUEST_TIMEOUT,
)


class InstallError(Exception):
    pass


class ProtectionException(Exception):
    pass


COHESITY_POSTGRES_CONNECTOR = "cohesity-postgres-connector"


def check__mandatory__params(module):
    """
    This method will perform validations of optionally mandatory parameters
    required for specific states.
    """
    success = True
    missing_params = list()
    platform = module.params.get("platform")
    if module.params.get("state") == "present":
        action = "creation"
        if platform == "PostgreSQL" and not module.params.get("netmask_bits"):
            missing_params.append("netmask_bits")
    else:
        action = "remove"

    if not success:
        module.fail_json(
            msg="The following variables are mandatory for this action ("
            + action
            + ") when working with UDA environment platform type '%s'" % platform,
            missing=missing_params,
            changed=False,
        )


def check_plugin(module, results):
    """
    Determine if the Cohesity Plugin is currently installed in the host.
    """
    cmd = "rpm -qa|grep " + COHESITY_POSTGRES_CONNECTOR
    rc, out, err = module.run_command(cmd)
    split_out = out.split("\n")
    version = ""
    for v in split_out:
        if COHESITY_POSTGRES_CONNECTOR in v:
            version = v.split()[-2]
            break
    if version:
        # => When the plugin is installed, we should be able to return
        # => the version information
        results["version"] = version
    else:
        # => If this didn't return a Version, then we have bigger problems
        # => and probably should try to re-install or force the uninstall.
        results["version"] = "unknown"
        results["check_plugin"] = dict(stdout=out, stderr=err)
    return results


def download_datastore_plugin(module):
    """
    Download the datastore plugin from the cohesity server.
    """
    path = module.params.get("download_location") or os.getcwd()
    try:
        platform = "k" + module.params.get("platform")
        uri = (
            "https://"
            + server
            + "/irisservices/api/v1/public/physicalAgents/download?hostType=%s"
        ) % platform
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
            "user-plugin": "cohesity-ansible/v1.0.9",
        }
        response = open_url(
            url=uri,
            method="GET",
            headers=headers,
            validate_certs=validate_certs,
            timeout=REQUEST_TIMEOUT,
        )
        resp_headers = response.headers
        if "content-disposition" in resp_headers.keys():
            filename = resp_headers["content-disposition"].split("=")[1]
        else:
            filename = "cohesity-plugin-installer"
        filename = path + "/" + filename
        try:
            with open(filename, "wb") as f:
                f.write(response.read())
            os.chmod(filename, 0o755)
        except Exception as e:
            raise InstallError(e)
        finally:
            f.close()
        # Plugin installation commands will be exectued through playbooks.
        if platform == "kSapHana":
            module.exit_json(filename=filename, changed=True)
            return filename
    except urllib_error.URLError as e:
        # => Capture and report any error messages.
        raise__cohesity_exception__handler(e.read(), module)
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def update_global_allow_lists(module):
    """ "
    Function to update the cluster global allow lists.
    Required only for SapHana platform.
    : returns: None
    """
    try:
        API = uri = (
            "https://" + server + "/irisservices/api/v1/public/externalClientSubnets"
        )
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
            "user-plugin": "cohesity-ansible/v1.0.9",
        }
        response = open_url(
            url=uri,
            method="GET",
            headers=headers,
            validate_certs=validate_certs,
            timeout=REQUEST_TIMEOUT,
        )
        if response.code == 200:
            resp = json.loads(response.read())

        endpoint = module.params.get("endpoint")
        mask_bits = module.params.get("netmask_bits")
        # Fetch existing subnets available in the cluster, to avoid
        # overwriting existing subnets.
        client_subnets = resp.get("clientSubnets", [])
        # Check host is already added ot the existing subnets.
        for subnet in client_subnets:
            if subnet["ip"] == endpoint:
                return
        subnet = {
            "ip": endpoint,
            "netmaskBits": mask_bits,
            "nfsAccess": "kReadWrite",
            "s3Access": "kReadWrite",
            "smbAccess": "kReadWrite",
        }
        client_subnets.append(subnet)
        body = {"clientSubnets": client_subnets}
        response = open_url(
            url=uri,
            method="PUT",
            data=json.dumps(body),
            headers=headers,
            validate_certs=validate_certs,
            timeout=REQUEST_TIMEOUT,
        )
    except urllib_error.URLError as e:
        # => Capture and report any error messages.
        module.fail_json(
            msg="Error while updating global subnets, err %s" % str(e.read())
        )
    except Exception as e:
        module.fail_json(msg="Error while updating global subnets, err %s" % str(e))


def upgrade_plugin(module):
    # TODO: Add support for upgrade.
    return


def install_plugin(module, filename):
    """
    Function to install the cohesity datastore plugin on the hosts.
    """
    try:
        scripts_dir = module.params.get("scripts_dir")
        platform = module.params.get("platform")
        # The scripts will be stored under following location
        # <scripts_dir>/cohesity/postgres/scripts/.
        if platform in ["Postgres"]:
            cmd = "rpm -ivh %s --prefix %s" % (filename, scripts_dir)
        rc, stdout, stderr = module.run_command(cmd)
        # => Any return code other than 0 is considered a failure.
        if rc:
            module.fail_json(msg="Error while installing connector plugin %s" % stderr)
        return (True, "Successfully Installed the Cohesity plugin")
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def uninstall_plugin(module):
    try:
        if module.params.get("platform") == "PostgreSQL":
            cmd = "rpm remove " + COHESITY_POSTGRES_CONNECTOR + " -y"
            rc, stdout, stderr = module.run_command(cmd)
            # => Any return code other than 0 is considered a failure.
            if rc:
                return (
                    False,
                    "Failed to uninstall the Cohesity plugin, err msg '%s'" % stderr,
                )
            return (True, "Successfully Uninstalled the Cohesity plugin")
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def main():
    # => Load the default arguments including those specific to the Cohesity Plugin.
    argument_spec = cohesity_common_argument_spec()
    argument_spec.update(
        dict(
            state=dict(choices=["present", "absent"], default="present"),
            platform=dict(
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
                ],
                default="Linux",
            ),
            endpoint=dict(type="str", required=True),
            netmask_bits=dict(type="int"),
            scripts_dir=dict(type="str", default="/opt"),
            download_location=dict(type="str"),
            upgrade=dict(type="bool", default=False),
        )
    )

    # => Create a new module object
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    results = dict(
        changed=False,
        msg="Attempting to install datastore plugin on the datastore server",
        state=module.params.get("state"),
    )
    global server, validate_certs, token
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = get__cohesity_auth__token(module)
    result = check_plugin(module, results)
    if module.check_mode:
        check_mode_results = dict(
            changed=False,
            msg="Check Mode: Plugin is Currently not Installed",
            version="",
        )
        if module.params.get("state") == "present":
            if result["version"]:
                check_mode_results[
                    "msg"
                ] = "Check Mode: Plugin is currently installed.  No changes"
            else:
                check_mode_results["msg"] = (
                    "Check Mode: Plugin is currently not installed."
                    + " This action would install the Plugin."
                )
                check_mode_results["version"] = result["version"]
        else:
            if result["version"]:
                check_mode_results[
                    "msg"
                ] = "Check Mode: Plugin is currently installed.  This action would uninstall the Plugin."
                check_mode_results["version"] = result["version"]
            else:
                check_mode_results[
                    "msg"
                ] = "Check Mode: Plugin is currently not installed.  No changes."
        module.exit_json(**check_mode_results)

    elif module.params.get("state") == "present":
        check__mandatory__params(module)

        # Endpoint should be added to global allowlists for SapHana platform.
        if module.params.get("platform") == "SapHana":
            update_global_allow_lists(module)

        # Download the user scripts from the cluster.
        filename = download_datastore_plugin(module)
        install_plugin(module, filename)
        results = dict(
            changed=True,
            msg="Successfully installed datatstore plugin",
        )

    elif module.params.get("state") == "absent":
        status, resp = uninstall_plugin(module)
        results = dict(
            changed=status,
            msg=resp,
            status=status,
            resp=resp,
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
