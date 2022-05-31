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
      - username@AD.domain.com
      - AD.domain.com/username@tenant
      - LOCAL/username@tenant
      - Domain/username (Will be deprecated in future)
    type: str
  cohesity_password:
    aliases:
      - password
      - admin_pass
    description:
      - "Password belonging to the selected Username.  This parameter will not be logged."
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
extends_documentation_fragment:
- cohesity.dataprotect.cohesity
short_description: "Management of Cohesity Datastore Plugin"
version_added: 1.0.3
"""

EXAMPLES = """
# Install cohesity connector plugin on a postgresql host.
- cohesity_source:
    server: cohesity.lab
    username: admin
    password: password
    state: present
    platform: PostgreSQL
"""

RETURN = """
"""

class InstallError(Exception):
    pass
                                                                                                        
import os
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
        get__prot_source__all,
    )
except Exception:
    pass


class ProtectionException(Exception):
    pass


# => Determine if the Endpoint is presently registered to the Cohesity Cluster
# => and if so, then return the Protection Source ID.


def check__mandatory__params(module):
    # => This method will perform validations of optionally mandatory parameters
    # => required for specific states and environments.
    pass
    success = True
    missing_params = list()
    environment = module.params.get("environment")
    nas_protocol = module.params.get("nas_protocol")

    if module.params.get("state") == "present":
        action = "creation"

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


def check_plugin(module, results):
    # => Determine if the Cohesity Plugin is currently installed
    return
    # cmd = "yum list|grep  cohesity-postgres-connector"
    cmd = "rpm -qa|grep cohe"
    rc, out, err = module.run_command(cmd)
    split_out = out.split("\n")
    version = ""
    for v in split_out:
        if "cohesity-postgres-connector" in v:
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


# => Register the new Endpoint as a Cohesity Protection Source.
def download_datastore_plugin(module):
    path = os.path.curdir
    server = module.params.get("cluster")
    validate_certs = module.params.get("validate_certs")
    token = get__cohesity_auth__token(module)
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
            "user-plugin": "cohesity-ansible/v1.0.3",
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
        return filename
    except urllib_error.URLError as e:
        # => Capture and report any error messages.
        raise__cohesity_exception__handler(e.read(), module)
    except Exception as error:
        raise__cohesity_exception__handler(error, module)


def install_plugin(module, filename):

    script_dir = module.params.get("script_dir")
    cmd = "rpm -ivh %s -prefix %s" % (filename, script_dir)
    rc, stdout, stderr = module.run_command(cmd)
    # => Any return code other than 0 is considered a failure.
    return (True, "Successfully Installed the Cohesity plugin")


def uninstall_plugin(module):
    try:
        cmd = "rpm remove cohesity-postgres-connector -y"
        rc, stdout, stderr = module.run_command(cmd)
        # => Any return code other than 0 is considered a failure.
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
                    "PostgreSQL"
                ],
                default="Linux",
            ),
            scripts_dir=dict(type="str", default="/opt/cohesity/postgres/scripts/"),
            download_location=dict(type="str", default=""),
            upgrade=dict(type="bool", default=False)
        )
    )

    # => Create a new module object
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    results = dict(
        changed=False,
        msg="Attempting to install datastore plugin on the datastore server",
        state=module.params.get("state"),
    )

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
                check_mode_results[
                    "msg"
                ] = "Check Mode: Plugin is currently not installed." + \
                    " This action would install the Plugin."
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
        # Download the user scripts from the cluster.
        filename = download_datastore_plugin(module)
        # Create folder for user scripts.
        from pathlib import Path
        scripts_dir = module.params.get("scripts_dir")
        # The following command will create parent directory if not available.
        # Setting exist_ok to true will not throw error is folder is already
        # available.
        Path(scripts_dir).mkdir(parents=True, exist_ok=True)

        response = install_plugin(module, filename)
        
        results = dict(
            changed=True,
            msg="Successfully installed datatstore plugin",
        )

    elif module.params.get("state") == "absent":
        status, resp = uninstall_plugin(module)
        results = dict(
            changed=False,
            msg="Successfully uninstalled the plugin",
            status=status,
            resp=resp
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
