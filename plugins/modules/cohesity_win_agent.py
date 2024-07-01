#!/usr/bin/python
# Copyright (c) 2022 Cohesity Inc


from __future__ import absolute_import, division, print_function

__metaclass__ = type

# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)


DOCUMENTATION = """
module: cohesity_win_agent
short_description: Management of Cohesity Physical Windows Agent
description:
    - Ansible Module used to deploy or remove the Cohesity Physical Agent from supported Windows Machines.
    - When executed in a playbook, the Cohesity Agent installation will be validated and the appropriate
    - state action will be applied.  The most recent version of the Cohesity Agent will be automatically
    - downloaded to the host.
version_added: 1.3.0
author: "Naveena (@naveena-maplelabs)"
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
    description:
      - Determines if the agent should be C(present) or C(absent) from the host
    choices:
      - present
      - absent
    default: 'present'
  service_user:
    description:
      - Username with which Cohesity Agent will be installed
  service_password:
    description:
      - Password belonging to the selected Username.  This parameter will not be logged.
  install_type:
    description:
      - Installation type for the Cohesity Agent on Windows
    choices:
      - volcbt
      - fscbt
      - allcbt
      - onlyagent
    default: 'volcbt'
  preservesettings:
    description:
      - Should the settings be retained when uninstalling the Cohesity Agent
    type: bool
    default: 'no'

extends_documentation_fragment:
- cohesity.dataprotect.cohesity
"""

EXAMPLES = """
# Install the current version of the agent on Windows
- cohesity_win_agent:
    server: cohesity.lab
    username: admin
    password: password
    state: present

# Install the current version of the agent with custom Service Username/Password
- cohesity_win_agent:
    server: cohesity.lab
    username: admin
    password: password
    state: present
    service_user: cagent
    service_password: cagent

# Install the current version of the agent using FileSystem ChangeBlockTracker
- cohesity_win_agent:
    server: cohesity.lab
    username: admin
    password: password
    state: present
    install_type: fscbt
"""

RETURN = """
"""
