# (c) 2018, Cohesity Inc
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.


class ModuleDocFragment(object):

    # Core Cohesity Options documentation fragment
    DOCUMENTATION = """
options:
  validate_certs:
    aliases:
      - cohesity_validate_certs
    default: true
    description:
      - "Switch determines if SSL Validation should be enabled."
    type: bool
requirements:
  - python >= 3.6
  - cohesity_management_sdk >= 1.6.0

notes:
  - Currently, the Ansible Module requires Full Cluster Administrator access.
"""
