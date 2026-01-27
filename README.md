<!--
  Title: Cohesity Ansible Collection
  Description: This project provides a Ansible Collection for interacting with the Cohesity DataPlatform
  Author: Cohesity Inc
  -->
# Ansible Collection - cohesity.dataprotect

![](https://github.com/cohesity/ansible-collection/blob/main/docs/assets/images/cohesity_ansible.png)

## Overview
[![License: GNU General Public License v3.0](https://img.shields.io/badge/LICENSE-GPL--v3.0-blue)](https://github.com/cohesity/ansible-collection/blob/main/LICENSE)

This project provides an Ansible Collection for interacting with the [Cohesity DataPlatform](https://www.cohesity.com/products/data-platform).

This Ansible Collection can be used on Windows, Linux or MacOS leveraging Python.

It includes modules, tasks, and example plays useful for automating common tasks and orchestrating workflows in your environment.

This Ansible Collection leverages Cohesity REST API to interact with the Cohesity Cluster.

# Installation
```bash
ansible-galaxy collection install cohesity.dataprotect
```
To use this collection, add the following to the top of your playbook:
```
collections:
  - cohesity.dataprotect
```
# Requirements
- ansible-core version >= 2.16.3
- requests >= 2.31.0
- python version >= '3.6'
- pywinrm
- cohesity_management_sdk == 1.10.1

To install the requirements, run **pip install -r [requirement.txt](https://github.com/cohesity/ansible-collection/blob/main/requirements.txt)**

## Table of contents

 - [Getting Started](https://github.com/cohesity/ansible-collection/blob/main/README.md#get-started)
 - [More samples playbooks](https://github.com/cohesity/ansible-collection/blob/main/README.md#examples)
 - [How can you contribute](https://github.com/cohesity/ansible-collection/blob/main/README.md#contribute)
 - [Suggestions and Feedback](https://github.com/cohesity/ansible-collection/blob/main/README.md#suggest)
 - [Disclaimer](#disclaimer)


## <a name="get-started"></a> Let's get started

* [Documentation for Cohesity Ansible Collection](https://github.com/cohesity/ansible-collection/tree/main/docs).

## <a name="examples"></a> Some samples to get you going :bulb:

* Refer [`playbooks`](https://github.com/cohesity/ansible-collection/tree/main/playbooks) folder to find more examples.

## <a name="contribute"></a> Contribute

* [Refer our contribution guideline](https://github.com/cohesity/ansible-collection/tree/main/CONTRIBUTING.md).

## <a name="suggest"></a> Suggestions and Feedback

We would love to hear from you. Please send your suggestions and feedback to: [support@cohesity.com](mailto:support@cohesity.com)

## Code of Conduct
This collection follows the [Ansible project's Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html).

## License

GNU General Public License v3.0.

## <a name ="disclaimer"></a> Disclaimer

The scripts, recipes, and integrations provided here are community-contributed or best-effort solutions from Cohesity engineering and ecosystem partners. These resources are not officially supported by Cohesity Support or Field teams.
For production-grade use or enterprise implementation support, please contact Cohesity Professional Services or your account team.
