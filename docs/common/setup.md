# Setup

[Go back to Documentation home page ](../README.md)

## Steps to install

* Make sure that the [prerequisites](pre-requisites.md) are installed.
* Install the Cohesity Ansible Collection on the Ansible Control Machine using `ansible-galaxy` on the command line:
  ```
  ansible-galaxy collection install cohesity.dataprotect
  ```
* All set! You can now reference the `cohesity.dataprotect` collection in your plays directly, like this:
  ```yaml
  collections:
      - cohesity.dataprotect
  ```
