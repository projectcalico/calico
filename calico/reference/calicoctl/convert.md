---
title: calicoctl convert
description: Command to convert contents of policy.yaml to v3 policy.
canonical_url: '/reference/calicoctl/convert'
---

This sections describes the `calicoctl convert` command.

Read the [calicoctl command line interface user reference]({{ site.baseurl }}/reference/calicoctl/overview)
for a full list of calicoctl commands.

> **Note**: The available actions for a specific resource type may be
> limited based on the datastore used for {{site.prodname}} (etcdv3 / Kubernetes API).
> Please refer to the
> [Resources section]({{ site.baseurl }}/reference/resources/overview)
> for details about each resource type.
{: .alert .alert-info}

## Displaying the help text for 'calicoctl convert' command

Run `calicoctl convert --help` to display the following help menu for the
command.

```
Usage:
  calicoctl convert --filename=<FILENAME>
                [--output=<OUTPUT>] [--ignore-validation]

Examples:
  # Convert the contents of policy.yaml to a Calico v3 policy.
  calicoctl convert -f ./policy.yaml -o yaml

  # Convert a policy based on the JSON passed into stdin.
  cat policy.json | calicoctl convert -f -

Options:
  -h --help                     Show this screen.
  -f --filename=<FILENAME>      Filename to use to create the resource. If set to
                                "-" loads from stdin.
  -o --output=<OUTPUT FORMAT>   Output format. One of: yaml or json.
                                [Default: yaml]
  --ignore-validation           Skip validation on the converted manifest.

Description:
  Convert config files from Calico v1 or Kubernetes to Calico v3 API versions. Both YAML and JSON formats are accepted.

  The default output will be printed to stdout in YAML format.
```
{: .no-select-button}

> **Note:** Currently the only Kubernetes API resource supported for conversion is NetworkPolicy.
{: .alert .alert-info}

### Examples

1. Convert a set of resources (of mixed type) from Calico v1 or Kubernetes to Calico v3 APIs using the data in resources.yaml.

   ```bash
   calicoctl convert -f multi-resource-v1.yaml -o yaml > multi-resource-v3.yaml
   ```
   > **Tip**: By default convert command outputs the converted resources to stdout, but it can be redirected to a file.
   {: .alert .alert-success}

1. Convert a policy based on the JSON passed into stdin.

   ```bash
   cat policy.json | calicoctl convert -f -
   ```
   Result will be printed to stdout.

### Options

```
-f --filename=<FILENAME>      Filename to use to convert the resource.  If set to
                              "-" loads from stdin.
-o --output=<OUTPUT FORMAT>   Output format. One of: yaml or json.
                              [Default: yaml]
--ignore-validation           Skip validation on the converted manifest.
```
{: .no-select-button}

## See also

-  [Installing calicoctl]({{ site.baseurl }}/maintenance/clis/calicoctl/install)
-  [Resources]({{ site.baseurl }}/reference/resources/overview) for details on all valid resources, including file format
   and schema
-  [calicoctl get]({{ site.baseurl }}/reference/calicoctl/get) for details on `calicoctl get` command to get the resources.
