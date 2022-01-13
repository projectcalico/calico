---
title: calicoctl ipam check
description: Command to check IPAM status
canonical_url: '/reference/calicoctl/ipam/check'
---

This section describes the `calicoctl ipam check` command.

Read the [calicoctl overview]({{ site.baseurl }}/reference/calicoctl/overview) for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl ipam check' command

Run `calicoctl ipam check --help` to display the following help menu for the command.

```
Usage:
  calicoctl ipam check [--config=<CONFIG>] [--show-all-ips] [--show-problem-ips] [-o <FILE>]

Options:
  -h --help                 Show this screen.
  -o --output=<FILE>        Path to output report file.
     --show-all-ips         Print all IPs that are checked.
     --show-problem-ips     Print all IPs that are leaked or not allocated properly.
  -c --config=<CONFIG>      Path to the file containing connection configuration in
                            YAML or JSON format.
                            [default: /etc/calico/calicoctl.cfg]

Description:
  The ipam check command checks the integrity of the IPAM datastructures against Kubernetes.
```
{: .no-select-button}

### Examples

Example workflow for checking consistency and releasing leaked addresses.

**Lock the data store**

```bash
calicoctl datastore migrate lock
```

> **Note:** Once the data store is locked, new pods will not be able to be launched until the data store is unlocked.
{: .alert .alert-info}

**Generate a report using the check command**

```bash
calicoctl ipam check -o report.json
```

**Release any unnecessary addresses**

```bash
calicoctl ipam release --from-report report.json
```

**Unlock the data store**

```bash
calicoctl datastore migrate unlock
```

## See also

-  [Installing calicoctl]({{ site.baseurl }}/maintenance/clis/calicoctl/install)
