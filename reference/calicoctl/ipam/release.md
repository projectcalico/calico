---
title: calicoctl ipam
canonical_url: '/reference/calicoctl/ipam/release'
---

This section describes the `calicoctl ipam release` command.

Read the [calicoctl overview]({{ site.baseurl }}/reference/calicoctl/) for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl ipam release' command

Run `calicoctl ipam release --help` to display the following help menu for the
command.

```
Usage:
  calicoctl ipam release --ip=<IP> [--config=<CONFIG>]

Options:
  -h --help             Show this screen.
     --ip=<IP>          IP address to release.
  -c --config=<CONFIG>  Path to the file containing connection
                          configuration in YAML or JSON format.
                          [default: /etc/calico/calicoctl.cfg]

Description:
  The ipam release command releases an IP address from the Calico IP Address
  Manager that was been previously assigned to an endpoint.  When an IP address
  is released, it becomes available for assignment to any endpoint.

  Note that this does not remove the IP from any existing endpoints that may be
  using it, so only use this command to clean up addresses from endpoints that
  were not cleanly removed from Calico.
```
{: .no-select-button}

### Examples

```
calicoctl ipam release --ip=192.168.1.2
```

### General options

```
-c --config=<CONFIG>      Path to the file containing connection
                          configuration in YAML or JSON format.
                          [default: /etc/calico/calicoctl.cfg]
```
{: .no-select-button}

## See also

-  [Installing calicoctl]({{ site.baseurl }}/getting-started/calicoctl/install)
