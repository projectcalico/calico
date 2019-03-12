---
title: calicoctl ipam
canonical_url: 'https://docs.projectcalico.org/v3.6/reference/calicoctl/commands/ipam/release'
---

This section describes the `calicoctl ipam release` command.

Read the [calicoctl Overview]({{site.baseurl}}/{{page.version}}/reference/calicoctl/) for a full list of calicoctl commands.

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

### Examples

```
$ calicoctl ipam release --ip=192.168.1.2
```

### General options

```
-c --config=<CONFIG>      Path to the file containing connection
                          configuration in YAML or JSON format.
                          [default: /etc/calico/calicoctl.cfg]
```

## See also

-  [calicoctl configuration]({{site.baseurl}}/{{page.version}}/reference/calicoctl/setup) for details on configuring `calicoctl` to access
   the Calico datastore.
