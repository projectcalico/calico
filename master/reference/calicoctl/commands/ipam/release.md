---
title: calicoctl ipam
---

This section describes the `calicoctl ipam` commands.

This command allows an interface into Calico's IP address management to release
IP addresses from endpoints and view additional information about assigned IPs.

Read the [calicoctl Overview]({{site.baseurl}}/{{page.version}}/reference/calicoctl) for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl ipam' commands

Run `calicoctl ipam --help` to display the following help menu for the
calicoctl ipam commands.

```
Usage:
  calicoctl ipam release --ip=<IP>

Options:
  -h --help      Show this screen.
     --ip=<IP>   IP address

Description:
  The ipam release command releases an IP address from the Calico IP Address
  Manager that was been previously assigned to an endpoint.  When an IP address 
  is released, it becomes available for assignment to any endpoint.

  Note that this does not remove the IP from any existing endpoints that may be
  using it, so only use this command to clean up addresses from endpoints that 
  were not cleanly removed from Calico.
```

#### Examples

```
$ calicoctl ipam release --ip=192.168.1.2
```
