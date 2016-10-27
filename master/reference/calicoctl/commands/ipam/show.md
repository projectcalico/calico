---
title: calicoctl ipam
---

This section describes the `calicoctl ipam show` command.

Read the [calicoctl Overview]({{site.baseurl}}/{{page.version}}/reference/calicoctl/) for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl ipam show' command

Run `calicoctl ipam show --help` to display the following help menu for the
calicoctl ipam show command.

```
Usage:
  calicoctl ipam show --ip=<IP>

Options:
  -h --help      Show this screen.
     --ip=<IP>   IP address

Description:
  The ipam show command prints information about a given IP address, such as special
  attributes defined for the IP or whether the IP has been reserved by a user of
  the Calico IP Address Manager.
```

### Examples

```
# IP is not assigned to an endpoint
$ calicoctl ipam show --ip=192.168.1.2
IP 192.168.1.2 is not currently assigned

# Basic Docker container has the assigned IP
$ calicoctl ipam show --ip=192.168.1.1
No attributes defined for 192.168.1.1
```
