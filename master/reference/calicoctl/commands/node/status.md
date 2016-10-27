---
title: calicoctl node status
---

This sections describes the `calicoctl node status` commands.

Read the [calicoctl Overview]({{site.baseurl}}/{{page.version}}/reference/calicoctl)
for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl node status' commands

Run `calicoctl node status --help` to display the following help menu for the
calicoctl status command.

```
Usage:
  calicoctl node status

Options:
  -h --help                 Show this screen.

Description:
  Check the status of the Calico node instance.  This incudes the status and uptime
  of the node instance, and BGP peering states.
```

### Examples

```
$ calicoctl status
calico-node container is running. Status: Up 5 seconds

IPv4 BGP status
IP: 172.17.8.100    AS Number: 64511 (inherited)
+--------------+-------------------+-------+----------+-------------+
| Peer address |     Peer type     | State |  Since   |     Info    |
+--------------+-------------------+-------+----------+-------------+
| 172.17.8.101 | node-to-node mesh |   up  | 17:54:00 | Established |
+--------------+-------------------+-------+----------+-------------+

IPv6 BGP status
No IPv6 address configured.
```

## See also
-  [Resources]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/) for details on all valid resources, including file format
   and schema
-  [Policy]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/policy) for details on the Calico selector-based policy model
-  [calicoctl configuration]({{site.baseurl}}/{{page.version}}/reference/calicoctl/setup/config) for details on configuring `calicoctl` to access
   the Calico datastore.
