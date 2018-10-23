---
title: calicoctl node status
redirect_from: latest/reference/calicoctl/commands/node/status
canonical_url: 'https://docs.projectcalico.org/v3.3/reference/calicoctl/commands/node/status'
---

This sections describes the `calicoctl node status` command.

Read the [calicoctl Overview]({{site.baseurl}}/{{page.version}}/reference/calicoctl)
for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl node status' command

Run `calicoctl node status --help` to display the following help menu for the
command.

```
Usage:
  calicoctl node status

Options:
  -h --help                 Show this screen.

Description:
  Check the status of the Calico node instance.  This incudes the status and
  uptime of the node instance, and BGP peering states.
```

### Examples

```
$ sudo calicoctl node status
Calico process is running.

IPv4 BGP status
+--------------+-------------------+-------+----------+-------------+
| PEER ADDRESS |     PEER TYPE     | STATE |  SINCE   |    INFO     |
+--------------+-------------------+-------+----------+-------------+
| 172.17.8.102 | node-to-node mesh | up    | 23:30:04 | Established |
+--------------+-------------------+-------+----------+-------------+

IPv6 BGP status
No IPv6 peers found.
```
