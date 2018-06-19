---
title: calicoctl version
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v3.1/reference/calicoctl/commands/version'
---

This sections describes the `calicoctl version` command.

Read the [calicoctl Overview]({{site.baseurl}}/{{page.version}}/reference/calicoctl/) 
for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl version' commands

Run `calicoctl version --help` to display the following help menu for the 
commands.

```
Usage:
  calicoctl version [--config=<CONFIG>]

Options:
  -h --help             Show this screen.
  -c --config=<CONFIG>  Path to the file containing connection configuration in
                        YAML or JSON format.
                        [default: /etc/calico/calicoctl.cfg]

Description:
  Display the version of calicoctl.
```

### Examples:

```
$ calicoctl version
Client Version:    v1.4.0
Build date:        2017-07-21T19:33:04+0000
Git commit:        d2babb6
Cluster Version:   v2.4.0
Cluster Type:      KDD,hosted
```

## See also

-  [calicoctl configuration]({{site.baseurl}}/{{page.version}}/reference/calicoctl/setup) for details on configuring `calicoctl` to access
   the Calico datastore.
