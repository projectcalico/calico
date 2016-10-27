---
title: calicoctl version
---

This sections describes the `calicoctl version` command.

Read the [calicoctl Overview]({{site.baseurl}}/{{page.version}}/reference/calicoctl/) 
for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl version' commands

Run `calicoctl version --help` to display the following help menu for the 
calicoctl version commands.

```
Usage:
  calicoctl version

Options:
  -h --help   Show this screen.

Description:
  Display the version of calicoctl.
```

### Examples:

```
$ calicoctl version
0.8.0
```

## See also
-  [Resources]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/) for details on all valid resources, including file format
   and schema
-  [Policy]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/policy) for details on the Calico selector-based policy model
-  [calicoctl configuration]({{site.baseurl}}/{{page.version}}/reference/calicoctl/setup/config) for details on configuring `calicoctl` to access
   the Calico datastore.
