---
title: calicoctl node checksystem
---

This section describes the `calicoctl node checksystem` command.

Read the [calicoctl Overview]({{site.baseurl}}/{{page.version}}/reference/calicoctl) 
for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl checksystem' command

Run `calicoctl node checksystem --help` to display the following help menu for the
calicoctl checksystem command.

```
Usage: 
  calicoctl node checksystem

Options:
  -h --help                 Show this screen.

Description:
  Check the compatibility of this compute host to run a Calico node instance.
```

### Examples:

```
$ calicoctl checksystem
WARNING: Unable to detect the xt_set module. Load with `modprobe xt_set`
WARNING: Unable to detect the ipip module. Load with `modprobe ipip`
```

### See also
-  [Resources]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/) for details on all valid resources, including file format
   and schema
-  [Policy]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/policy) for details on the Calico selector-based policy model
-  [calicoctl configuration]({{site.baseurl}}/{{page.version}}/reference/calicoctl/setup/config) for details on configuring `calicoctl` to access
   the Calico datastore.
