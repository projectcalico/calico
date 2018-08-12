---
title: calicoctl checksystem
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v3.1/reference/calicoctl/commands/node/checksystem'
---
This section describes the `calicoctl checksystem` commands.

The `calicoctl checksystem` command allows users to check for
incompatibilities between Calico and the host system.

Read the [calicoctl Overview]({{site.baseurl}}/{{page.version}}/reference/calicoctl) for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl checksystem' commands

Run `calicoctl checksystem --help` to display the following help menu for the
calicoctl checksystem commands.

```

Usage:
  calicoctl checksystem

Description:
  Check for incompatibilities between Calico and the host system

Options:
  --fix  DEPRECATED: checksystem no longer fixes issues that it detects
  --libnetwork  Check for the correct docker version for libnetwork deployments
```

## calicoctl checksystem commands

### calicoctl checksystem
This command allows you to verify that your host system is configured correctly
for calicoctl to manage a Calico network.  The Calico network hosts must be
configured to have specific networking modules loaded, such as iptables,
ipsets support, and IP forwarding.  Calico checks for these modules in the  
`modules.dep` and `modules.builtin` files under `/lib/modules/<kernel>/`.

Running this command will only check for incompatibilities on the host it is
run on.

Command syntax:

```
calicoctl checksystem

    --fix:  DEPRECATED - no longer fixes issues detected by checksystem
    --libnetwork  Check for the correct docker version for libnetwork deployments
```

Examples:

```
$ calicoctl checksystem
WARNING: Unable to detect the xt_set module. Load with `modprobe xt_set`
WARNING: Unable to detect the ipip module. Load with `modprobe ipip`

$ calicoctl checksystem --libnetwork

```
