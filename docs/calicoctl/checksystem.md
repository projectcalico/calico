<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.19.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# User reference for 'calicoctl checksystem' commands

This section describes the `calicoctl checksystem` commands.

The `calicoctl checksystem` command allows users to check for 
incompatibilities between Calico and the host system.

Read the [calicoctl command line interface user reference](../calicoctl.md) for a full list of calicoctl commands.

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
[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/calicoctl/checksystem.md?pixel)](https://github.com/igrigorik/ga-beacon)
