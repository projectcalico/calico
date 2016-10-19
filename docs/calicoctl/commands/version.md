> ![warning](../images/warning.png) This document describes an alpha release of calicoctl
>
> See note at top of [calicoctl guide](../README.md) main page.

# User reference for 'calicoctl version' commands

This sections describes the `calicoctl version` commands.

This command prints the version of `calicoctl` in use.

Read the [calicoctl command line interface user reference](../calicoctl.md) 
for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl version' commands

Run `calicoctl version --help` to display the following help menu for the 
calicoctl version commands.

```
Usage:
  calicoctl version

Description:
  Display the version of calicoctl
```

## calicoctl version commands


### calicoctl version

Print the version of `calicoctl` in use.

This command is specific to the `calicoctl` being run on a given machine.

Command syntax:

```
calicoctl version

```

Examples:

```
$ calicoctl version
Version:      v0.0.1-alpha
Build date:   2016-09-13T23:26:03+0000
Git commit:   ffa65e3
```
[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/libcalico-go/docs/calicoctl/commands/version.md?pixel)](https://github.com/igrigorik/ga-beacon)
