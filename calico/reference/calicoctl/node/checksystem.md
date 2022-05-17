---
title: calicoctl node checksystem
description: Command to check compatibility of host to run a Calico node instance.
canonical_url: '/reference/calicoctl/node/checksystem'
---

This section describes the `calicoctl node checksystem` command.

Read the [calicoctl Overview]({{ site.baseurl }}/reference/calicoctl/overview)
for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl node checksystem' command

Run `calicoctl node checksystem --help` to display the following help menu for the
command.

```
Usage:
  calicoctl node checksystem [--kernel-config=<kernel-config>]

Options:
  -h --help                             Show this screen.
  -f --kernel-config=<kernel-config>    Override the Kernel config file location.
                                        Expected format is plain text.
                                        default search locations:
                                          "/usr/src/linux/.config",
                                          "/boot/config-kernelVersion,
                                          "/usr/src/linux-kernelVersion/.config",
                                          "/usr/src/linux-headers-kernelVersion/.config",
                                          "/lib/modules/kernelVersion/build/.config"

Description:
  Check the compatibility of this compute host to run a Calico node instance.
```
{: .no-select-button}

### Procedure

These are the steps that `calicoctl` takes in order to pinpoint what modules are available in your system.

1. `calicoctl` checks the kernel version.
2. By executing `lsmod` it tries to find out what modules are enabled.
3. Modules without a match in step 2 will be checked against `/lib/modules/<YOUR_KERNEL_VERSION>/modules.dep` file.
4. Modules without a match in step 2 & 3 will be checked against `/lib/modules/<YOUR_KERNEL_VERSION>/modules.builtin` file.
5. Modules without a match in previous steps will be tested against `kernelconfig` file `/usr/src/linux/.config`.
6. Any remaining module will be tested against loaded iptables modules in `/proc/net/ip_tables_matches`.

### Examples

```bash
calicoctl node checksystem
```

An example response follows.

```
xt_conntrack                                            OK
xt_u32                                                  OK
WARNING: Unable to detect the xt_set module. Load with `modprobe xt_set`
WARNING: Unable to detect the ipip module. Load with `modprobe ipip`
```
{: .no-select-button}

It is possible to override the `kernel-config` file using `--kernel-config` argument. In this case `calicoctl` will try to resolve the modules against the provided file and skip the default locations.

```bash
calicoctl node checksystem --kernel-config /root/MYKERNELFILE
```
