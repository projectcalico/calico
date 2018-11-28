---
title: calicoctl ipam
canonical_url: 'https://docs.projectcalico.org/v3.3/reference/calicoctl/commands/ipam/show'
---

This section describes the `calicoctl ipam show` command.

Read the [calicoctl Overview]({{site.baseurl}}/{{page.version}}/reference/calicoctl/) for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl ipam show' command

Run `calicoctl ipam show --help` to display the following help menu for the
command.

```
Usage:
  calicoctl ipam show --ip=<IP> [--config=<CONFIG>]

Options:
  -h --help             Show this screen.
     --ip=<IP>          IP address to show.
-c --config=<CONFIG>    Path to the file containing connection
                        configuration in YAML or JSON format.
                        [default: /etc/calico/calicoctl.cfg]

Description:
  The ipam show command prints information about a given IP address, such as
  special attributes defined for the IP or whether the IP has been reserved by
  a user of the Calico IP Address Manager.
```
{: .no-select-button}

### Examples

1. Print the information associated with an IP address.

   ```bash
   calicoctl ipam show --ip=192.168.1.2
   ```

   The following results indicate that the IP is not assigned to an endpoint.

   ```bash
   Results
   IP 192.168.1.2 is not currently assigned
   ```
   {: .no-select-button}

1. Print the information associated with a different IP address.

   ```bash
   calicoctl ipam show --ip=192.168.1.1
   ```

   Results show that a basic Docker container has the assigned IP.

   ```bash
   No attributes defined for 192.168.1.1
   ```
   {: .no-select-button}

### Options

```
--ip=<IP>          IP address to show.
```
{: .no-select-button}

### General options

```
-c --config=<CONFIG>       Path to the file containing connection
                           configuration in YAML or JSON format.
                           [default: /etc/calico/calicoctl.cfg]
```
{: .no-select-button}

## See also

-  [calicoctl configuration]({{site.baseurl}}/{{page.version}}/reference/calicoctl/setup) for details on configuring `calicoctl` to access
   the {{site.prodname}} datastore.
