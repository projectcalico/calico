---
title: calicoctl ipam
canonical_url: '/reference/calicoctl/ipam/show'
---

This section describes the `calicoctl ipam show` command.

Read the [calicoctl Overview]({{site.baseurl}}/{{page.version}}/reference/calicoctl/) for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl ipam show' command

Run `calicoctl ipam show --help` to display the following help menu for the
command.

```
Usage:
  calicoctl ipam show [--ip=<IP> | --show-blocks] [--config=<CONFIG>]

Options:
  -h --help             Show this screen.
     --ip=<IP>          Report whether this specific IP address is in use.
     --show-blocks      Show detailed information for IP blocks as well as pools.
  -c --config=<CONFIG>  Path to the file containing connection
                        configuration in YAML or JSON format.
                        [default: /etc/calico/calicoctl.cfg]

Description:
  The ipam show command prints information about a given IP address, or about
  overall IP usage.
```
{: .no-select-button}

### Examples

1. Print the information associated with an IP address.

   ```bash
   calicoctl ipam show --ip=192.168.1.2
   ```

   The following result indicates that the IP is not assigned to an endpoint.

   ```bash
   IP 192.168.1.2 is not currently assigned
   ```
   {: .no-select-button}

1. Print the information associated with a different IP address.

   ```bash
   calicoctl ipam show --ip=10.244.118.70
   ```

   For a Kubernetes pod IP, attributes indicate the pod name and namespace:

   ```bash
   IP 10.244.118.70 is in use
   Attributes:
     pod: nano-66d4c99f8b-jm5s9
     namespace: default
     node: ip-172-16-101-160.us-west-2.compute.internal
   ```
   {: .no-select-button}

1. Print a summary of IP usage.

   ```bash
   calicoctl ipam show
   ```

   The table shows usage for each IP Pool:

   ```bash
   +----------+-------------------+------------+------------+-------------------+
   | GROUPING |       CIDR        | IPS TOTAL  | IPS IN USE |     IPS FREE      |
   +----------+-------------------+------------+------------+-------------------+
   | IP Pool  | 10.65.0.0/16      |      65536 | 5 (0%)     | 65531 (100%)      |
   | IP Pool  | fd5f:abcd:64::/48 | 1.2089e+24 | 7 (0%)     | 1.2089e+24 (100%) |
   +----------+-------------------+------------+------------+-------------------+
   ```

1. Print more detailed IP usage by blocks.

   ```bash
   calicoctl ipam show --show-blocks
   ```

   As well as the total usage per IP Pool, the table shows usage for block that has been allocated from those pools:

   ```bash
   +----------+-------------------------------------------+------------+------------+-------------------+
   | GROUPING |                   CIDR                    | IPS TOTAL  | IPS IN USE |     IPS FREE      |
   +----------+-------------------------------------------+------------+------------+-------------------+
   | IP Pool  | 10.65.0.0/16                              |      65536 | 5 (0%)     | 65531 (100%)      |
   | Block    | 10.65.79.0/26                             |         64 | 5 (8%)     | 59 (92%)          |
   | IP Pool  | fd5f:abcd:64::/48                         | 1.2089e+24 | 7 (0%)     | 1.2089e+24 (100%) |
   | Block    | fd5f:abcd:64:4f2c:ec1b:27b9:1989:77c0/122 |         64 | 7 (11%)    | 57 (89%)          |
   +----------+-------------------------------------------+------------+------------+-------------------+
   ```

### Options

```
--ip=<IP>          Specific IP address to show.
--show-blocks      Show detailed information for IP blocks as well as pools.
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

-  [Installing calicoctl]({{site.baseurl}}/{{page.version}}/getting-started/calicoctl/install)
