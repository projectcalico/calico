---
title: calicoctl node
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v3.1/reference/calicoctl/commands/node/'
---

This sections describes the `calicoctl node` commands.

The `calicoctl node` command starts the calico/node Docker image that runs the
main Calico processes such as Felix and the BIRD BGP routing daemon.  The
calico/node container is required to be running on every compute host for
Calico networking.

The `calicoctl node bgp` commands can be used to configure BGP peering for the
node.  For an overview of BGP configuration, read the
[BGP tutorial]({{site.baseurl}}/{{page.version}}/usage/configuration/bgp), which covers in more detail all available BGP
related commands, including use cases.

Read the [calicoctl Overview]({{site.baseurl}}/{{page.version}}/reference/calicoctl)
for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl node' commands

Run `calicoctl node --help` to display the following help menu for the
calicoctl node commands.

```

Usage:
  calicoctl node [--ip=<IP>] [--ip6=<IP6>] [--node-image=<DOCKER_IMAGE_NAME>]
    [--runtime=<RUNTIME>] [--as=<AS_NUM>] [--log-dir=<LOG_DIR>]
    [--detach=<DETACH>] [--no-pull]
    [(--libnetwork [--libnetwork-image=<LIBNETWORK_IMAGE_NAME>])]
  calicoctl node stop [--force]
  calicoctl node remove [--hostname=<HOSTNAME>] [--remove-endpoints]
  calicoctl node show
  calicoctl node bgp peer add <PEER_IP> as <AS_NUM>
  calicoctl node bgp peer remove <PEER_IP>
  calicoctl node bgp peer show [--ipv4 | --ipv6]

Description:
  Configure the Calico node containers as well as default BGP information
  for this node.

Options:
  --as=<AS_NUM>             The default AS number for this node.
  --detach=<DETACH>         Set "true" to run Calico service as detached,
                            "false" to run in the foreground.  When using
                            libnetwork, this may not be set to "false".
                            When using --runtime=rkt, --detach is always false.
                            [default: true]
  --force                   Forcefully stop the Calico node
  --hostname=<HOSTNAME>     The hostname from which to remove the Calico node.
  --ip=<IP>                 The local management address to use.
  --ip6=<IP6>               The local IPv6 management address to use.
  --ipv4                    Show IPv4 information only.
  --ipv6                    Show IPv6 information only.
  --libnetwork              Use the libnetwork plugin.
  --libnetwork-image=<LIBNETWORK_IMAGE_NAME>    (Deprecated) This flag will be ignored.
                            [default: calico/node-libnetwork:v0.10.0]
  --log-dir=<LOG_DIR>       The directory for logs [default: /var/log/calico]
  --no-pull                 Prevent from pulling the Calico node Docker images.
  --node-image=<DOCKER_IMAGE_NAME>    Docker image to use for Calico's per-node
                            container. [default: calico/node:v0.23.1]
  --remove-endpoints        Remove the endpoint data when deleting the node
                            from the Calico network.
  --runtime=<RUNTIME>       Specify how Calico services should be
                            launched.  When set to "docker" or "rkt", services
                            will be launched via the calico-node container,
                            whereas a value of "none" will not launch them at
                            all. [default: docker]
```

## calicoctl node commands


### calicoctl node

This command performs two actions:

1. Initialize this host for Calico by setting first-time config in etcd.
2. (Optional) Start the `calico/node` container. By default
(or via `--runtime=docker`) the `calicoctl node` does this by downloading
the `calico/node` Docker image and running it in a container.

It is required to run the `calicoctl node` command prior to configuring
endpoints to use Calico networking.  In order to run the command, the host must
be running Docker and must have access to the etcd instance for the Calico
cluster.

This command must be run as root and must be run on the specific Calico node
that you are configuring.

Command syntax:

```
calicoctl node [--ip=<IP>] [--ip6=<IP6>] [--node-image=<DOCKER_IMAGE_NAME>]
    [--runtime=<RUNTIME>] [--as=<AS_NUM>] [--log-dir=<LOG_DIR>]
    [--detach=<DETACH>] [--no-pull]
    [(--libnetwork [--libnetwork-image=<LIBNETWORK_IMAGE_NAME>])]

    <IP>: Unique IPv4 address associated with an interface on the host machine.
    <IP6>: Unique IPv6 address associated with an interface on the host machine.
    <DOCKER_IMAGE_NAME>: Desired calico/node Docker image to use.
                         (default value depends on calicoctl binary version)
    <RUNTIME>: Specify how Calico should launch its core processes.
    <AS_NUM>: Autonomous System number to use for BGP peering.
              (default global AS number of 64511 is used if not specified)
    <LOG_DIR>: Directory where Calico will store logs, if not default.
               (default: /var/log/calico)
    <DETACH>: Boolean to have calico/node run as detached (true) or in the foreground (false).
              (default: true)
    <LIBNETWORK_IMAGE_NAME>: Desired calico/node-libnetwork Docker image to use when
                             using the Docker libnetwork driver.

    --libnetwork: Download and run the calico/node-libnetwork Docker image.
    --no-pull: Prevent from pulling the Calico node Docker images.
```

When running the `calicoctl node` command with the `--libnetwork` plugin, the
command starts the `calico/node` Docker image with libnetwork plugin enabled in it.

The `--runtime=rkt` setting can be used to start the Calico services in a rkt
container.

The `--runtime=none` setting can be used to prevent Calico from launching the
calico-node Docker container, instead allowing you to run the core processes
via some other means. For example, you might install directly on the host and
execute them via a systemd unit.

The `--ip` and `--ip6` flags should be used to specify a unique IP address that
is owned by an interface on this Calico host system.  These IP addresses are
used to identify source addresses for BGP peering, allowing an interface
through the host system over which traffic will flow to the workloads.

The `--detach` option should be used if you are adding Calico to an init system.

The `--no-pull` flag will prevent calico-node from pulling the Calico node
Docker image to use.  This is useful if you want to run Calico with a custom
node image that you have stored locally on your machine.  You may also want
to pull an image using the `docker pull` command to get the image with specific
`docker pull` parameters.

By default, when the `calico-node` container starts it will create default
pools if no pools exist. This behavior can be suppressed by setting the
`NO_DEFAULT_POOLS` environment variable to `TRUE`.

Examples:

```
$ calicoctl node

No IP provided. Using detected IP: 172.25.0.1
Calico node is running with id: c95fc492d57bd7d3c568e5b1d67001c1cec7c01b771531618fbf910557e37f29

# Run the Calico node with IPv4 and IPv6, using calico/node version v0.7.0
$ calicoctl node --ip=172.25.0.1 --ip6=2620:0104::1 --node-image=calico/node:v0.7.0
Pulling Docker image calico/node:v0.7.0

Calico node is running with id: f97a6fe29109ea6d9cc3be70a2a6fd9b56a5dc3c4e9ba77f6b14643ec3da4915

# Run the Calico node using the Docker libnetwork driver
$ sudo calicoctl node --libnetwork
No IP provided. Using detected IP: 172.25.0.1
Calico node is running with id: c95fc492d57bd7d3c568e5b1d67001c1cec7c01b771531618fbf910557e37f29
Calico libnetwork driver is running with id: 504b1d6d42908e376d9941ad8e3dfd65b072c15455c108e0205beee52d71fa69
```

#### Calico with libnetwork
When running Calico with libnetwork, the Calico libnetwork driver handles
creation of a profile, and adding and removing the container from the Calico
network during the lifecycle of a network and the containers attached to that
network.

The `docker network create` command allows you to specify the driver used for
networking _and_ the driver used for IPAM.  To use Calico networking with
libnetwork you need to :

- Run `calicoctl node` with the `--libnetwork` flag
- Create a network using the `-d calico` setting.  You may optionally use the
`--ipam-driver calico` setting if you would like to use Calico IP address
management.

```
calicoctl node --libnetwork
docker network create -d calico net1
docker network create -d calico --ipam-driver calico net2
```

Read our [Calico as a Docker network plugin tutorial]({{site.baseurl}}/{{page.version}}/getting-started/docker/tutorials/basic)
for more details.

### calicoctl node stop
This command is used to stop a `calico/node` instance.  If there are endpoints
remaining on the host that have been networked with Calico, a warning message
will appear and the command will abort unless forced with the --force option.

To stop the node cleanly, you must first remove all workloads from Calico and
manually clean up any workloads that were uncleanly stopped with the
`calicoctl endpoint remove` command.

This command must be run as root and must be run on the specific Calico node
that you are configuring.

Command syntax:

```
calicoctl node stop [--force]

    --force:  Stop the Calico node even if there are still endpoints
              configured.
```

Examples:

```
$ calicoctl node stop
Node stopped and all configuration removed
```

### calicoctl node remove
This command is used to remove data associated with a `calico/node` instance.  

To remove the node cleanly, you must first remove all workloads from Calico and
manually clean up any workloads that were uncleanly stopped with the
`calicoctl endpoint remove` command, and then run the `calicoctl node stop`
command to stop the node before removing it.

You can remove endpoint configuration from the node by passing in the
`--remove-endpoints` flag.  This flag is required to remove a node that
contains endpoint config.

You can remove the Calico node on a different host by passing in the hostname
of the node to remove with the `--hostname=<HOSTNAME>` parameter. If you do not
know the hostname of the machine, you can view node information using the
`calicoctl node show` command, as seen in this doc. You may want to do this if,
for example, a node in the cluster is no longer in use, yet the data for the
host still appears in the datastore.

This command must be run as root.

Command syntax:

```
calicoctl node remove [--hostname=<HOSTNAME>] [--remove-endpoints]

    --hostname=<HOSTNAME>: The hostname from which to remove the Calico node.
    --remove-endpoints:    Remove the endpoint data when deleting the node
                           from the Calico network.
```

Examples:

```
$ calicoctl node remove
Node configuration removed
```

### calicoctl node show
This command is used to show hostname, IP address, and BGP data for all nodes
in the cluster.

Command syntax:

```
calicoctl node show
```

Examples:

```
$ calicoctl node show
+------------+--------------+-----------+-------------------+-----------------------+--------------+
|  Hostname  |  Bird IPv4   | Bird IPv6 |       AS Num      |      BGP Peers v4     | BGP Peers v6 |
+------------+--------------+-----------+-------------------+-----------------------+--------------+
| calico-01  | 172.17.8.101 |           | 64511 (inherited) |                       |              |
| calico-02  | 172.25.20.5  |           |       63333       | 172.25.10.10 as 63333 |              |
+------------+--------------+-----------+-------------------+-----------------------+--------------+

```

### calicoctl node bgp peer add \<PEER_IP\> as \<AS_NUM\>
This command allows users to configure specific BGP peers with this node.

This command must be run on the specific Calico node that you are configuring.
If peering with another Calico compute host (or indeed most BGP
implementations) you will need to configure the peering on both devices in
order to enable it.

Use [`calicoctl node bgp peer show`](bgp) to display current list of
configured peers, and [`calicoctl status`](status) to see all BGP peers
of this node and their status.


Command syntax:

```
calicoctl node bgp peer add <PEER_IP> as <AS_NUM>

    <PEER_IP>: IP address of BGP peer to add.
    <AS_NUM>: Autonomous systems number to configure with BGP peer.

```

Examples:

```
$ calicoctl node bgp peer add 172.25.0.2 as 65511
```

### calicoctl node bgp peer remove \<PEER_IP\>
This command allows users to remove specific BGP peers from this Calico node.

NOTE: This command only removes peers configured with `calicoctl node bgp peer
add`. It does not remove global peers ([`calicoctl bgp peer add`](bgp))
or peerings with other Calico nodes if the node mesh is on
([`calicoctl bgp node-mesh`](bgp)).

This command must be run on the specific Calico node that you are configuring.

Command syntax:

```
calicoctl node bgp peer remove <PEER_IP>

    <PEER_IP>: IP address of BGP peer to remove.
```

Examples:

```
$ calicoctl node bgp peer remove 172.25.0.1
BGP peer removed from node configuration
```

### calicoctl node bgp peer show
This command allows users to view the node-specific BGP peers configured on
this node.

NOTE: This command does not show global BGP peers ([`calicoctl bgp peer show`](bgp))
or peerings to other Calico nodes when the node-mesh is on
([`calicoctl bgp node-mesh`](bgp)). To show all BGP peers of this node and
their status, use [`calicoctl status`](status).

This command must be run on individual Calico nodes.

Command syntax:

```
calicoctl node bgp peer show [--ipv4 | --ipv6]

    --ipv4: Show only IPv4 peers.
    --ipv6: Show only IPv6 peers.

```

Examples:

```
$ calicoctl node bgp peer show --ipv4
+-----------------------------+--------+
| Node specific IPv4 BGP Peer | AS Num |
+-----------------------------+--------+
| 172.17.8.101                | 65511  |
+-----------------------------+--------+

```
