<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-docker source tree.
>
> View the calico-docker documentation for the latest release [here](https://github.com/projectcalico/calico-docker/blob/v0.10.0/README.md).
<!--- else
> You are viewing the calico-docker documentation for release **release**.
<!--- end of master only -->

# User reference for 'calicoctl node' commands

This sections describes the `calicoctl node` commands.

The `calicoctl node` command starts the calico/node Docker image that runs the 
main Calico processes such as Felix and the BIRD BGP routing daemon.  The 
calico/node container is required to be running on every compute host for 
Calico networking.

Read the [calicoctl command line interface user reference](../calicoctl.md) 
for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl node' commands

Run `calicoctl node --help` to display the following help menu for the 
calicoctl node commands.

```

Usage:
  calicoctl node [--ip=<IP>] [--ip6=<IP6>] [--node-image=<DOCKER_IMAGE_NAME>]
    [--runtime=<RUNTIME>] [--as=<AS_NUM>] [--log-dir=<LOG_DIR>]
    [--detach=<DETACH>] [--rkt]
    [(--kubernetes [--kube-plugin-version=<KUBE_PLUGIN_VERSION])]
    [(--libnetwork [--libnetwork-image=<LIBNETWORK_IMAGE_NAME>])]
  calicoctl node stop [--force]
  calicoctl node remove [--remove-endpoints]
  calicoctl node bgp peer add <PEER_IP> as <AS_NUM>
  calicoctl node bgp peer remove <PEER_IP>
  calicoctl node bgp peer show [--ipv4 | --ipv6]

Description:
  Configure the Calico node containers as well as default BGP information
  for this node.

Options:
  --force                   Stop the Calico node even if there are still
                            endpoints configured.
  --remove-endpoints        Remove the endpoint data when deleting the node
                            from the Calico network.
  --node-image=<DOCKER_IMAGE_NAME>    Docker image to use for Calico's per-node
                            container. [default: calico/node:latest]
  --detach=<DETACH>         Set "true" to run Calico service as detached,
                            "false" to run in the foreground.  When using
                            libnetwork, this may not be set to "false".
                            [default: true]
  --runtime=<RUNTIME>       Specify how Calico services should be
                            launched.  When set to "docker", services will be
                            launched via the calico-node container, whereas a
                            value of "none" will not launch them at all.
                            [default: docker]
  --log-dir=<LOG_DIR>       The directory for logs [default: /var/log/calico]
  --ip=<IP>                 The local management address to use.
  --ip6=<IP6>               The local IPv6 management address to use.
  --as=<AS_NUM>             The default AS number for this node.
  --ipv4                    Show IPv4 information only.
  --ipv6                    Show IPv6 information only.
  --kubernetes              Download and install the Kubernetes plugin.
  --kube-plugin-version=<KUBE_PLUGIN_VERSION> Version of the Kubernetes plugin
                            to install when using the --kubernetes option.
                            [default: v0.3.0]
  --rkt                     Download and install the rkt plugin.
  --libnetwork              Use the libnetwork plugin.
  --libnetwork-image=<LIBNETWORK_IMAGE_NAME>    Docker image to use for
                            Calico's libnetwork driver.
                            [default: calico/node-libnetwork:latest]

```

## calicoctl node commands


### calicoctl node 

This command performs two actions:

1. Initialize this host for Calico by setting first-time config in etcd.
2. (Optional) Start the `calico/node` Docker container. By default
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
    [--detach=<DETACH>] [--rkt]
    [(--kubernetes [--kube-plugin-version=<KUBE_PLUGIN_VERSION])]
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
    <KUBE_PLUGIN_VERSION>: The version of the `calico-kubernetes` plugin to install.
    <LIBNETWORK_IMAGE_NAME>: Desired calico/node-libnetwork Docker image to use when 
                             using the Docker libnetwork driver.

    --kubernetes: Download and install the kubernetes plugin.
    --rkt: Download and install the rkt plugin.
    --libnetwork: Download and run the calico/node-libnetwork Docker image.
```

When running the `calicoctl node` command with the `--libnetwork` plugin, the 
command starts a container using the `calico/node-libnetwork` Docker image in 
addition to starting the `calico/node` Docker image.

The `--runtime=none` setting can be used to prevent Calico from launching the
calico-node Docker container, instead allowing you to run the core processes
via some other means. For example, you might install directly on the host and
execute them via a systemd unit.

The `--ip` and `--ip6` flags should be used to specify a unique IP address that 
is owned by an interface on this Calico host system.  These IP addresses are 
used to identify source addresses for BGP peering, allowing an interface 
through the host system over which traffic will flow to the workloads.

The `--kubernetes` flag configures your Calico node with the Calico Kubernetes 
plugin.  This allows you to run Calico with the Kubernetes orchestrator.

The `--rkt` flag configures your Calico node with the Calico rkt plugin, which 
allows you to run Calico with the rkt orchestrator.

The `--detach` option should be used if you are adding Calico to an init system.

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

This command must be run as root and must be run on the specific Calico node 
that you are configuring.

Command syntax:

```
calicoctl node remove [--remove-endpoints]

    --remove-endpoints:  Remove the endpoint data when deleting the node
                         from the Calico network.
```

Examples:

```
$ calicoctl node remove
Node configuration removed
```

### calicoctl node bgp peer add \<PEER_IP\> as \<AS_NUM\>
This command allows users to configure specific BGP peers with this node.

This command must be run on the specific Calico node that you are configuring. 
If peering with another Calico compute host (or indeed most BGP 
implementations) you will need to configure the peering on both devices in 
order to enable it.

Use [`calicoctl node bgp peer show`](./bgp.md) to display current list of 
configured peers, and [`calicoctl status`](./status.md) to see all BGP peers 
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
add`. It does not remove global peers ([`calicoctl bgp peer add`](./bgp.md)) 
or peerings with other Calico nodes if the node mesh is on 
([calicoctl bgp node-mesh](./bgp.md)).

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

NOTE: This command does not show global BGP peers ([calicoctl bgp peer show]
(./bgp.md)) or peerings to other Calico nodes when the node-mesh is on 
([calicoctl bgp node-mesh](./bgp.md)). To show all BGP peers of this node and 
their status, use [`calicoctl status`](./status.md).

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
