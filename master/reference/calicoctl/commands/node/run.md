---
title: calicoctl node run
---

This sections describes the `calicoctl node run` command.

Read the [calicoctl Overview]({{site.baseurl}}/{{page.version}}/reference/calicoctl)
for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl node run' command

Run `calicoctl node run --help` to display the following help menu for the
command.

```
Usage:
  calicoctl node run [--ip=<IP>] [--ip6=<IP6>] [--as=<AS_NUM>]
                     [--name=<NAME>]
                     [--log-dir=<LOG_DIR>]
                     [--node-image=<DOCKER_IMAGE_NAME>]
                     [--backend=(bird|gobgp|none)]
                     [--config=<CONFIG>]
                     [--no-default-ippools]
                     [--dryrun]

Options:
  -h --help                Show this screen.
     --as=<AS_NUM>         The default AS number for this node.  If this is not
                           specified, the node will use the global AS number
                           (see 'calicoctl config' for details).
     --name=<NAME>         The name of the Calico node.  If this is not
                           supplied it defaults to the host name.
     --ip=<IP>             The local management address to use.  If this is not
                           specified, the node will attempt to auto-discover
                           the local IP address to use - however, it is
                           recommended to specify the required address to use.
     --ip6=<IP6>           The local IPv6 management address to use.  If this
                           is not specified, the node will not route IPv6.
     --log-dir=<LOG_DIR>   The directory containing Calico logs.
                           [default: /var/log/calico]
     --node-image=<DOCKER_IMAGE_NAME>
                           Docker image to use for Calico's
                           per-node container.
                           [default: calico/node:%s]
     --backend=(bird|gobgp|none)
                           Specify which networking backend to use.  When set
                           to "none", Calico node runs in policy only mode.
                           The option to run with gobgp is currently
                           experimental.
                           [default: bird]
     --dryrun              Output the appropriate Docker command, without
                           starting the container.
     --no-default-ippools  Do not create default pools upon startup.
                           Default IP pools will be created if this is not set
                           and there are no pre-existing Calico IP pools.
  -c --config=<CONFIG>     Filename containing connection configuration in
                           YAML or JSON format.
                           [default: /etc/calico/calicoctl.cfg]

Description:
  This command is used to start a Calico node container instance.  The
  Calico node provides Calico networking on your compute host.
```

### Examples

```
# Start the Calico node with a specific IPv4 address for BGP.
$ sudo calicoctl node run --ip=10.10.0.12
Running command to load modules: modprobe -a xt_set ip6_tables
Enabling IPv4 forwarding
Enabling IPv6 forwarding
Increasing conntrack limit
Running the following command:

docker run -d --net=host --privileged --name=calico-node -e ETCD_AUTHORITY=127.0.0.1:2379 -e CALICO_LIBNETWORK_ENABLED=true -e HOSTNAME=calico -e IP=10.10.0.12 -e AS= -e NO_DEFAULT_POOLS= -e IP6= -e CALICO_NETWORKING_BACKEND=bird -e ETCD_SCHEME=http -e ETCD_ENDPOINTS= -v /lib/modules:/lib/modules -v /run/docker/plugins:/run/docker/plugins -v /var/run/docker.sock:/var/run/docker.sock -v /var/log/calico:/var/log/calico -v /var/run/calico:/var/run/calico calico/node:v1.0.0-beta-rc4-22-gfd4cf3c

```

### Options

```
   --as=<AS_NUM>         The default AS number for this node.  If this is not
                         specified, the node will use the global AS number
                         (see 'calicoctl config' for details).
   --name=<NAME>         The name of the Calico node.  If this is not
                         supplied it defaults to the host name.
   --ip=<IP>             The local management address to use.  If this is not
                         specified, the node will attempt to auto-discover
                         the local IP address to use - however, it is
                         recommended to specify the required address to use.
   --ip6=<IP6>           The local IPv6 management address to use.  If this
                         is not specified, the node will not route IPv6.
   --log-dir=<LOG_DIR>   The directory containing Calico logs.
                         [default: /var/log/calico]
   --node-image=<DOCKER_IMAGE_NAME>
                         Docker image to use for Calico's
                         per-node container.
                         [default: calico/node:%s]
   --backend=(bird|gobgp|none)
                         Specify which networking backend to use.  When set
                         to "none", Calico node runs in policy only mode.
                         The option to run with gobgp is currently
                         experimental.
                         [default: bird]
   --dryrun              Output the appropriate Docker command, without
                         starting the container.
   --no-default-ippools  Do not create default pools upon startup.
                         Default IP pools will be created if this is not set
                         and there are no pre-existing Calico IP pools.
```

### General options

```
-c --config=<CONFIG>     Filename containing connection configuration in
                           YAML or JSON format.
                           [default: /etc/calico/calicoctl.cfg]
```

## See also

-  [Resources]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/) for details on all valid resources, including file format
   and schema
-  [Policy]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/policy) for details on the Calico selector-based policy model
-  [calicoctl configuration]({{site.baseurl}}/{{page.version}}/reference/calicoctl/setup) for details on configuring `calicoctl` to access
   the Calico datastore.

