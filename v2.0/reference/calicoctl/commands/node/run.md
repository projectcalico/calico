---
title: calicoctl node run
canonical_url: 'https://docs.projectcalico.org/v3.3/reference/calicoctl/commands/node/run'
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
                     [--init-system]
                     [--disable-docker-networking]
                     [--docker-networking-ifprefix=<IFPREFIX>]

Options:
  -h --help                Show this screen.
     --name=<NAME>         The name of the Calico node.  If this is not
                           supplied it defaults to the host name.
     --as=<AS_NUM>         Set the AS number for this node.  If omitted, it
                           will use the value configured on the node resource.
                           If there is no configured value and --as option is
                           omitted, the node will inherit the global AS number
                           (see 'calicoctl config' for details).
     --ip=<IP>             Set the local IPv4 routing address for this node.
                           If omitted, it will use the value configured on the
                           node resource.  If there is no configured value
                           and the --ip option is omitted, the node will
                           attempt to autodetect an IP address to use.  Use a
                           value of 'autodetect' to always force autodetection
                           of the IP each time the node starts.
     --ip6=<IP6>           Set the local IPv6 routing address for this node.
                           If omitted, it will use the value configured on the
                           node resource.  If there is no configured value
                           and the --ip6 option is omitted, the node will not
                           route IPv6.
     --log-dir=<LOG_DIR>   The directory containing Calico logs.
                           [default: /var/log/calico]
     --node-image=<DOCKER_IMAGE_NAME>
                           Docker image to use for Calico's per-node container.
                           [default: calico/node:%s]
     --backend=(bird|gobgp|none)
                           Specify which networking backend to use.  When set
                           to "none", Calico node runs in policy only mode.
                           The option to run with gobgp is currently
                           experimental.
                           [default: bird]
     --dryrun              Output the appropriate command, without starting the
                           container.
     --init-system         Run the appropriate command to use with an init
                           system.
     --no-default-ippools  Do not create default pools upon startup.
                           Default IP pools will be created if this is not set
                           and there are no pre-existing Calico IP pools.
     --disable-docker-networking
                           Disable Docker networking.
     --docker-networking-ifprefix=<IFPREFIX>
                           Interface prefix to use for the network interface
                           within the Docker containers that have been networked
                           by the Calico driver.
                           [default: cali]
  -c --config=<CONFIG>     Path to the file containing connection
                           configuration in YAML or JSON format.
                           [default: /etc/calico/calicoctl.cfg]

Description:
  This command is used to start a calico/node container instance which provides
  Calico networking and network policy on your compute host.
```

### Examples

```
# Start the Calico node with a pre-configured IPv4 address for BGP.
$ sudo calicoctl node run
Running command to load modules: modprobe -a xt_set ip6_tables
Enabling IPv4 forwarding
Enabling IPv6 forwarding
Increasing conntrack limit
Running the following command:

docker run --net=host --privileged --name=calico-node -d --restart=always -e ETCD_SCHEME=http -e HOSTNAME=calico -e CALICO_LIBNETWORK_ENABLED=true -e ETCD_AUTHORITY=127.0.0.1:2379 -e AS= -e NO_DEFAULT_POOLS= -e ETCD_ENDPOINTS= -e IP= -e IP6= -e CALICO_NETWORKING_BACKEND=bird -v /var/run/docker.sock:/var/run/docker.sock -v /var/run/calico:/var/run/calico -v /lib/modules:/lib/modules -v /var/log/calico:/var/log/calico -v /run/docker/plugins:/run/docker/plugins calico/node:v1.0.2

Waiting for etcd connection...
Using configured IPv4 address: 192.0.2.0
No IPv6 address configured
Using global AS number
WARNING: Could not confirm that the provided IPv4 address is assigned to this host.
Calico node name:  calico
CALICO_LIBNETWORK_ENABLED is true - start libnetwork service
Calico node started successfully
```

### Options

```
   --name=<NAME>         The name of the Calico node.  If this is not
                         supplied it defaults to the host name.
   --as=<AS_NUM>         Set the AS number for this node.  If omitted, it
                         will use the value configured on the node resource.
                         If there is no configured value and --as option is
                         omitted, the node will inherit the global AS number
                         (see 'calicoctl config' for details).
   --ip=<IP>             Set the local IPv4 routing address for this node.
                         If omitted, it will use the value configured on the
                         node resource.  If there is no configured value
                         and the --ip option is omitted, the node will
                         attempt to autodetect an IP address to use.  Use a
                         value of 'autodetect' to always force autodetection
                         of the IP each time the node starts.
   --ip6=<IP6>           Set the local IPv6 routing address for this node.
                         If omitted, it will use the value configured on the
                         node resource.  If there is no configured value
                         and the --ip6 option is omitted, the node will not
                         route IPv6.
   --log-dir=<LOG_DIR>   The directory containing Calico logs.
                         [default: /var/log/calico]
   --node-image=<DOCKER_IMAGE_NAME>
                         Docker image to use for Calico's per-node container.
                         [default: calico/node:%s]
   --backend=(bird|gobgp|none)
                         Specify which networking backend to use.  When set
                         to "none", Calico node runs in policy only mode.
                         The option to run with gobgp is currently
                         experimental.
                         [default: bird]
   --dryrun              Output the appropriate command, without starting the
                         container.
   --init-system         Run the appropriate command to use with an init
                         system.
   --no-default-ippools  Do not create default pools upon startup.
                         Default IP pools will be created if this is not set
                         and there are no pre-existing Calico IP pools.
   --disable-docker-networking
                         Disable Docker networking.
   --docker-networking-ifprefix=<IFPREFIX>
                         Interface prefix to use for the network interface
                         within the Docker containers that have been networked
                         by the Calico driver.
                         [default: cali]
```

### General options

```
-c --config=<CONFIG>     Path to the file containing connection
                         configuration in YAML or JSON format.
                         [default: /etc/calico/calicoctl.cfg]
```

## See also

-  [Resources]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/) for details on all valid resources, including file format
   and schema
-  [Policy]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/policy) for details on the Calico selector-based policy model
-  [calicoctl configuration]({{site.baseurl}}/{{page.version}}/reference/calicoctl/setup) for details on configuring `calicoctl` to access
   the Calico datastore.

