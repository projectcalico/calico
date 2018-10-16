---
title: calicoctl node run
canonical_url: 'https://docs.projectcalico.org/v3.2/reference/calicoctl/commands/node/run'
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
                     [--ip-autodetection-method=<IP_AUTODETECTION_METHOD>]
                     [--ip6-autodetection-method=<IP6_AUTODETECTION_METHOD>]
                     [--log-dir=<LOG_DIR>]
                     [--node-image=<DOCKER_IMAGE_NAME>]
                     [--backend=(bird|gobgp|none)]
                     [--config=<CONFIG>]
                     [--no-default-ippools]
                     [--dryrun]
                     [--init-system]
                     [--disable-docker-networking]
                     [--docker-networking-ifprefix=<IFPREFIX>]
                     [--use-docker-networking-container-labels]

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
                           route IPv6.  Use a value of 'autodetect' to force
                           autodetection of the IP each time the node starts.
     --ip-autodetection-method=<IP_AUTODETECTION_METHOD>
                           Specify the autodetection method for detecting the
                           local IPv4 routing address for this node.  The valid
                           options are:
                           > first-found
                             Use the first valid IP address on the first
                             enumerated interface (common known exceptions are
                             filtered out, e.g. the docker bridge).  It is not
                             recommended to use this if you have multiple
                             external interfaces on your host.
                           > can-reach=<IP OR DOMAINNAME>
                             Use the interface determined by your host routing
                             tables that will be used to reach the supplied
                             destination IP or domain name.
			   > interface=<IFACE NAME REGEX LIST>
                             Use the first valid IP address found on interfaces
                             named as per the first matching supplied interface
			     name regex. Regexes are separated by commas
			     (e.g. eth.*,enp0s.*).
			   > skip-interface=<IFACE NAME REGEX LIST>
			     Use the first valid IP address on the first
			     enumerated interface (same logic as first-found
			     above) that does NOT match with any of the
			     specified interface name regexes. Regexes are
			     separated by commas (e.g. eth.*,enp0s.*).
                           [default: first-found]
     --ip6-autodetection-method=<IP6_AUTODETECTION_METHOD>
                           Specify the autodetection method for detecting the
                           local IPv6 routing address for this node.  See
                           ip-autodetection-method flag for valid options.
                           [default: first-found]
     --log-dir=<LOG_DIR>   The directory containing Calico logs.
                           [default: /var/log/calico]
     --node-image=<DOCKER_IMAGE_NAME>
                           Docker image to use for Calico's per-node container.
                           [default: {{site.imageNames["node"]}}:latest]
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
     --use-docker-networking-container-labels
                           Extract the Calico-namespaced Docker container labels
                           (org.projectcalico.label.*) and apply them to the
                           container endpoints for use with Calico policy.
                           This option is only valid when using Calico Docker
                           networking, and when enabled traffic must be
                           explicitly allowed by configuring Calico policies.
  -c --config=<CONFIG>     Path to the file containing connection
                           configuration in YAML or JSON format.
                           [default: /etc/calico/calicoctl.cfg]

Description:
  This command is used to start a calico/node container instance which provides
  Calico networking and network policy on your compute host.
```

### Kubernetes as the datastore

When {{site.prodname}} is configured to use the Kubernetes API as the datastore, BGP routing is *currently*
not supported.  Many of the command line options related to BGP routing will
have no effect.  These include:
-  `--ip`, `--ip6`, `--ip-autodetection-method`, `--ip6-autodetection-method`
-  `--as`
-  `--backend`

### Examples

```
# Start the {{site.nodecontainer}} with a pre-configured IPv4 address for BGP.
$ sudo calicoctl node run
Running command to load modules: modprobe -a xt_set ip6_tables
Enabling IPv4 forwarding
Enabling IPv6 forwarding
Increasing conntrack limit
Running the following command:

docker run --net=host --privileged --name={{site.noderunning}} -d --restart=always -e ETCD_SCHEME=http -e HOSTNAME=calico -e CALICO_LIBNETWORK_ENABLED=true -e ETCD_AUTHORITY=127.0.0.1:2379 -e AS= -e NO_DEFAULT_POOLS= -e ETCD_ENDPOINTS= -e IP= -e IP6= -e CALICO_NETWORKING_BACKEND=bird -v /var/run/docker.sock:/var/run/docker.sock -v /var/run/calico:/var/run/calico -v /lib/modules:/lib/modules -v /var/log/calico:/var/log/calico -v /run/docker/plugins:/run/docker/plugins {{site.imageNames["node"]}}:{{site.data.versions[page.version].first.title}}

Waiting for etcd connection...
Using configured IPv4 address: 192.0.2.0
No IPv6 address configured
Using global AS number
WARNING: Could not confirm that the provided IPv4 address is assigned to this host.
Calico node name:  calico
CALICO_LIBNETWORK_ENABLED is true - start libnetwork service
Calico node started successfully
```

#### IP Autodetection method examples

The node resource includes IPv4 and IPv6 routing IP addresses that should
match those on one of the host interfaces.  These IP addresses may be
configured in advance by configuring the node resource prior to starting the
`{{site.nodecontainer}}` service, alternatively, the addresses may either be explicitly
specified or autodetected through options on the `calicoctl run` command.

There are different autodetection methods available and you should use the one
best suited to your deployment.  If you are able to explicitly specify the IP
addresses, that is always preferred over autodetection. This section describes
the available methods for autodetecting the hosts IP addresses.

An IPv4 address is always required, and so if no address was previously
configured in the node resource, and no address was specified on the CLI, then
we will attempt to autodetect an IPv4 address.  An IPv6 address, however, will
only be autodetected when explicitly requested.

To force autodetection of an IPv4 address, use the option `--ip=autodetect`.  To
force autodetection of an IPv6 address, use the option `--ip6=autodetect`.

To set the autodetection method for IPv4, use the `--ip-autodetection-method` option.
To set the autodetection method for IPv6, use the `--ip6-autodetection-method` option.

> **Note**: If you are starting the `{{site.nodecontainer}}` container directly (and not using the
> `calicoctl run` helper command), the options are passed in environment
> variables. These are described in 
> [Configuring `{{site.nodecontainer}}`]({{site.baseurl}}/{{page.version}}/reference/node/configuration).
{: .alert .alert-info}

**first-found**

The `first-found` option enumerates all interface IP addresses and returns the
first valid IP address (based on IP version and type of address) on
the first valid interface.  Certain known "local" interfaces
are omitted, such  as the docker bridge.  The order that both the interfaces
and the IP addresses are listed is system dependent.

This is the default detection method. However, since this method only makes a
very simplified guess, it is recommended to either configure the node with a
specific IP address, or to use one of the other detection methods.

e.g.

```
# First-found auto detection method explicitly specified
sudo calicoctl node run --ip autodetect --ip-autodetection-method first-found
```

**can-reach=DESTINATION**

The `can-reach` method uses your local routing to determine which IP address
will be used to reach the supplied destination.  Both IP addresses and domain
names may be used.

e.g.

```
# IP detection using a can-reach IP address
sudo calicoctl node run --ip autodetect --ip-autodetection-method can-reach=8.8.8.8

# IP detection using a can-reach domain name
sudo calicoctl node run --ip autodetect --ip-autodetection-method can-reach=www.google.com
```

**interface=INTERFACE-REGEX,INTERFACE-REGEX,...**

The `interface` method uses the supplied interface regular expressions (golang
syntax) to enumerate matching interfaces and to return the first IP address on
the first interface that matches any of the interface regexes provided.  The
order that both the interfaces and the IP addresses are listed is system
dependent.

e.g.

```
# IP detection on interface eth0
sudo calicoctl node run --ip autodetect --ip-autodetection-method interface=eth0

# IP detection on interfaces eth0, eth1, eth2 etc.
sudo calicoctl node run --ip autodetect --ip-autodetection-method interface=eth.*

# IP detection on interfaces eth0, eth1, eth2 etc. and wlp2s0
sudo calicoctl node run --ip-autodetect --ip-autodetection-method interface=eth.*,wlp2s0
```

**skip-interface=INTERFACE-REGEX,INTERFACE-REGEX,...**

The `skip-interface` method uses the supplied interface regular expressions (golang
syntax) to enumerate all interface IP addresses and returns the first valid IP address
(based on IP version and type of address) that does not match the listed regular
expressions.  Like the `first-found` option, it also skips by default certain known
"local" interfaces such as the docker bridge.  The order that both the interfaces
and the IP addresses are listed is system dependent.

This method has the ability to take in multiple regular expressions separated by `,`.
Specifying only one regular expression for interfaces to skip will also work and a
terminating `,` character does not need to be specified for those cases.

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
                         route IPv6.  Use a value of 'autodetect' to force
                         autodetection of the IP each time the node starts.
   --ip-autodetection-method=<IP_AUTODETECTION_METHOD>
                         Specify the autodetection method for detecting the
                         local IPv4 routing address for this node.  The valid
                         options are:
                         > first-found
                           Use the first valid IP address on the first
                           enumerated interface (common known exceptions are
                           filtered out, e.g. the docker bridge).  It is not
                           recommended to use this if you have multiple
                           external interfaces on your host.
                         > can-reach=<IP OR DOMAINNAME>
                           Use the interface determined by your host routing
                           tables that will be used to reach the supplied
                           destination IP or domain name.
			 > interface=<IFACE NAME REGEX LIST>
                           Use the first valid IP address found on interfaces
                           named as per the first matching supplied interface
			   name regex. Regexes are separated by commas
			   (e.g. eth.*,enp0s.*).
			 > skip-interface=<IFACE NAME REGEX LIST>
			   Use the first valid IP address on the first
			   enumerated interface (same logic as first-found
			   above) that does NOT match with any of the
			   specified interface name regexes. Regexes are
			   separated by commas (e.g. eth.*,enp0s.*).
                         [default: first-found]
   --ip6-autodetection-method=<IP6_AUTODETECTION_METHOD>
                         Specify the autodetection method for detecting the
                         local IPv6 routing address for this node.  See
                         ip-autodetection-method flag for valid options.
                         [default: first-found]
   --log-dir=<LOG_DIR>   The directory containing Calico logs.
                         [default: /var/log/calico]
   --node-image=<DOCKER_IMAGE_NAME>
                         Docker image to use for Calico's per-node container.
                         [default: {{site.imageNames["node"]}}:latest]
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
   --use-docker-networking-container-labels
                         Extract the Calico-namespaced Docker container labels
                         (org.projectcalico.label.*) and apply them to the
                         container endpoints for use with Calico policy.
                         This option is only valid when using Calico Docker
                         networking, and when enabled traffic must be
                         explicitly allowed by configuring Calico policies.
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
-  [Policy]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/networkpolicy) for details on the {{site.prodname}} selector-based policy model
-  [calicoctl configuration]({{site.baseurl}}/{{page.version}}/reference/calicoctl/setup) for details on configuring `calicoctl` to access
   the {{site.prodname}} datastore.
