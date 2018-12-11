---
title: 'Configuring BIRD as a BGP Route Reflector'
canonical_url: 'https://docs.projectcalico.org/v3.4/usage/routereflector/bird-rr-config'
---

For many Calico deployments, the use of a Route Reflector is not required. 
However, for large scale deployments a full mesh of BGP peerings between each
of your Calico nodes may become untenable.  In this case, route reflectors
allow you to remove the full mesh and scale up the size of the cluster.

These instructions will take you through installing BIRD as a BGP route
reflector, and updating your other BIRD instances to speak to your new
route reflector.  The instructions that are are valid for both Ubuntu 14.04 and 
RHEL 7.  

For a container-based deployment, using the calico/node container, check 
out the [Calico BIRD Route Reflector container](calico-routereflector).

## Prerequisites

Before starting this you will need the following:

-   A machine running either Ubuntu 14.04 or RHEL 7 that is not already
    being used as a compute host.
-   SSH access to the machine.

## Installation

### Step 1: Install BIRD

#### Ubuntu 14.04

Add the official [BIRD](http://bird.network.cz/) PPA. This PPA contains
fixes to BIRD that are not yet available in Ubuntu 14.04. To add the
PPA, run:

    sudo add-apt-repository ppa:cz.nic-labs/bird

Once that's done, update your package manager and install BIRD (the
single `bird` package installs both IPv4 and IPv6 BIRD):

    sudo apt-get update
    sudo apt-get install bird

#### RHEL 7

First, install EPEL. Depending on your system, the following command may
be sufficient:

    sudo yum install epel-release

If that fails, try the following instead:

    wget https://dl.fedoraproject.org/pub/epel/7/x86_64/e/epel-release-7-9.noarch.rpm
    sudo yum install epel-release-7-9.noarch.rpm

With that complete, you can now install BIRD:

    yum install -y bird bird6

### Step 2: Set your BIRD IPv4 configuration

Before doing this, you'll need to take note of what BGP AS number you've
used in your compute node install.

Open `/etc/bird/bird.conf` on your route reflector system and initially
fill it with the following template, replacing `<router_id>` with the
IPv4 address of your route reflector:

    # Configure logging
    log syslog { debug, trace, info, remote, warning, error, auth, fatal, bug };
    log stderr all;

    # Override router ID
    router id <router_id>;


    filter import_kernel {
    if ( net != 0.0.0.0/0 ) then {
       accept;
       }
    reject;
    }

    # Turn on global debugging of all protocols
    debug protocols all;

    # This pseudo-protocol watches all interface up/down events.
    protocol device {
      scan time 2;    # Scan interfaces every 2 seconds
    }

Then, at the end, for each compute node in your deployment add one of
the following blocks, replacing `<node_shortname>` with a purely
alphabetical name for the host (this must be unique for each host, but
the shortname is only used within this file), `<node_ip>` with the
node's IPv4 address, and `<as_number>` with the AS number you're using:

    protocol bgp <node_shortname> {
      description "<node_ip>";
      local as <as_number>;
      neighbor <node_ip> as <as_number>;
      multihop;
      rr client;
      graceful restart;
      import all;
      export all;
    }

### Step 3 (Optional): Set your BIRD IPv6 configuration

If you want to use IPv6 connectivity, you'll need to repeat step 2 but
using `/etc/bird/bird6.conf`. The *only* differences between the two
are:

-   the filter needs to filter out ::/0 instead of 0.0.0.0/0
-   where before you set `<node_ip>` to the compute node's IPv4 address,
    this time you need to set it to the compute node's IPv6 address

Note that `<router_id>` should still be set to the route reflector's
IPv4 address: you cannot use an IPv6 address in that field.

### Step 4: Restart BIRD

#### Ubuntu 14.04

Restart BIRD:

    sudo service bird restart

Optionally, if you configured IPv6 in step 3, also restart BIRD6:

    sudo service bird6 restart

#### RHEL 7

Restart BIRD:

    systemctl restart bird
    systemctl enable bird

Optionally, if you configured IPv6 in step 3, also restart BIRD6:

    systemctl restart bird6
    systemctl enable bird6

### Step 5: Reconfigure compute nodes 

#### Openstack deployments

If you used the `calico-gen-bird-conf.sh` script to configure your
compute hosts, and you used the route reflector IP when you did, you do
not need to do anything further.

Otherwise, on each of your compute nodes, edit `/etc/bird/bird.conf`
(and, if you're using IPv6, `/etc/bird/bird6.conf`) to remove all their
peer relationships (the blocks beginning with `protocol bgp`) except for
one. Edit that one's `neighbor` field IP address to be the IP address of
the route reflector (either IPv4 or IPv6). Then, restart their BIRD
instances as detailed in step 4.

#### Container-based deployments

For container-based deployments using the `calico/node` container, use 
`calicoctl` to disable the full mesh between each node and configure the
route reflector as a global peer.

To disable the node-to-node mesh:

```
$ calicoctl config set nodeToNodeMesh off
```

To create a global peer for the route reflector:

```
$ cat << EOF | calicoctl create -f -
apiVersion: v1
kind: bgpPeer
metadata:
  peerIP: 192.20.30.40
  scope: global
spec:
  asNumber: 64567
EOF
```

For more details/options refer to the [BGP configuration guide]({{site.baseurl}}/{{page.version}}/usage/configuration/bgp).