---
title: Configuring BIRD as a BGP route reflector
sitemap: false 
canonical_url: https://docs.projectcalico.org/v3.1/usage/routereflector/bird-rr-config
---

For many Calico deployments, the use of a route reflector is not required.
However, for large scale deployments a full mesh of BGP peerings between each
of your Calico nodes may become untenable.  In this case, route reflectors
allow you to remove the full mesh and scale up the size of the cluster.

These instructions will take you through installing BIRD as a BGP route
reflector, and updating your other BIRD instances to speak to your new
route reflector.  The instructions are valid for both Ubuntu and Red Hat
Enterprise Linux (RHEL).

For a container-based deployment, using the `{{site.nodecontainer}}` container, check
out the [{{site.prodname}} BIRD route reflector container](calico-routereflector).

## Prerequisites

Before starting this you will need the following:

-   A machine running either Ubuntu or RHEL that is not already
    being used as a compute host.
-   SSH access to the machine.

## Installation

### Step 1: Install BIRD

#### Ubuntu

Add the official [BIRD](http://bird.network.cz/) PPA. This PPA contains
fixes to BIRD that are not yet available in Ubuntu. To add the
PPA, run:

    sudo add-apt-repository ppa:cz.nic-labs/bird

    > **Tip**: If the above command fails with error
    > `'ascii' codec can't decode byte`, try running the command with a
    > UTF-8 enabled locale:
    > `LC_ALL=en_US.UTF-8 add-apt-repository ppa:cz.nic-labs/bird`.
    {: .alert .alert-success}

Once that's done, update your package manager and install BIRD (the
single `bird` package installs both IPv4 and IPv6 BIRD):

    sudo apt-get update
    sudo apt-get install bird

#### RHEL

> **Note**: The following commands require root privileges. You can either open a root shell
> or prefix them with `sudo`.
{: .alert .alert-info}

1. From a terminal prompt, create a new file called bird.repo in the
   `/etc/yum.repos.d/` directory.

   ```bash
   vi /etc/yum.repos.d/bird.repo
   ```

1. Add the following lines to the file.

   ```
   [bird]
   name=Network.CZ Repository
   baseurl=ftp://repo.network.cz/pub/redhat/
   enabled=1
   gpgcheck=0
   gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-network.cz
   ```

1. Save and close the file.

1. If you don't already have the `/etc/pki/rpm-gpg/` directory, use the following command
   to create it.

   ```bash
   mkdir -p /etc/pki/rpm-gpg/
   ```

1. Download the public key of the BIRD repository into the `/etc/pki/rpm-gpg/` directory.

   ```bash
   curl ftp://bird.network.cz/pub/bird/redhat/RPM-GPG-KEY-network.cz -o /etc/pki/rpm-gpg/RPM-GPG-KEY-network.cz
   ```

   > **Tip**: If you don't have curl, try replacing `curl` with `wget` in the command.
   {: .alert .alert-success}

1. Use the following command to install BIRD.

   ```bash
   yum install -y bird
   ```

> **Note**: We do not recommend installing [Extra Packages for Enterprise Linux (EPEL)](https://fedoraproject.org/wiki/EPEL).
> EPEL lacks official Red Hat support. It contains the BIRD package, but it also contains
> other packages. Installing EPEL may cause existing packages on your system to
> be overwritten with unsupported packages. To avoid issues of this kind, we recommend
> using the method described above.
{: .alert .alert-info}

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

#### Ubuntu

Restart BIRD:

    sudo service bird restart

Optionally, if you configured IPv6 in step 3, also restart BIRD6:

    sudo service bird6 restart

#### RHEL

Restart BIRD:

    systemctl restart bird
    systemctl enable bird

Optionally, if you configured IPv6 in step 3, also restart BIRD6:

    systemctl restart bird6
    systemctl enable bird6

### Step 5: Reconfigure compute nodes


#### Container-based deployments

For container-based deployments using the `{{site.nodecontainer}}` container, use
`calicoctl` to disable the full mesh between each node and configure the
route reflector as a global peer.

To disable the node-to-node mesh:

```
# Get the current bgpconfig settings
$ calicoctl get bgpconfig -o yaml > bgp.yaml

# Set nodeToNodeMeshEnabled to false
$ vim bgp.yaml

# Replace the current bgpconfig settings
$ calicoctl replace -f bgp.yaml
```

To create a global peer for the route reflector:

```
$ cat << EOF | calicoctl create -f -
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: bgppeer-global-1
spec:
  peerIP: 192.20.30.40
  asNumber: 64567
EOF
```

For more details/options refer to the [BGP configuration guide]({{site.baseurl}}/{{page.version}}/usage/configuration/bgp).
