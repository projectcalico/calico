---
title: Chef Trial Install
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/openstack/installation/chef'
---

> **WARNING**
>
> The chef install only supports OpenStack Icehouse and we've heard
> reports that it doesn't work smoothly outside our test lab. We
> recommend using one of our packaged installs - see [here]({{site.baseurl}}/{{page.version}}/getting-started/openstack/installation/).
>

If you're interested in trying out Calico but you don't have much
familiarity with installing OpenStack, you can install an
OpenStack-with-Calico deployment using Chef. If you're familiar with
Chef, this is the fastest way to get a quick test environment for
playing around with Calico.

This install procedure has only been tested on Ubuntu 14.04. Other
versions of Ubuntu may also work successfully. It is unlikely that this
install will work with Red Hat Enterprise Linux or its variants.

This procedure requires a Chef server: it is not sufficient to use
chef-solo. The installation uses knowledge about the other nodes in the
deployment to determine how to configure a node.

## What You Get

This install guide creates a deployment that contains a single control
node and at least two compute nodes. All the compute nodes are connected
in a BGP mesh, no BGP route reflector is required. This is the simplest
possible configuration for Calico.

Note that this is **not** a production install of Calico or of
OpenStack. It is intended for trial and testing purposes only.

## How To Use It: For Chef Newbies

If you are unfamiliar with Chef you may want to use the hosted Chef as a
service, as mentioned on the [Getting Started with Chef
website](http://gettingstartedwithchef.com/). The following instructions
provide a step-by-step guide on installing Chef and using the hosted
Chef service to install a test OpenStack+Calico environment.

### Ingredients

-   At least four servers running Ubuntu 14.04. These are for:
    -   One OpenStack control node
    -   Two OpenStack compute nodes.
    -   One Chef bootstrap server for running the node bootstrapping.

You can in principle get away with using only three machines and
performing the bootstrapping from one of the OpenStack nodes, however
this has never been tested. If you try this out, please let us know how
it went!

### Prepare Your OpenStack Nodes

The default Ubuntu 14.04 installation may have hosts configuration that
causes problems for the Chef installation. We recommend ensuring the
following preparation is performed on each OpenStack node prior to
starting the bootstrap process:

-   Ensure your hostname is correctly set. Edit the `/etc/hostname`
    file and set the correct name for each node (names must
    be unique).
-   Ensure your loopback IP and OpenStack DNS entries are configured.
    Edit the `/etc/hosts` file:
    - Set the loopback IP address to 127.0.0.1.
    - Set your hostname IP address to your static IP.
-   Configure the hostnames / IPs of the other OpenStack nodes.

If you are using VMware and VMs for each of these machines (for
testing), ensure the VM setting allows the VM to expose hardware
assisted virtualization to the guest OS (setting under the CPU
configuration).

### Prepare Chef

-   If you are intending to use the hosted Chef service, follow the
    instructions on [Getting Started with
    Chef](http://gettingstartedwithchef.com/) to create a new user and
    to create an organization for that user.
-   On your Chef bootstrap server, follow the instructions on [Getting
    Started with Chef](http://gettingstartedwithchef.com/) to
    install Chef.
-   Clone the calico-chef repo on the Chef bootstrap server (or
    somewhere sensible):

        git clone https://github.com/projectcalico/calico-chef.git

-   Create a directory for the chef installation configuration. The
    following instructions assume you created a `.chef` directory under
    the `calico-chef` directory that was created by the git clone.
-   Generate the knife config for the organization on the hosted chef
    site, download the `knife.rb` into the `.chef` directory.
-   Download both the organization and user keys from the website into
    the `.chef` directory.
-   Load the roles from file. From the `.chef` directory:

        knife role from file ../roles/*.rb

## Bootstrap your OpenStack nodes

Setting up your test deployment nodes is a two-stage process. The first
is to bootstrap each node with the appropriate role. Once all roles are
assigned to the nodes, the chef client is re-run to update the
configuration on each node. This is necessary to set up the BGP mesh,
which needs to have knowledge of each compute node in the deployment.

To install the controller node, from the chef bootstrap server run:

    knife bootstrap --sudo --verbose --run-list "role[controller]" --ssh-user <username> --ssh-password <password> <controller node hostname>

To install each compute node, from the chef bootstrap server run the
following for each compute node:

    knife bootstrap --sudo --verbose --run-list "role[compute]" --ssh-user <username> --ssh-password <password> <compute node hostname>

Check that all nodes appear in the host Chef Web UI.

Now, log on to each node in the OpenStack deployment (controller and
compute nodes) and run:

    chef-client

This will fix up the BGP mesh between the compute nodes.

You should now be ready to go!

## How To Use It: For Experienced Chef Users

We provide a single `calico` cookbook in [this
repository](https://github.com/projectcalico/calico-chef). This cookbook
can be cloned in git and then added to the Chef server in the usual way.

The cookbook defines two roles: `controller` and `compute`. To set up
your deployment, perform the following steps:

1.  Bootstrap one machine with the `controller` role. This will install
    OpenStack's control components on to that machine. When using
    OpenStack you will mostly interact with the UI on that machine.
2.  Bootstrap at least two further machines with the `compute` role.

    Note that this procedure works best when you assign all your compute
    machines the `compute` role *before* executing their run lists. This
    way you'll only need to execute the run list for each compute
    machine once.

    If you execute the run list for a compute machine before all the
    compute machines have been assigned their role, you'll need to
    re-run the run-list once all compute machines are present. The
    `compute` role builds up config that relies on knowing all the other
    `compute` nodes.

3.  Play with Calico!
