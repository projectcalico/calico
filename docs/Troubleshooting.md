<!--- master only -->
> ![warning](images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.19.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Troubleshooting

## Running `sudo calicoctl ...` with Environment Variables

If you use `sudo` for commands like `calicoctl node`, remember that your environment
variables will not be transferred to the `sudo` environment.  You can run `sudo` with
the `-E` flag to include your environment variables:

    sudo -E calicoctl node

or you can set environment variables for `sudo` commands like this:

    sudo ETCD_AUTHORITY=172.25.0.1:2379 calicoctl node

## Ubuntu (or GNOME) NetworkManager

Disable [NetworkManager](https://help.ubuntu.com/community/NetworkManager) before 
attempting to use Calico networking.

NetworkManager manipulates the routing table for interfaces in the default network 
namespace where Calico veth pairs are anchored for connections to containers.  
This can interfere with the Calico agent's ability to route correctly.

You can configure interfaces in the `/etc/network/interfaces` file if the 
NetworkManager removes your host's interfaces. See the Debian 
[NetworkConfiguration](https://wiki.debian.org/NetworkConfiguration) 
guide for more information.

## etcd.EtcdException: No more machines in the cluster

If you see this exception, it means `calicoctl` can't communicate with your etcd 
cluster.  Ensure etcd is up and listening on `localhost:2379`

## Basic checks
Running `ip route` shows what routes have been programmed. Routes from other hosts 
should show that they are programmed by bird.

If your hosts reboot themselves with a message from `locksmithd` your cached CoreOS 
image is out of date.  Use `vagrant box update` to pull the new version.  I 
recommend doing a `vagrant destroy; vagrant up` to start from a clean slate afterwards.

If you hit issues, please raise tickets. Diags can be collected with the 
`sudo ./calicoctl diags` command.
[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/Troubleshooting.md?pixel)](https://github.com/igrigorik/ga-beacon)
