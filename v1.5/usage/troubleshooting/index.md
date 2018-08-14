---
title: Troubleshooting
canonical_url: 'https://docs.projectcalico.org/v3.2/usage/troubleshooting/'
---

## Running `sudo calicoctl ...` with Environment Variables

If you use `sudo` for commands like `calicoctl node`, remember that your environment
variables will not be transferred to the `sudo` environment.  You can run `sudo` with
the `-E` flag to include your environment variables:

```shell
    sudo -E calicoctl node
```

or you can set environment variables for `sudo` commands like this:

```shell
    sudo ETCD_AUTHORITY=172.25.0.1:2379 calicoctl node
```

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

## No ping between containers on different hosts

If you have connectivity between containers on the same host, and between
containers and the Internet, but not between containers on different hosts, it
probably indicates a problem in the BIRD setup.

Look at `calicoctl status` on each host.  It should include output like this:

	IPv4 BGP status
	IP: 172.16.8.242    AS Number: 64511 (inherited)
	+--------------+-------------------+-------+----------+--------------------------+
	| Peer address |     Peer type     | State |  Since   |           Info           |
	+--------------+-------------------+-------+----------+--------------------------+
	| 172.16.8.242 | node-to-node mesh | start | 09:34:09 | Established              |
	+--------------+-------------------+-------+----------+--------------------------+

If you do not see this, please check the following.

- Can your hosts ping each other?  There must be IP connectivity between the
  hosts.

- Your hosts' names must be different.  Calico uses hostname as a key in the
  etcd data, and the etcd data is used to autogenerate the correct BIRD
  config - so a duplicate hostname will prevent correct BIRD setup.

- There must not be iptables rules, or any kind of firewall, preventing
  communication between the hosts on TCP port 179.  (179 is the BGP port.)

## Basic checks
Running `ip route` shows what routes have been programmed. Routes from other hosts
should show that they are programmed by bird.

If your hosts reboot themselves with a message from `locksmithd` your cached CoreOS
image is out of date.  Use `vagrant box update` to pull the new version.  I
recommend doing a `vagrant destroy; vagrant up` to start from a clean slate afterwards.

If you hit issues, please raise tickets. Diags can be collected with the
`sudo ./calicoctl diags` command.
