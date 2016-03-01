<!--- master only -->
> ![warning](../../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.17.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Calico Networking with rkt

This tutorial describes how to set up a Calico cluster in a pure rkt environment.
rkt is used for running both the Calico components and the workloads.

## 1. Environment setup

This tutorial walks through getting a cluster set up with Vagrant. 

### 1.1 Install dependencies

* [VirtualBox][virtualbox] 5.0.0 or greater.
* [Vagrant][vagrant] 1.7.4 or greater.
* [Git][git]

<!--- master only -->
### 1.2 Clone this project

    git clone https://github.com/projectcalico/calico-containers.git
<!--- else
### 1.2 Clone this project, and checkout the **release** release

    git clone https://github.com/projectcalico/calico-containers.git
    git checkout tags/**release**
<!--- end of master only -->
    
### 1.3 Startup and SSH
Change into the directory for this guide:
  
    cd calico-containers/docs/cni/rkt

Run

    vagrant up

To connect to your servers
* Linux/Mac OS X
    * run `vagrant ssh <hostname>`
* Windows
    * Follow instructions from https://github.com/nickryand/vagrant-multi-putty
    * run `vagrant putty <hostname>`

### 1.4 Verify environment

You should now have two CoreOS servers. The servers are named calico-01 and calico-02 
and have IP addresses 172.18.18.101 and 172.18.18.102.

At this point, it's worth checking that your servers can ping each other.

From calico-01

    ping 172.18.18.102

From calico-02

    ping 172.18.18.101

If you see ping failures, the likely culprit is a problem with the VirtualBox network between the VMs.  You should 
check that each host is connected to the same virtual network adapter in VirtualBox and rebooting the host may also 
help.  Remember to shut down the VMs with `vagrant halt` before you reboot.

You should also verify each host can access etcd.  The following will return an error if etcd is not available.

    curl -L http://localhost:2379/version


## 2. Starting Calico services

Once you have your cluster up and running, start Calico on both hosts

    sudo calicoctl node  --runtime=rkt

This will create a systemd unit called `calico-node` which runs the Calico components under `rkt`

You can check that it's running

	$ sudo rkt list
	UUID            APP     IMAGE NAME                              STATE   NETWORKS
	bc13af40        node    registry-1.docker.io/calico/node:latest running

You can check the status and logs using normal systemd commands e.g. `systemctl status calico-node` and `journalctl -u calico-node`

## 3. Create the networks

You can configure multiple networks when using rkt. Each network is represented by a configuration file in
`/etc/rkt/net.d/``. Connections to a given container are only allowed from containers on the same network.
Containers on multiple networks can be accessed by containers on each network that it is connected to.

To define a rkt network for Calico, create a configuration file in `/etc/rkt/net.d/`.
- Each network should be given a unique "name"
- To use Calico networking, specify "type": "calico"
- To use Calico IPAM, specify "type": "calico-ipam" in the "ipam" section.

This worked example creates two rkt networks. Run these commands on both `calico-01` and `calico-02`
```
cat >/etc/rkt/net.d/10-calico-net1.conf <<EOF
{
    "name": "net1",
    "type": "calico",
    "ipam": {
        "type": "calico-ipam"
    }
}
EOF

cat >/etc/rkt/net.d/10-calico-net2.conf <<EOF
{
    "name": "net2",
    "type": "calico",
    "ipam": {
        "type": "calico-ipam"
    }
}
EOF
```

## 4. Create a webserver on one of the networks

With the networks created, let's start a container on `calico-01`

### On calico-01
Create a webserver using an `busybox` container running an `httpd` daemon. We'll put this on `net1` network.

We'll use `systemd-run` to create the webserver service.

    sudo systemd-run --unit=httpd sudo rkt run --net=net1 registry-1.docker.io/library/busybox --exec httpd -- -f -h /
 

 Normal [systemd commands][systemd-run] can then be used to get the status of the container and view its logs. 
 
 I can take a moment to download the container. After it's come up use `rkt list` to show the IP address.
 Check the status using `sudo rkt list` or `sudo journalctl -u httpd`
  
    $ sudo rkt list
	UUID            APP     IMAGE NAME                                      STATE   NETWORKS
	65f026a5        node    registry-1.docker.io/calico/node:latest         running
	b2dd9cff        busybox registry-1.docker.io/library/busybox:latest     running net1:ip4=192.168.0.0, default-restricted:ip4=172.16.28.2

 
 So we can see that we now have a `busybox` container running on the network `net1` with an IP address of `192.168.0.0`
 rkt also creates a second network called `default-restricted`. This is used for communication with the rkt metadata service running on the host and is covered in the [rkt documentation](https://github.com/coreos/rkt/blob/master/Documentation/networking/overview.md#the-default-restricted-network)
 
## 5. Validate access to webserver

Now that we've created a webserver and we know it's IP address, we can access it using `wget` from containers running on 
either host, as long as they are created on the same network.

On calico-02 use wget to access the httpd webserver

    sudo rkt run --net=net1 registry-1.docker.io/library/busybox --exec=/bin/wget -- -T 1 192.168.0.0/etc/passwd 2>/dev/null

Expected output

   [62032.807862] wget[4]: Connecting to 192.168.0.14 (192.168.0.14:80)
   [62032.813662] wget[4]: passwd               100% |*******************************|   334   0:00:00 ETA
    

This command runs the `wget` command in a busybox container to fetch the `passwd` file from our host. '-T 1' tells wget to only wait a second for a response.
Stderr is redirected to `/dev/null` as we're not interested in the logs from `rkt` for this command.

You can repeat this command on calico-01 and check that access works the same from any server in your cluster.

### 5.1 Checking cluster isolation 
If you repeat the above command but place the container on network `net2` then the `httpd` server can no longer be reached.

    sudo rkt run --net=net2 registry-1.docker.io/library/busybox --exec=/bin/wget -- -T 1 192.168.0.0/etc/passwd 2>/dev/null
    [62128.109283] wget[4]: Connecting to 192.168.0.0 (192.168.0.0:80)
    [62129.109472] wget[4]: wget: download timed out
    
## Further reading

For details on configuring Calico for different network topologies and to
learn more about Calico under-the-covers please refer to the 
[Further Reading](../../../README.md#further-reading) section on the main
documentation README.

[systemd-run]: https://github.com/coreos/rkt/blob/master/Documentation/using-rkt-with-systemd.md#systemd-run
[virtualbox]: https://www.virtualbox.org/
[vagrant]: https://www.vagrantup.com/downloads.html
[git]: http://git-scm.com/
[![Analytics](https://ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/cni/rkt/README.md?pixel)](https://github.com/igrigorik/ga-beacon)