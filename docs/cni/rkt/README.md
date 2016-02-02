<!--- master only -->
> ![warning](../../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.14.0/README.md).
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
Create a webserver using an `nginx` container. We'll put this on `net1` network.

We'll use `systemd-run` to create the webserver service.

    sudo systemd-run --unit=nginx rkt run --store-only=true --insecure-options=image --net=net1 --mount volume=myvol,target=/var/run --volume=myvol,kind=empty docker://nginx
 

 Normal [systemd commands][systemd-run] can then be used to get the status of the container and view its logs. 
 
 I can take a moment to download the container. After it's come up use `rkt list` to show the IP address.
 Check the status using `sudo rkt list` or `sudo journalctl -u nginx`
  
    $ sudo rkt list
	UUID            APP     IMAGE NAME                                      STATE   NETWORKS
	65f026a5        node    registry-1.docker.io/calico/node:latest         running
	b2dd9cff        nginx   registry-1.docker.io/library/nginx:latest       running net1:ip4=192.168.0.0, default-restricted:ip4=172.16.28.2

 
 So we can see that we now have an `nginx` container running on the network `net1` with an IP address of `192.168.0.0`
 rkt also creates a second network called `default-restricted`. This is used for communication with the rkt metadata service running on the host and is covered in the [rkt documentation](https://github.com/coreos/rkt/blob/master/Documentation/networking.md#the-default-restricted-network)
 
## 5. Validate access to webserver

Now that we've created a webserver and we know it's IP address, we can access it using `wget` from containers running on 
either host, as long as they are created on the same network.

On calico-02 use wget to access the nginx webserver

    sudo rkt run --net=net1 --store-only=true --insecure-options=image docker://busybox --exec=/bin/wget -- -T 1 -q -O - 192.168.0.0 2>/dev/null

Expected output

    [ 1808.316525] wget[4]: <!DOCTYPE html>
    [ 1808.316988] wget[4]: <html>
    [ 1808.317384] wget[4]: <head>
    [ 1808.317723] wget[4]: <title>Welcome to nginx!</title>
    [ 1808.318226] wget[4]: <style>
    [ 1808.318592] wget[4]: body {
    [ 1808.318958] wget[4]: width: 35em;
    [ 1808.319457] wget[4]: margin: 0 auto;
    [ 1808.319833] wget[4]: font-family: Tahoma, Verdana, Arial, sans-serif;
    [ 1808.320416] wget[4]: }
    [ 1808.320793] wget[4]: </style>
    [ 1808.321261] wget[4]: </head>
    [ 1808.321655] wget[4]: <body>
    [ 1808.322086] wget[4]: <h1>Welcome to nginx!</h1>
    [ 1808.322549] wget[4]: <p>If you see this page, the nginx web server is successfully installed and
    [ 1808.322918] wget[4]: working. Further configuration is required.</p>
    [ 1808.323476] wget[4]: <p>For online documentation and support please refer to
    [ 1808.323855] wget[4]: <a href="http://nginx.org/">nginx.org</a>.<br/>
    [ 1808.334445] wget[4]: Commercial support is available at
    [ 1808.335309] wget[4]: <a href="http://nginx.com/">nginx.com</a>.</p>
    [ 1808.335545] wget[4]: <p><em>Thank you for using nginx.</em></p>
    [ 1808.335777] wget[4]: </body>
    [ 1808.336030] wget[4]: </html>

    

This command runs the `wget` command in a busybox container, telling `wget` to be quiet, to only wait a second for a response and to output to stdout. 
Stderr is redirected to `/dev/null` as we're not interested in the logs from `rkt` for this command.

You can repeat this command on calico-01 and check that access works the same from any server in your cluster.

### 5.1 Checking cluster isolation 
If you repeat the above command but place the container on network `net2` then the `nginx` server can no longer be reached.

    sudo rkt run --net=net2 --insecure-options=image docker://busybox --exec=/bin/wget -- -T 1 -q -O - 192.168.0.0 2>/dev/null 
    [ 1856.858027] wget[4]: wget: download timed out
    
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