<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-docker source tree.
>
> View the calico-docker documentation for the latest release [here](https://github.com/projectcalico/calico-docker/blob/v0.9.0/README.md).
<!--- else
> You are viewing the calico-docker documentation for release **release**.
<!--- end of master only -->

# Set up Calico on CoreOS using Vagrant

These instructions allow you to set up a CoreOS cluster ready to network Docker containers with 
[Calico Docker networking][calico-networking] using Vagrant.

## Streamlined setup

1) Install dependencies

* [VirtualBox][virtualbox] 5.0.0 or greater.
* [Vagrant][vagrant] 1.7.4 or greater.
* [Git][git]

<!--- master only -->
2) Clone this project

    git clone https://github.com/projectcalico/calico-docker.git
<!--- else
2) Clone this project, and checkout the **release** release

    git clone https://github.com/projectcalico/calico-docker.git
    git checkout tags/**release**
<!--- end of master only -->
    
3) There are two demonstration options depending on whether you are running with libnetwork or 
the default Docker networking.  Select the required demonstration by changing into the appropriate directory:

  - For default Docker networking
  
    ```cd calico-docker/docs/getting-started/default-networking/vagrant-coreos```
    
  - For libnetwork
  
    ```cd calico-docker/docs/getting-started/libnetwork/vagrant-coreos```
    
4) Startup and SSH

Run

    vagrant up

To connect to your servers
* Linux/Mac OS X
    * run `vagrant ssh <hostname>`
* Windows
    * Follow instructions from https://github.com/nickryand/vagrant-multi-putty
    * run `vagrant putty <hostname>`

5) Verify environment

You should now have two CoreOS servers, each running etcd in a cluster. The servers are named calico-01 and calico-02 
and IP addresses 172.17.8.101 and 172.17.8.102.

At this point, it's worth checking that your servers can ping each other.

From calico-01

    ping 172.17.8.102

From calico-02

    ping 172.17.8.101

If you see ping failures, the likely culprit is a problem with the VirtualBox network between the VMs.  You should 
check that each host is connected to the same virtual network adapter in VirtualBox and rebooting the host may also 
help.  Remember to shut down the VMs with `vagrant halt` before you reboot.

You should also verify each host can access etcd.  The following will return an error if etcd is not available.

    curl -L http://$ETCD_AUTHORITY/version

And finally check that Docker is running on both hosts by running

    docker ps
    
## Try out Calico networking
Now you have a basic two node CoreOS cluster setup and you are ready to try Calico networking.

You can now run through the standard Calico demonstration.  There are two demonstration options depending on 
whether you are running with libnetwork or the default Docker networking.

- [demonstration with Docker default networking](default-networking/Demonstration.md)
- [demonstration with libnetwork](libnetwork/Demonstration.md) 


[calico-networking]: https://github.com/projectcalico/calico-docker
[virtualbox]: https://www.virtualbox.org/
[vagrant]: https://www.vagrantup.com/downloads.html
[using-coreos]: http://coreos.com/docs/using-coreos/
[git]: http://git-scm.com/
