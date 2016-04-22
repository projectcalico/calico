<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.19.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Running the Calico tutorials on Ubuntu using Vagrant and VirtualBox

These instructions allow you to set up an Ubuntu cluster ready to network Docker containers with 
[Calico Docker networking][calico-networking] using Vagrant.

## 1. Streamlined setup of the VMs

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

There are two worked examples you can follow: Calico as a Docker network
plugin, or Calico without Docker networking.  Select the networking option
by changing into the appropriate directory.

For Calico as a Docker network plugin
  
    cd calico-containers/docs/calico-with-docker/docker-network-plugin/vagrant-ubuntu

For Calico without Docker networking
  
    cd calico-containers/docs/calico-with-docker/without-docker-networking/vagrant-ubuntu
        
Use vagrant to create and boot your VMs.

    vagrant up

To connect to your servers
* Linux/Mac OS X
    * run `vagrant ssh <hostname>`
* Windows
    * Follow instructions from https://github.com/nickryand/vagrant-multi-putty
    * run `vagrant putty <hostname>`

### 1.4 Verify environment

You should now have two Ubuntu servers, with Etcd running on the first server.

At this point, it's worth checking that your servers can ping each other.

From calico-1

    ping 172.17.8.102

From calico-2

    ping 172.17.8.101

If you see ping failures, the likely culprit is a problem with the VirtualBox network between the VMs.  You should 
check that each host is connected to the same virtual network adapter in VirtualBox and rebooting the host may also 
help.  Remember to shut down the VMs with `vagrant halt` before you reboot.

You should also verify each host can access etcd.  The following will return an error if etcd is not available.

    curl -L http://$ETCD_AUTHORITY/version

And finally check that Docker is running on both hosts by running

    docker ps

## 2. Try out Calico Networking

Now you have a basic two node Ubuntu cluster setup and you are ready to try Calico networking.

There are two worked examples you can follow: Calico as a Docker network
plugin, or Calico without Docker networking.  Select the instructions based on 
the networking option that you chose in step (1.3).

- [Calico as a Docker network plugin walkthrough](docker-network-plugin/README.md) 
- [Calico without Docker networking walkthrough](without-docker-networking/README.md)  

[libnetwork]: https://github.com/docker/libnetwork
[experimental-channel]: https://github.com/docker/docker/tree/master/experimental
[virtualbox]: https://www.virtualbox.org/
[vagrant]: https://www.vagrantup.com/downloads.html
[git]: http://git-scm.com/
[calico-networking]: https://github.com/projectcalico/calico-containers
[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/calico-with-docker/VagrantUbuntu.md?pixel)](https://github.com/igrigorik/ga-beacon)
