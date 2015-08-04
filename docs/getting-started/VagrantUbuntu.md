
# Set up Calico on Ubuntu using Vagrant

These instructions allow you to set up an Ubuntu cluster ready to network Docker containers with 
[Calico Docker networking][calico-networking] using Vagrant.

## Streamlined setup

1) Install dependencies

* [VirtualBox][virtualbox] 5.0.0 or greater.
* [Vagrant][vagrant] 1.7.4 or greater.
* [Git][git]

2) Clone this project

    git clone https://github.com/Metaswitch/calico-docker.git
    
3) There are three demonstration options depending on whether you are running with libnetwork, Powerstrip or the
   default Docker networking.  Select the required demonstration by changing into the appropriate directory:

  - For Docker default networking
  
    ```cd calico-docker/docs/getting-started/default-networking/vagrant-ubuntu```
    
  - For libnetwork
  
    ```cd calico-docker/docs/getting-started/libnetwork/vagrant-ubuntu```
    
  - For Powerstrip
  
    ```cd calico-docker/docs/getting-started/powerstrip/vagrant-ubuntu```

4) Startup and SSH

Use vagrant to create and boot your VMs.

    vagrant up

To connect to your servers
* Linux/Mac OS X
    * run `vagrant ssh <hostname>`
* Windows
    * Follow instructions from https://github.com/nickryand/vagrant-multi-putty
    * run `vagrant putty <hostname>`

5) Verify environment

You should now have two Ubuntu servers, with Consul and Etcd running on the first server.

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

## Try out Calico Networking

Now you have a basic two node Ubuntu cluster setup and you are ready to try Calico networking.

You can now run through the standard Calico demonstration.  There are three demonstration options depending on 
whether you are running with libnetwork, Powerstrip or the default Docker networking.

- [demonstration with Docker default networking](default-networking/Demonstration.md)
- [demonstration with libnetwork](libnetwork/Demonstration.md)
- [demonstration with Powerstrip](powerstrip/Demonstration.md)

[libnetwork]: https://github.com/docker/libnetwork
[experimental-channel]: https://github.com/docker/docker/tree/master/experimental
[calico-ubuntu-vagrant]: https://github.com/Metaswitch/calico-ubuntu-vagrant-example
[virtualbox]: https://www.virtualbox.org/
[vagrant]: https://www.vagrantup.com/downloads.html
[git]: http://git-scm.com/
[calico-networking]: https://github.com/Metaswitch/calico-docker
