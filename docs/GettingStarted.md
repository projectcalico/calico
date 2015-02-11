# Getting started with Calico on Docker

Calico provide IP connectivity between Docker containers on different hosts. This brief guide shows you how to get up and running using Vagrant and VirtualBox, but any 64 bit Linux servers with a recent version of Docker and etcd (available on localhost:4001) should work. If you want to get started quickly and easily then we recommend just using Vagrant.

## How to install and run it.

You can run these instructions on a Windows, Mac or Linux computer. You'll be guided through setting up a two node CoreOS cluster, creating some Calico enabled endpoints and pinging between them. If you've never used Vagrant, CoreOS or Etcd before then we recommend skimming their docs before running through these instructions.

### Initial environment setup
So, to get started, install Vagrant and Virtualbox for your OS. You'll also need Git to get hold of the CoreOS Vagrantfile.
* https://www.virtualbox.org/wiki/Downloads (no need for the extensions, just the core package)
* https://www.vagrantup.com/downloads.html
* http://git-scm.com/downloads

Follow the CoreOS instructions for setting up a cluster under Vagrant.
* https://coreos.com/docs/running-coreos/platforms/vagrant/
* In config.rb, set `$update_channel='alpha'` and `$num_instances=2`
* Don't forget to set a discovery URL in `user-data`

From your git checkout, use Vagrant to start the CoreOS servers
* `vagrant up`

You should now have two CoreOS servers, each running etcd in a cluster. The servers are named core-01 and core-02.  By default these have IP addresses 172.17.8.101 and 172.17.8.102. If you want to start again at any point, you can run

* `vagrant destroy`
* `vagrant up`

To connect to your servers
* Linux/MacOSX
   * `vagrant ssh <hostname>`
* Windows
   * Follow instructions from https://github.com/nickryand/vagrant-multi-putty
   * `vagrant putty <hostname>`

At this point, it's worth checking that your servers can ping each other.
* e.g. From core-01
   * `ping 172.17.8.102`

### Using Calico
Download Calico onto both servers by SSHing onto them and running
* wget https://github.com/Metaswitch/calico-docker/releases/download/v0.0.3/calicoctl
* chmod +x calicoctl

Calico requires some components to be run only on a single host. For these instructions, we'll designate core-01 our "master" node. All the hosts (including the master) will be able to run calico networked containers.

* Start the master on `core-01`
  * `sudo ./calicoctl master --ip=172.17.8.101`

Now start calico on all the nodes (only do this after the master is started)
* On core-01
   * ` sudo ./calicoctl node --ip=172.17.8.101`
* On core-02
   * ` sudo ./calicoctl node --ip=172.17.8.102`

This will start a container. Check they are running
* `sudo docker ps`

You should see output like this on the master

```
    core@core-01 ~ $ docker ps
    CONTAINER ID        IMAGE                      COMMAND                CREATED             STATUS              PORTS               NAMES
    077ceae44fe3        calico/node:latest     "/sbin/my_init"     About a minute ago   Up About a minute                       calico-node
    17a54cc8f88a        calico/master:latest   "/sbin/my_init"     35 minutes ago       Up 35 minutes                           calico-master

```
And like this on the other hosts
```
    core@core-02 ~ $ docker ps
    CONTAINER ID        IMAGE                 COMMAND                CREATED             STATUS              PORTS               NAMES
    f770a8acbb11        calico/node:latest   "/sbin/my_init"     About a minute ago   Up About a minute                       calico-node

```

#### Creating networked endpoints
All containers need to be assigned IPs in the `192.168.0.0/16` range.

To allow networking to be set up during container creation, Docker API calls need to be routed through the `Powerstrip` proxy which is running on port `2377` on each node. The easiest way to do this is to set the environment before running docker commands.

On both hosts run
* export DOCKER_HOST=localhost:2377

(Note - this export will only persist for your current SSH session)

Containers can now be started using normal docker commands, but an IP address needs to be assigned. The is done by passing in an environment variable. e.g. `docker run -e CALICO_IP=192.168.1.1 -tid --name node1 busybox`

You need to connect directly to docker to attach to containers. This can be done like this
* `DOCKER_HOST=localhost:2375 docker attach node1`

Hit enter a few times to get a prompt. To get back out of the container and leave it running, remember to use `Ctrl-P,Q` rather than `exit`.

So, go ahead and start a few of containers on each host.
* On core-01
   * `A=$(docker run -e CALICO_IP=192.168.1.1 -td busybox)`
   * `B=$(docker run -e CALICO_IP=192.168.1.2 -td busybox)`
   * `C=$(docker run -e CALICO_IP=192.168.1.3 -td busybox)`
   
* On core-02
   * `D=$(docker run -e CALICO_IP=192.168.1.4 -td busybox)`
   * `E=$(docker run -e CALICO_IP=192.168.1.5 -td busybox)`

At this point, the containers have not been added to any security groups so they won't be able to communicate with any other containers.

Create some security groups (this can be done on either host)
* ` sudo ./calicoctl addgroup GROUP_A_C_E`
* ` sudo ./calicoctl addgroup GROUP_B`
* ` sudo ./calicoctl addgroup GROUP_D`

Now add the containers to the security groups
On core-01
* `sudo ./calicoctl addtogroup $A GROUP_A_C_E`
* `sudo ./calicoctl addtogroup $B GROUP_B`
* `sudo ./calicoctl addtogroup $C GROUP_A_C_E`

On core-02
* `sudo ./calicoctl addtogroup $D GROUP_D`
* `sudo ./calicoctl addtogroup $E GROUP_A_C_E`

At this point, it should be possible to attach to A (`DOCKER_HOST=localhost:2377 docker attach $A`) and check that it can ping C (192.168.1.3) and E (192.168.1.5) but not B or D. B and D are in their own groups so shouldn't be able to ping anyone else.

Finally, to clean everything up (without doing a `vagrant destroy`), you can run
* `sudo ./calicoctl reset`

## Troubleshooting

### Basic checks
Running `ip route` shows what routes have been programmed. Routes from other hosts should show that they are programmed by bird.

If you have rebooted your hosts, then some configuration can get lost. It's best to run a `sudo ./calicoctl reset` and start again.

If you hit issues, please raise tickets. Diags can be collected with the `sudo ./calicoctl diags` command.
