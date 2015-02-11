# Getting started with Calico on Docker

Calico can run in a Docker environment with L2 routed compute hosts. This brief guide shows you how to get up and running using Vagrant and VirtualBox, but any 64 bit Linux servers with a recent version of Docker and etcd (available on localhost:4001) should work.

## How to install and run it.

You can run these instructions on a Windows, Mac or Linux computer. You'll be guided through setting up a two node CoreOS cluster, creating some Calico enabled endpoints and pinging between them.

Although Vagrant/Virtualbox/CoreOS is used in these instruction, if you want to run in a different environment the requirements are minimal. You'll need Docker and an etcd cluster. If you want to get started quickly and easily then we recommend just using Vagrant.


### Initial environment setup
So, to get started, install Vagrant and Virtualbox for your OS. You'll also need Git for the CoreOS Vagrantfile.
* https://www.virtualbox.org/wiki/Downloads (no need for the extensions, just the core package)
* https://www.vagrantup.com/downloads.html
* http://git-scm.com/downloads

Follow the CoreOS instructions for setting up a cluster under Vagrant.
* https://coreos.com/docs/running-coreos/platforms/vagrant/
* In config.rb, set `$update_channel='alpha'` and `$num_instances=2`
* Don't forget to set a discovery URL in `user-data`

From your git checkout, use Vagrant to start the CoreOS servers
* `vagrant up`

You should now have three CoreOS servers, each running etcd in a cluster. The servers are named core-01 and core-02.  By default these have IP addresses 172.17.8.101 and 172.17.8.102. If you want to start again at any point, you can run

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
   * `ping 172.18.8.102`

### Using Calico
Download Calico onto each server
* wget https://github.com/Metaswitch/calico-docker/releases/download/v0.0.1/calicoctl

Calico currently requires that some components are run only on a single host. For these instructions, we'll designate core-01 our "master" node. All the hosts (including the master) will be able to run calico networked containers.

* Start the master on `core-01`
  * `sudo ./calicoctl master --ip=172.18.8.101`

Now start calico on all the nodes (substituting the correct IP)
* E.g. On core-02
   * ` sudo ./calicoctl node --ip=172.18.8.102`


This will start a container. Check they are running
* `sudo docker ps`

You should see output like this on the master

```
    core@core-01 ~ $ docker ps
    CONTAINER ID        IMAGE                      COMMAND                CREATED             STATUS              PORTS               NAMES
    TODO
```
And like this on the other hosts
```
    core@core-02 ~ $ docker ps
    CONTAINER ID        IMAGE                 COMMAND                CREATED             STATUS              PORTS               NAMES
    TODO
```

#### Creating networked endpoints
All containers need to be assigned IPs in the `192.168.0.0/16` range.

To allow networking to be set up, Docker API calls need to be routed through our proxy. The easiest way to do this is to set the environment when running docker commands.

Containers can be started using normal docker commands, but an IP address needs to be assigned. The is done by passing in an environment variable.

`DOCKER_HOST=localhost:2377 docker run -e CALICO_IP=192.168.1.1 -tid --name node1 ubuntu`

You can attach to the container created above using
* `docker attach node1`

Hit enter a few times to get a prompt. To get back out of the container and leave it running, remember to use `Ctrl-P,Q` rather than `exit`.

So, go ahead and start a few of containers on each host.
* On core-01 TODO
   * `DOCKER_HOST=localhost:2377 docker run -e CALICO_IP=192.168.1.1 -tid --name node1 busybox`
   * `DOCKER_HOST=localhost:2377 docker run -e CALICO_IP=192.168.1.2 -tid --name node2 busybox`
   * `DOCKER_HOST=localhost:2377 docker run -e CALICO_IP=192.168.1.3 -tid --name node3 busybox`
   
* On core-02
   * `DOCKER_HOST=localhost:2377 docker run -e CALICO_IP=192.168.1.4 -tid --name node4 busybox`
   * `DOCKER_HOST=localhost:2377 docker run -e CALICO_IP=192.168.1.5 -tid --name node5 busybox`

At this point, the containers have not been added to any security groups so they won't be able to communicate with any other containers.

Create two new security groups (this can be done on either host)
* ` sudo ./calicoctl addgroup GROUP1`
* ` sudo ./calicoctl addgroup GROUP2`

Now add the containers to the security groups
* TODO 
* sudo ./calicoctl addtogroup $A GROUP1

At this point, it should be possible to attach to B (`docker attach $B`) and check that it can ping C (192.168.1.3) and E (192.168.1.5) but not A or D. A and D are in their own groups so shouldn't be able to ping anyone else.


Finally, to clean everything up (without doing a `vagrant destroy`), you can run
* `sudo ./calicoctl reset`

## Troubleshooting

### Basic checks
Running `ip route` shows what routes have been programmed. Routes from other hosts should show
that they are programmed by bird.

If you have rebooted your hosts, then some configuration can get lost. It's best to run a `sudo
./calicoctl reset` and start again.

If you hit issues, please raise tickets. Diags can be collected with the `sudo ./calicoctl diags` command.
