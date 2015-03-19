# Getting started with Calico on Docker

Calico provide IP connectivity between Docker containers on different hosts. This brief guide shows you how to get up and running using Vagrant and VirtualBox, but any 64 bit Linux servers with a recent version of Docker and etcd (available on localhost:4001) should work. If you want to get started quickly and easily then we recommend just using Vagrant.

## How to install and run it.

You can run these instructions on a Windows, Mac or Linux computer. You'll be guided through setting up a two node CoreOS cluster, creating some Calico enabled endpoints and pinging between them. If you've never used Vagrant, CoreOS or Etcd before then we recommend skimming their docs before running through these instructions.

### Initial environment setup
So, to get started, install Vagrant, Virtualbox and Git for your OS.
* https://www.virtualbox.org/wiki/Downloads (no need for the extensions, just the core package)
* https://www.vagrantup.com/downloads.html
* http://git-scm.com/downloads

Use the customized CoreOS-based Vagrant file from https://github.com/Metaswitch/calico-coreos-vagrant-example for streamlined setup. Follow the instructions there (and see the <a href="https://coreos.com/docs/running-coreos/platforms/vagrant/">CoreOS documentation</a>).

You should now have two CoreOS servers, each running etcd in a cluster. The servers are named core-01 and core-02.  By default these have IP addresses 172.17.8.101 and 172.17.8.102. If you want to start again at any point, you can run

* `vagrant destroy`
* If you manually set the discovery URL in `user-data`, replace it with a fresh one.
* `vagrant up`

To connect to your servers
* Linux/MacOSX
   * `vagrant ssh <hostname>`
* Windows
   * Follow instructions from https://github.com/nickryand/vagrant-multi-putty
   * `vagrant putty <hostname>`

At this point, it's worth checking that your servers can ping each other reliably.
* From core-01
```
ping 172.17.8.102
```
* From core-02
```
ping 172.17.8.101
```

If you see ping failures, the likely culprit is a problem with then Virtualbox network between the VMs.  Rebooting the host may help.  Remember to shut down the VMs first with `vagrant halt` before you reboot.
   
### Installing Calico
If you didn't use the calico-coreos-vagrant-example Vagrantfile, you'll need to download Calico onto both servers by SSHing onto them and running
```
wget https://github.com/Metaswitch/calico-docker/releases/download/v0.1.0/calicoctl
chmod +x calicoctl
```
Now start calico on all the nodes
* On core-01
```
sudo ./calicoctl node --ip=172.17.8.101
```
* On core-02
```
sudo ./calicoctl node --ip=172.17.8.102
```

This will start a container. Check they are running
```
sudo docker ps
```

You should see output like this on each node

```
core@core-01 ~ $ docker ps
CONTAINER ID        IMAGE                      COMMAND                CREATED             STATUS              PORTS               NAMES
077ceae44fe3        calico/node:v0.1.0     "/sbin/my_init"     About a minute ago   Up About a minute                       calico-node
```

#### Using Calico: Creating networked endpoints
By default containers need to be assigned IPs in the `192.168.0.0/16` range. (Use `calicoctl` commands to set up different ranges if desired)

To allow networking to be set up during container creation, Docker API calls need to be routed through the `Powerstrip` proxy which is running on port `2377` on each node. The easiest way to do this is to set the environment before running docker commands.

On both hosts run
```
export DOCKER_HOST=localhost:2377
```

(Note - this export will only persist for your current SSH session)

Containers can now be started using normal docker commands, but an IP address needs to be assigned. The is done by passing in an environment variable. e.g. `docker run -e CALICO_IP=192.168.1.1 -tid --name node1 busybox`

You need to connect directly to docker to attach to containers. This can be done like this
```
DOCKER_HOST=localhost:2375 docker attach node1
```

Hit enter a few times to get a prompt. To get back out of the container and leave it running, remember to use `Ctrl-P,Q` rather than `exit`.

So, go ahead and start a few of containers on each host.
* On core-01
```
docker run -e CALICO_IP=192.168.1.1 --name workload-A -tid busybox
docker run -e CALICO_IP=192.168.1.2 --name workload-B -tid busybox
docker run -e CALICO_IP=192.168.1.3 --name workload-C -tid busybox
```
* On core-02
```
docker run -e CALICO_IP=192.168.1.4 --name workload-D -tid busybox
docker run -e CALICO_IP=192.168.1.5 --name workload-E -tid busybox
```

At this point, the containers have not been added to any security groups so they won't be able to communicate with any other containers.

Create some security groups (this can be done on either host)
```
sudo ./calicoctl group add GROUP_A_C_E
sudo ./calicoctl group add GROUP_B
sudo ./calicoctl group add GROUP_D
```

Now add the containers to the security groups (note that `group add` works from any Calico node, but `group addmember` only works from the Calico node where the container is hosted).
On core-01
```
sudo ./calicoctl group addmember GROUP_A_C_E workload-A
sudo ./calicoctl group addmember GROUP_B  workload-B
sudo ./calicoctl group addmember GROUP_A_C_E workload-C
```

On core-02
```
sudo ./calicoctl group addmember GROUP_D workload-D
sudo ./calicoctl group addmember GROUP_A_C_E workload-E
```

Now, check that A can ping C (192.168.1.3) and E (192.168.1.5)
```
docker exec workload-A ping -c 4 192.168.1.3
docker exec workload-A ping -c 4 192.168.1.5
```

Also check that A cannot ping B (192.168.1.2) or D (192.168.1.4).
```
docker exec workload-A ping -c 4 192.168.1.2
docker exec workload-A ping -c 4 192.168.1.4
```

B and D are in their own groups so shouldn't be able to ping anyone else.

Finally, to clean everything up (without doing a `vagrant destroy`), you can run
```
sudo ./calicoctl reset
```

## IPv6
To connect your containers with IPv6, first make sure your Docker hosts each have an IPv6 address assigned.

On core-01
```
sudo ip addr add fd80:24e2:f998:72d6::1/112 dev eth1
```

On core-02
```
sudo ip addr add fd80:24e2:f998:72d6::2/112 dev eth1
```

Verify connectivity by pinging

On core-01
```
ping6 fd80:24e2:f998:72d6::2
```

Then restart your calico-node processes with the `--ip6` parameter to enable v6 routing.

On core-01
```
sudo ./calicoctl node --ip=172.17.8.101 --ip6=fd80:24e2:f998:72d6::1
```

On core-02
```
sudo ./calicoctl node --ip=172.17.8.102 --ip6=fd80:24e2:f998:72d6::2
```

Then, you can start containers with IPv6 connectivity by giving them an IPv6 address in `CALICO_IP`. By default, Calico is configured to use IPv6 addresses in the pool fd80:24e2:f998:72d6/64 (`calicoctl ipv6 pool add` to change this).

On core-01
```
docker run -e CALICO_IP=fd80:24e2:f998:72d6::1:1 --name workload-F -tid phusion/baseimage:0.9.16
sudo ./calicoctl group add GROUP_F_G
sudo ./calicoctl group addmember GROUP_F_G workload-F
```

Note that we have used `phusion/baseimage:0.9.16` instead of `busybox`.  Busybox doesn't support IPv6 versions of network tools like ping.  Baseimage was chosen since it is the base for the Calico service images, and thus won't require an additional download, but of course you can use whatever image you'd like.

One core-02
```
docker run -e CALICO_IP=fd80:24e2:f998:72d6::1:2 --name workload-G -tid phusion/baseimage:0.9.16
sudo ./calicoctl group addmember GROUP_F_G workload-G
docker exec workload-G ping6 -c 4 fd80:24e2:f998:72d6::1:1
```


## Troubleshooting

### Basic checks
Running `ip route` shows what routes have been programmed. Routes from other hosts should show that they are programmed by bird.

If you have rebooted your hosts, then some configuration can get lost. It's best to run a `sudo ./calicoctl reset` and start again.

If your hosts reboot themselves with a message from `locksmithd` your cached CoreOS image is out of date.  Use `vagrant box update` to pull the new version.  I recommend doing a `vagrant destroy; vagrant up` to start from a clean slate afterwards.

If you hit issues, please raise tickets. Diags can be collected with the `sudo ./calicoctl diags` command.
