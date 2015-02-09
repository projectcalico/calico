# Getting started with Calico on Docker

Calico can run in a Docker environment with L2 routed compute hosts. This brief guide shows you
how to get up and running using Vagrant and VirtualBox.

## How to install and run it.

You can run these instructions on a Windows, Mac or Linux computer. You'll be guided through
setting up a two node CoreOS cluster, creating some Calico enabled endpoints and pinging between them.

Although Vagrant/Virtualbox/CoreOS is used in these instruction, if you want to run in a different environment the requirements are minimal. You'll
need Docker and an etcd cluster. If you want to get started quickly and easily then we recommend just
using Vagrant.


### Initial environment setup
So, to get started, install Vagrant and Virtualbox for your OS. You'll also need Git for the CoreOS Vagrantfile.
* https://www.virtualbox.org/wiki/Downloads (no need for the extensions, just the core package)
* https://www.vagrantup.com/downloads.html
* http://git-scm.com/downloads

Follow the CoreOS instructions for setting up a cluster under Vagrant.
* https://coreos.com/docs/running-coreos/platforms/vagrant/
* In config.rb, set `$update_channel='alpha'` and `$num_instances=3`
* Don't forget to set a discovery URL in `user-data`

From your git checkout, use Vagrant to start the CoreOS servers
* `vagrant up`

You should now have three CoreOS servers, each running etcd in a cluster. The servers are named core-01, core-02, core-03.  By default these have IP addresses 172.17.8.101, 172.17.8.102 and 172.17.8.103. If you want to start again at any point, you can run

* `vagrant destroy`
* `vagrant up`

To connect to your servers
* Linux/MacOSX
   * `vagrant ssh <hostname>`
* Windows
   * Follow instructions from https://github.com/nickryand/vagrant-multi-putty
   * `vagrant putty <hostname>`
   * `vagrant putty core-02`

At this point, it's worth checking that your servers can ping each other.
* e.g. From core-01
   * `ping 172.18.8.102`

### Using Calico
Download Calico onto each server
* TODO

Calico currently requires that some components are run only on a single host. For these instructions, we'll designate core-01 our "master" node. All three containers will be able to run calico networked containers.

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

To allow networking to be set up, Docker API calls need to be routed through our proxy. The easiest way to do this is to export an environment variable.
And pass in CALICO_IP too.
CALICO_IP

You can attach to the container created above using
* `docker attach $CID`

Hit enter a few times to get a prompt. To get back out of the container and leave it running, remember to use `Ctrl-P,Q` rather than `exit`.

So, go ahead and start a few of containers on each host.
* On core-01 TODO
   * `A=$(sudo ./calicoctl run 192.168.1.1 --master=core-01 --group=ONLY_A -- -ti busybox)`
   * `B=$(sudo ./calicoctl run 192.168.1.2 --master=core-01 -- -ti busybox)`
   * `C=$(sudo ./calicoctl run 192.168.1.3 --master=core-01 -- -ti busybox)`

* On core-02
   * `D=$(sudo ./calicoctl run 192.168.1.4 --master=core-01 --group=ONLY_D-- -ti busybox)`
   * `E=$(sudo ./calicoctl run 192.168.1.5 --master=core-01 -- -ti busybox)`

B,C and E are created without passing in an explicit group name so they are all in the `DEFAULT` group.

At this point, it should be possible to attach to B (`docker attach $B`) and check that it can ping C (192.168.1.3) and E (192.168.1.5) but not A or D. A and D are in their own groups so shouldn't be able to ping anyone else.


Finally, to clean everything up (without doing a `vagrant destroy`), you can run
* `sudo ./calicoctl reset`

## Troubleshooting

### Basic checks
Running `ip route` shows what routes have been programmed. Routes from other hosts should show
that they are programmed by bird.

If you have rebooted your hosts, then some configuration can get lost. It's best to run a `sudo
./calicoctl reset` and start again.

If you hit issues, please raise tickets. Diags can be collected with the `diags.sh` command.
