# Getting started with Calico on Docker

Calico can run in a Docker environment with L2 routed compute hosts. This brief guide shows you
how to get up and running using Vagrant and VirtualBox.

## How to install and run it.

You can run these instructions on a Windows, Mac or Linux computer. You'll be guided through
setting up a two node CoreOS cluster, creating some Calico enabled endpoints and pinging between
 them.

Although Vagrant/Virtualbox/CoreOS is used, the environmental requirements are minimal. You'll
obviously need Docker and Git and we currently rely on some SSH keys and host file settings -
see XXX for more details. If you want to get started quickly and easily then we recommend just
using Vagrant.


### Initial environment setup
So, to get started, install Vagrant, Virtualbox and GIt for your OS.
* https://www.virtualbox.org/wiki/Downloads (no need for the extensions, just the core package)
* https://www.vagrantup.com/downloads.html
* http://git-scm.com/downloads

Clone this repo so the Vagrant file is available.
* `git clone https://github.com/metaswitch/calico-docker.git`

From your git checkout, use Vagrant to start the CoreOS servers
* `vagrant up`

Congratulations, you now have two CoreOS servers with the Calico code checked out on them. The servers are named core-01 and core-02.  By default these have IP addresses 172.17.8.101 and 172.17.8.102. If you want to start again at any point, you can run

* `vagrant destroy`
* `vagrant up`

To connect to your servers
* Linux/MacOSX
   * `vagrant ssh core-01`
   * `vagrant ssh core-02`
* Windows
   * Follow instructions from https://github.com/nickryand/vagrant-multi-putty
   * `vagrant putty core-01`
   * `vagrant putty core-02`

At this point, it's worth checking that your two servers can ping each other.
* From core-01
   * `ping core-02`
* From core-02
   * `ping core-01`

### Using Calico
Calico currently requires that some components are run only on a single host. For this prototype, we'll designate core-01 our "master" node and core-02 will be a secondary node.

* Start the master on `core-01`
  * `sudo ./calico master --peer=core-02`

Now start calico on both nodes.
* On core-01
   * ` sudo ./calico launch --master=core-01 --peer=core-01`
* On core-02
   * ` sudo ./calico launch --master=core-01 --peer=core-02`

This will start a number of Docker containers. Check they are running
* `sudo docker ps`

    core@core-01 ~ $ docker ps
    CONTAINER ID        IMAGE                      COMMAND                CREATED             STATUS              PORTS               NAMES
    96ccc60e25ef        calico_bird:latest         "bird -s bird.ctl -d   2 minutes ago       Up 2 minutes                            calico_bird_1
    a37bf51c9fef        calico_aclmanager:latest   "calico-felix --conf   2 minutes ago       Up 2 minutes                            calico_felix_1
    46132f56423b        calico_pluginep:latest     "python plugin.py ne   6 minutes ago       Up 6 minutes                            calico_pluginnetwork_1
    5235f9168feb        calico_aclmanager:latest   "calico-acl-manager    6 minutes ago       Up 6 minutes                            calico_aclmanager_1
    e14b53b79962        calico_pluginep:latest     "python plugin.py ep   6 minutes ago       Up 6 minutes                            calico_pluginep_1


    core@core-02 ~ $ docker ps
    CONTAINER ID        IMAGE                 COMMAND                CREATED             STATUS              PORTS               NAMES
    37f41d95e69d        calico_bird:latest    "bird -s bird.ctl -d   4 minutes ago       Up 4 minutes                            calico_bird_1
    bb14fc3f8dce        calico_felix:latest   "calico-felix --conf   4 minutes ago       Up 4 minutes                            calico_felix_1


#### Creating networked endpoints
All containers need to be assigned IPs in the `192.168.0.0/16` range.

The general way to start a new container:  (Hint: don't run this yet; specific examples to run below.)
* `CID=$(sudo ./calico run CONTAINER_IP --master=MASTER [--group=GROUP] -- DOCKER_OPTIONS)`
    * `CONTAINER_IP`, is the IP address to assign to the container; this must be unique address from the 192.168.0.0/16 range.
    * `--master` points at the address of the master node.
    * `GROUP` is the name of the group.  Only containers in the same group can ping each other, groups are created on-demand so you can choose any name here. If you don't supply a group then the `DEFAULT` group is used.
    * DOCKER_OPTIONS are passed through to Docker, e.g. `-ti busybox` to start an interactive busybox container.
    * `CID` will be set to the container ID of the new container.

You can attach to the container created above using
* `docker attach $CID`

Hit enter a few times to get a prompt. To get back out of the container and leave it running, remember to use `Ctrl-P,Q` rather than `exit`.

So, go ahead and start a few of containers on each host.
* On core-01
   * `A=$(sudo ./calico run 192.168.1.1 --master=core-01 --group=ONLY_A -- -ti busybox)`
   * `B=$(sudo ./calico run 192.168.1.2 --master=core-01 -- -ti busybox)`
   * `C=$(sudo ./calico run 192.168.1.3 --master=core-01 -- -ti busybox)`

* On core-02
   * `D=$(sudo ./calico run 192.168.1.4 --master=core-01 --group=ONLY_E-- -ti busybox)`
   * `E=$(sudo ./calico run 192.168.1.5 --master=core-01 -- -ti busybox)`

B,C and E are created without passing in an explicit group name so they are all in the `DEFAULT` group.

At this point, it should be possible to attach to B (`docker attach $B`) and check that it can ping C (192.168.1.3) and E (192.168.1.5) but not A or D. A and D are in their own groups so shouldn't be able to ping anyone else.


Finally, to clean everything up (without doing a `vagrant destroy`), you can run
* `sudo ./calico reset`

## Troubleshooting

### Basic checks
Running `ip route` shows what routes have been programmed. Routes from other hosts should show
that they are programmed by bird.

If you have rebooted your hosts, then some configuration can get lost. It's best to run a `sudo
./calico reset` and start again.

If you hit issues, please raise tickets. Diags can be collected with the `diags.sh` command.
