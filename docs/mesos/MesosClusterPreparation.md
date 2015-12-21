<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-docker source tree.
>
> View the calico-docker documentation for the latest release [here](https://github.com/projectcalico/calico-docker/blob/v0.13.0/README.md).
<!--- else
> You are viewing the calico-docker documentation for release **release**.
<!--- end of master only -->

# Mesos Cluster and Master Preparation

Follow this tutorial to ensure your Mesos Master host and cluster setup are compatible with a Mesos + Calico Deployment.

## Configure your firewall
You will either need to configure the firewalls on each node in your cluster 
(recommended) to allow access to the cluster services or disable it completely. 
Included in this section is configuration examples for `firewalld` on your Master node.  If you use 
a different firewall, check your documentation for how to open the listed ports.

Master node(s) require

| Service Name | Port/protocol     |
|--------------|-------------------|
| mesos-master | 5050/tcp          |

Example `firewalld` config

```
sudo firewall-cmd --zone=public --add-port=5050/tcp --permanent
sudo systemctl restart firewalld
```

# Install ZooKeeper and etcd
> Note: Most Mesos deployments will run these services on specific, dedicated 
> machines chosen to maximize availability. These commands can be run on any 
> Centos machine, but for the purposes of this demo, we will run through them on 
> our Master to quickly and easily set up a cluster.

If you would like to quickly bring up a Mesos cluster, you can install 
Zookeeper and Etcd directly onto the master using Docker containers.

## 1. Install Docker

We install Docker to easily deploy ZooKeeper and etcd as containers.

Run the following commands to install Docker:

```
sudo yum -y install docker docker-selinux
sudo systemctl enable docker.service
sudo systemctl start docker.service
```
### Verify Docker installation

```
sudo docker run hello-world
```

### Add user to Docker Group (Optional)
You may also want to create a `docker` group and add your local user to the group.  This means you can drop the `sudo` in the `docker ...` commands that follow.

```
sudo groupadd docker
sudo usermod -aG docker `whoami`
sudo systemctl restart docker.service
```

Then log out (`exit`) and log back in to pick up your new group association.  Verify your user has access to Docker without sudo

```
docker ps
```

## 2. Launch ZooKeeper
Mesos uses ZooKeeper to elect and keep track of the leading master in the cluster.

```
sudo docker pull jplock/zookeeper:3.4.5
sudo docker run --detach --name zookeeper -p 2181:2181 jplock/zookeeper:3.4.5
```

#### Configure Firewall for ZooKeeper
ZooKeeper uses tcp over port 2181, so you'll need to open this port on your firewall.

| Service Name | Port/protocol     |
|--------------|-------------------|
| ZooKeeper    | 2181/tcp          |

Example `firewalld` config

```
sudo firewall-cmd --zone=public --add-port=2181/tcp --permanent
sudo systemctl restart firewalld
```
## 3. Launch etcd
Calico uses etcd as its data store and communication mechanism among Calico components.

etcd needs your fully qualified domain name to start correctly.

```
sudo docker pull quay.io/coreos/etcd:v2.2.0
export FQDN=`hostname -f`
sudo mkdir -p /var/etcd
sudo FQDN=`hostname -f` docker run --detach --name etcd --net host -v /var/etcd:/data quay.io/coreos/etcd:v2.2.0 \
     --advertise-client-urls "http://${FQDN}:2379,http://${FQDN}:4001" \
     --listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001" \
     --data-dir /data
```
If you have SELinux policy enforced, you must perform the following step:

```
sudo chcon -Rt svirt_sandbox_file_t /var/etcd
```

#### Configure Firewall for etcd
Etcd uses tcp over ports 2379 and 4001. You'll need to open the relevent ports on your firewall:

| Service Name | Port/protocol     |
|--------------|-------------------|
| etcd         | 4001/tcp          |

Example `firewalld` config

```
sudo firewall-cmd --zone=public --add-port=4001/tcp --permanent
sudo systemctl restart firewalld
```

# Next Steps 
With your Master configured, you're ready to [Install Calico](README.md#2-install-mesos-slave-netmodules-and-calico).

[![Analytics](https://ga-beacon.appspot.com/UA-52125893-3/calico-docker/docs/mesos/MesosClusterPreparation.md?pixel)](https://github.com/igrigorik/ga-beacon)
