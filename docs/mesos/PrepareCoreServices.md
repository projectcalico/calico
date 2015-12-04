# Prepare Core Services for Mesos + Calico Deployment
*Most Mesos clusters will run these services on specific, dedicated machines chosen to maximize availability.*

## Docker

- **Docker must be installed on each Mesos Agent** that is deploying calico via the packaged Calico container (recommended). Users who prefer to [run Calico as a baremetal service](#) do not need to install Docker on each Agent.
- **Docker must be installed on Mesos Master** if etcd and ZooKeeper are being deployed as Docker containers. Users who are running etcd / ZooKeeper elsewhere do not need to install Docker on each Master.

Run the following commands to install Docker:

    $ sudo yum -y install docker docker-selinux
    $ sudo systemctl enable docker.service
    $ sudo systemctl start docker.service

### Verify Docker installation

    $ sudo docker run hello-world

*Optional:* You may also want to create a `docker` group and add your local user to the group.  This means you can drop the `sudo` in the `docker ...` commands that follow.

    $ sudo groupadd docker
    $ sudo usermod -aG docker `whoami`
    $ sudo systemctl restart docker.service

Then log out (`exit`) and log back in to pick up your new group association.  Verify your user has access to Docker without sudo

    $ docker ps

## ZooKeeper
Mesos uses ZooKeeper to elect and keep track of the leading master in the cluster.

    $ sudo docker pull jplock/zookeeper:3.4.5
    $ sudo docker run --detach --name zookeeper -p 2181:2181 jplock/zookeeper:3.4.5

*If you have a firewall configured on the host running ZooKeeper, open port 2181 to allow incoming and outgoing tcp traffic. See our [Host Preparation Guide](PrepareHosts.md) for more details on firewall configuration.*

## etcd
Calico uses etcd as its data store and communication mechanism among Calico components.

etcd needs your fully qualified domain name to start correctly.

    $ sudo docker pull quay.io/coreos/etcd:v2.2.0
    $ export FQDN=`hostname -f`
    $ sudo mkdir -p /var/etcd
    $ sudo FQDN=`hostname -f` docker run --detach --name etcd --net host -v /var/etcd:/data quay.io/coreos/etcd:v2.2.0 \
     --advertise-client-urls "http://${FQDN}:2379,http://${FQDN}:4001" \
     --listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001" \
     --data-dir /data

If you have SELinux policy enforced, you must perform the following step:

    $ sudo chcon -Rt svirt_sandbox_file_t /var/etcd

*If you have a firewall configured on the host running etcd, open ports 2379 and 4001 to allow incoming and outgoing tcp traffic. See our [Host Preparation Guide](PrepareHosts.md) for more details on firewall configuration.*
[![Analytics](https://ga-beacon.appspot.com/UA-52125893-3/calico-docker/docs/mesos/PrepareCoreServices.md?pixel)](https://github.com/igrigorik/ga-beacon)
