# Mesos Host Preparation
#### Follow this guide to ensure your hosts are compatible with a Mesos + Calico Deployment 

## 1. Set & verify fully qualified domain name
These instructions assume each host can reach other hosts using their fully qualified domain names (FQDN).  To check the FQDN on a host use

    $ hostname -f

Then attempt to ping that name from other hosts.

Also important are that Calico and Mesos have the same view of the (non-fully-qualified) hostname.  Ensure that the value returned by `$ hostname` is unique for each host in your cluster.

## 2. Configure your firewall
You will either need to configure the firewalls on each node in your cluster (recommended) to allow access to the cluster services or disable it completely.  Included in this section is configuration examples for `firewalld`.  If you use a different firewall, check your documentation for how to open the listed ports.

Master node(s) require

| Service Name | Port/protocol     |
|--------------|-------------------|
| mesos-master | 5050/tcp          |

Example `firewalld` config

    $ sudo firewall-cmd --zone=public --add-port=5050/tcp --permanent
    $ sudo systemctl restart firewalld

Agent (compute) nodes require

| Service Name | Port/protocol     |
|--------------|-------------------|
| BIRD (BGP)   | 179/tcp           |
| mesos-agent  | 5051/tcp          |

Example `firewalld` config

    $ sudo firewall-cmd --zone=public --add-port=179/tcp --permanent
    $ sudo firewall-cmd --zone=public --add-port=5051/tcp --permanent
    $ sudo systemctl restart firewalld

## 4. Optional: Configure Firewall for etcd & zookeeper
Etcd uses tcp over ports 2379 and 4001, ZooKeeper uses tcp over port 2181, and Marathon uses tcp over port 8080. In the next Core Services Prepearation Guide, we will run these services on the master, and will open those ports now. Wherever you choose to run these services, be sure to open these ports as well:

| Service Name | Port/protocol     |
|--------------|-------------------|
| etcd         | 4001/tcp           |
| zookeeper    | 8080/tcp          |

Example `firewalld` config

    $ sudo firewall-cmd --zone=public --add-port=4001/tcp --permanent
    $ sudo firewall-cmd --zone=public --add-port=8080/tcp --permanent
    $ sudo systemctl restart firewalld

## 5. Next Steps 
With your hosts configured, you're ready to continue on to [Preparing Core Services](PrepareCoreServices.md)

[![Analytics](https://ga-beacon.appspot.com/UA-52125893-3/calico-docker/docs/mesos/PrepareHosts.md?pixel)](https://github.com/igrigorik/ga-beacon)
