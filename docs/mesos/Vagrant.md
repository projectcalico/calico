<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.21.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Vagrant Start a Mesos Cluster with Calico
This guide will show you how to use Vagrant to launch a Mesos Cluster
with Calico installed and ready to network Docker Containerizer tasks.

## 1. Install Dependencies
This guide requires a host machine with:

 * [VirtualBox][virtualbox] to host the virtual machines.
 * [Vagrant][vagrant] to install and configure the machines in Virtual Box.
 * [Git][git]

## 2. Download Demo Files
   ```
   git clone https://github.com/projectcalico/calico-containers.git
   ```

## 3. Startup
```
cd calico-containers/docs/mesos/vagrant-centos/
vagrant up
```

That's it! Your Mesos Cluster is ready to use!

### Cluster Layout
```
.-----------------------------------------------------------------------------------.
| Machine Type | OS     | Hostname        | IP Address     | Services               |
|--------------|--------|-----------------|----------------|------------------------|
| Master       | Centos | calico-mesos-01 | 172.24.197.101 | mesos-master           |
|              |        |                 |                | etcd                   |
|              |        |                 |                | docker                 |
|              |        |                 |                | zookeeper              |
|              |        |                 |                | marathon               |
|              |        |                 |                | marathon load-balancer |
|              |        |                 |                | calico-node            |
|--------------|--------|-----------------|----------------|------------------------|
| Agents       | Centos | calico-mesos-02 | 172.24.197.102 | mesos-agent            |
|              |        | calico-mesos-03 | 172.24.197.103 | docker                 |
|              |        |                 |                | calico-node            |
|              |        |                 |                | calico-libnetwork      |
'-----------------------------------------------------------------------------------'
```

## 4. SSH
To connect to your Vagrant boxes on OSX / Linux, see
[Vagrant's SSH command](https://www.vagrantup.com/docs/cli/ssh.html).
For Windows, see https://github.com/nickryand/vagrant-multi-putty.

## 5. Next Steps
With your cluster deployed, you can follow the
[Docker Containerizer Usage Guide](./UsageGuideDockerContainerizer.md).
to learn how to launch your own Calico-networked tasks.

[virtualbox]: https://www.virtualbox.org/
[vagrant]: https://www.vagrantup.com/
[git]: https://www.git-scm.com/
[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/mesos/Vagrant.md?pixel)](https://github.com/igrigorik/ga-beacon)
