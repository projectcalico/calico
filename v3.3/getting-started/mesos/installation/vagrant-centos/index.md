---
title: Vagrant Deployed Mesos Cluster with Calico
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/mesos/installation/vagrant-centos/'
---
This guide will show you how to use Vagrant to launch a Mesos Cluster
with {{site.prodname}} installed and ready to network Docker Containerizer tasks.

## 1. Install Dependencies
This guide requires a host machine with:

 * [VirtualBox][virtualbox] to host the virtual machines.
 * [Vagrant][vagrant] to install and configure the machines in Virtual Box.
 * [curl][curl]

### 1.2 Download the source files

    mkdir demo; cd demo
    curl -O {{site.url}}{{page.dir}}Vagrantfile
    curl -O {{site.url}}{{page.dir}}calico.service
    curl -O {{site.url}}{{page.dir}}marathon-lb.service
    curl -O {{site.url}}{{page.dir}}mesos-dns.service

## 3. Startup

```shell
vagrant up
```

This starts a two node cluster with the cluster layout described below.

Access the Mesos and Marathon services at the following URLs:

| Service         | URL                        |
| :-------------- | :------------------------- |
| Mesos-Master UI | http://172.24.197.101:5050 |
| Marathon UI     | http://172.24.197.101:8080 |

### Cluster Layout

| Machine Type | OS     | Hostname  | IP Address     | Services               |
| :----------- | :----- | :-------- | :------------- | :--------------------- |
| Master       | Centos | calico-01 | 172.24.197.101 | mesos-master           |
|              |        |           |                | etcd                   |
|              |        |           |                | docker                 |
|              |        |           |                | zookeeper              |
|              |        |           |                | marathon               |
|              |        |           |                | marathon load-balancer |
|              |        |           |                | {{site.noderunning}}   |
|--------------|--------|-----------|----------------|------------------------|
| Agents       | Centos | calico-01 | 172.24.197.102 | mesos-agent            |
|              |        | calico-02 | 172.24.197.103 | docker                 |
|              |        |           |                | {{site.noderunning}}   |

## 4. SSH

To connect to your Vagrant boxes on OSX / Linux, see
[Vagrant's SSH command](https://www.vagrantup.com/docs/cli/ssh.html).
For Windows, see <https://github.com/nickryand/vagrant-multi-putty>.

## 5. Next Steps

With your cluster deployed, you can follow the
[tutorials on using {{site.prodname}} with Mesos]({{site.baseurl}}/{{page.version}}/getting-started/mesos#tutorials).

[virtualbox]: https://www.virtualbox.org/
[vagrant]: https://www.vagrantup.com/
[curl]: https://curl.haxx.se/
