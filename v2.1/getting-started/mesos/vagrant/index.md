---
title: Vagrant Deployed Mesos Cluster with Calico
canonical_url: 'https://docs.projectcalico.org/v2.3/getting-started/mesos/vagrant/index'
---
This guide will show you how to use Vagrant to launch a Mesos Cluster
with Calico installed and ready to network Docker Containerizer tasks.

## 1. Install Dependencies
This guide requires a host machine with:

 * [VirtualBox][virtualbox] to host the virtual machines.
 * [Vagrant][vagrant] to install and configure the machines in Virtual Box.
 * [Curl][curl]

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

That's it! Your Mesos Cluster is ready to use!

### Cluster Layout

<pre>
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
'-----------------------------------------------------------------------------------'
</pre>

## 4. SSH
To connect to your Vagrant boxes on OSX / Linux, see
[Vagrant's SSH command](https://www.vagrantup.com/docs/cli/ssh.html).
For Windows, see <https://github.com/nickryand/vagrant-multi-putty>.

## 5. Next Steps
With your cluster deployed, you can follow the
[Docker Containerizer Usage Guide]({{site.baseurl}}/{{page.version}}/getting-started/mesos/tutorials/docker).
to learn how to launch your own Calico-networked tasks.

[virtualbox]: https://www.virtualbox.org/
[vagrant]: https://www.vagrantup.com/
[curl]: https://curl.haxx.se/
