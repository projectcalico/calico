---
title: Framework Install Walkthrough
sitemap: false 
---

Calico maintains a Framework for DC/OS for simple installation and use.
The framework is flexible so that users can use it as an installer,
a runtime daemon, or both. Below, we'll see exactly how to deploy the following
common configurations:

a. **The One-Click Install:** Easy install for demo purposes

b. **Calico with Manually Run Etcd:** A more stable approach to connecting Calico with etcd.

c. **Calico with Prerequisites Met:** Using the Framework only as a runtime init system.

d. **Calico Outside DC/OS:** Manually installing Calico as a system service.

## a.) The One-Click Install

The calico-framework can be one-click installed for demo purposes. We do not
recommend one-click installing on a existing cluster (especially production
clusters) for the following reasons:

1. Installation of a CNI plugin requires the agent process be restarted.
2. Configuration of a cluster-store for Docker requires the daemon process be restarted.

These steps can significantly impact your cluster, so we recommend
performing them outside of the Framework steps (as we'll see later in method 'b'.)

##### Prerequisites

Install etcd from Universe.

![Installing etcd from Universe]({{site.baseurl}}/images/dcos-install-etcd.gif)

##### Install Steps

Simply install calico from Universe.

![Installing Calico from Universe]({{site.baseurl}}/images/dcos-install-calico.gif)

It will take a few minutes for Calico to finish
installing on your cluster. You can check the status of the installation by
visiting Calico's web status interface:

 - Go to the **Services** tab
 - Find Calico in the list of running services
   (note that it may take a few minutes for Calico
    to appear).
 - Once the Calico service is `Healthy`, click the
   square pop-out icon next to the service name to
   open the Calico status page in a new tab.

![alt tag]({{site.baseurl}}/images/mesos/dcos-calico-open-status.png)

You should see a page that looks like the following:

![alt tag]({{site.baseurl}}/images/mesos/dcos-calico-status.png)

>Note: The webpage may fail to load initially since the Calico
service restarts the Docker and Mesos agent services, which
will cause a restart of the Calico framework when it happens
on the same agent. This is expected and nothing to be
concerned about. Once the status page is running, you will see a
table where each row represents an agent, including statuses
for each of the Calico components installed.

## b.) Calico-DC/OS with Manually Run etcd

Though the above install is fast and easy to deploy, it is arguably a bit
unreliable since it runs core infrastructure (i.e. etcd) in Mesos instead of
underneath it as a core component.

With just a few tweaks to the process above, we can improve stability by connecting
the Calico-DC/OS Framework to an etcd cluster we have manually run ourselves,
outside of DC/OS.

##### Prerequisites

Run an etcd cluster across your masters. Follow the
[official etcd clustering guide](https://coreos.com/etcd/docs/latest/clustering.html#static)
for information on how to run a HA etcd cluster.

For demo purposes, we'll run one single instance of etcd on our first master
(available at http://m1.dcos:2379):

```shell
docker run -d --net=host --name=etcd quay.io/coreos/etcd:v2.0.11 \
--advertise-client-urls "http://m1.dcos:2379" \
--listen-client-urls "http://m1.dcos:2379,http://127.0.0.1:2379" \
```

##### Install Steps

This time, we will launch the calico framework with the following configuration:

```json
{
  "Etcd Settings": {
    "run-proxy": false,
    "etcd-endpoints": "http://m1.dcos:2379"
  }
}
```

## c.) Framework for Runtime Tasks Only (Prereqs Met)

Users who want to minimize impact on cluster availability during installation
can perform the Framework Installation steps manually (etcd, docker cluster-store,
& calico-cni install) and use the Framework solely to run Calico's core components:
`calico/node` and `calico/node-libnetwork`.

##### Prerequisites

1. **etcd.** For this example, we'll again run etcd manually on our master:

   ```shell
   docker run -d --net=host --name=etcd quay.io/coreos/etcd:v2.0.11 \
   --advertise-client-urls "http://m1.dcos:2379" \
   --listen-client-urls "http://m1.dcos:2379,http://127.0.0.1:2379"
   ```

2. **Configure Docker with Cluster-store** on every agent.

   This will often be either zookeeper on the mesos-masters, or the etcd cluster
   that was just launched.
   For this example, we'll use the etcd cluster on our masters, to separate
   docker's use of a Database from Mesos'.

   On each agent, create / modify `/etc/docker/daemon.json` with the following content:

   ```json
   {
     "cluster-store": "etcd://m1.dcos:2379"
   }
   ```


3. **Install Calico-CNI.**

   ```shell
   curl -L -o /opt/mesosphere/active/cni/calico  https://github.com/projectcalico/calico-cni/releases/download/v1.3.0/calico
   curl -L -o /opt/mesosphere/active/cni/calico-ipam https://github.com/projectcalico/calico-cni/releases/download/v1.3.0/calico-ipam
   cat <<EOF > /opt/mesosphere/etc/dcos/network/cni/calico.conf
   {
       "name": "calico",
       "type": "calico",
       "ipam": {
           "type": "calico-ipam"
       },
       "etcd_authority": "m1.dcos:2379"
   }
   ```

##### Install Steps

Now, we will disable all install steps of the framework, allowing it to just
ensure `calico/node` and `calico/node-libnetwork` are running.

Launch Calico with the following configuration:

```json
{
  "Etcd Settings": {
    "run-proxy": false,
    "etcd-endpoints": "http://m1.dcos:2379"
  },
  "Configure Docker Cluster-Store": {
    "enable": false
  },
  "Install CNI": {
    "enable": false
  }
}
```

### d.) Calico Outside DC/OS

The above methods (c & d) for running Calico are very stable, as they ensure
cluster configuration is not done while tasks are running.

At this point, it is one more simple step to run Calico completely underneath DC/OS -
see the [Calico as a Service]({{site.baseurl}}/{{page.version}}/usage/configuration/as-service)
for information and examples of how to run Calico as a systemd service.
