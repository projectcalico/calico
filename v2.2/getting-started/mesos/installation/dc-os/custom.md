---
title: Customizing the Calico Universe Framework
sitemap: false 
---

The the Calico Universe Framework includes customization options which support
more stable deployments when users

#### Custom etcd

By default, Calico will run etcd in proxy mode on every agent, forwarding requests
to `http://localhost:2379` to the running etcd cluster launched by Universee,
accessible via an SRV entry.

The Calico Universe framework alternatively can be configured to directly connect
to an etcd instance launched outside of universe, removing
the need for etcd-proxy:

1. Run an etcd cluster across your masters. Follow the
   [official etcd clustering guide](https://coreos.com/etcd/docs/latest/clustering.html#static)
   for information on how to run a HA etcd cluster.

   For demo purposes, we'll run one single instance of etcd on our first master
   (available at http://m1.dcos:2379):

   ```shell
   docker run -d --net=host --name=etcd quay.io/coreos/etcd:v2.0.11 \
   --advertise-client-urls "http://m1.dcos:2379" \
   --listen-client-urls "http://m1.dcos:2379,http://127.0.0.1:2379" \
   ```

2. Launch the Calico Universe Framework with the following configuration:

   ```json
   {
     "Etcd Settings": {
       "run-proxy": false,
       "etcd-endpoints": "http://m1.dcos:2379"
     }
   }
   ```

#### Configure Docker with Cluster-Store

The Docker engine must be restarted after

Users who want to minimize impact on cluster availability during installation
can perform the docker cluster-store configuration manually.

1. On each agent, create or modify `/etc/docker/daemon.json` with the following content:

   ```json
   {
    "cluster-store": "etcd://m1.dcos:2379"
   }
   ```

2. Restart docker:

   ```
   systemctl restart docker
   ```

   Ensure it has picked up the changes:

   ```
   docker info | grep -i "cluster store"
   ```

3. When launching the Calico Universe Framework, disable the Docker Cluster-Store configuration step:

   ```json
   {
     "Configure Docker Cluster-Store": {
       "enable": false
     }
   }
   ```

#### Install the Calico CNI Plugins

Installation of CNI plugins requires a restart of the Mesos-Agent process.
Users who want to minimize impact on cluster availability during installation
can install the Calico plugin manually by performing the following steps
on each agent:

1. Download Calico's CNI plugin binaries:

   ```shell
   curl -L -o /opt/mesosphere/active/cni/calico  {{site.data.versions[page.version].first.components["calico/cni"].download_calico_url}}
   curl -L -o /opt/mesosphere/active/cni/calico-ipam {{site.data.versions[page.version].first.components["calico/cni"].download_calico_ipam_url}}
   ```

2. Create a standard Calico CNI network configuration:

   ```shell
   cat <<EOF > /opt/mesosphere/etc/dcos/network/cni/calico.conf
   {
       "name": "calico",
       "cniVersion": "0.1.0",
       "type": "calico",
       "ipam": {
           "type": "calico-ipam"
       },
       "etcd_endpoints": "http://m1.dcos:2379"
   }
   ```

3. When launching the Calico Universe Framework, disable the CNI plugin installation step:

   ```json
   {
     "Install CNI": {
       "enable": false
     }
   }
   ```
