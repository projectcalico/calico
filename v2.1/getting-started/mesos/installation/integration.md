---
title: Integration Guide
sitemap: false 
---

This guide explains the components necessary to install Calico on Mesos for integrating with custom configuration management. To install Calico in Mesos, no changes are needed on any Mesos Master.
**Adding Calico to a Mesos cluster only requires modifications to each Agent.**

Ensure you've met the [prerequisites](prerequisites) before continuing, namely that
you have etcd running.

Calico runs as a Docker container on each host. The `calicoctl` command line tool can be used to launch the `calico/node` container.

1. Download the calicoctl binary:

   ```
   sudo wget -O /usr/local/bin/calicoctl {{site.data.versions[page.version].first.components.calicoctl.download_url}}
   sudo chmod +x /usr/local/bin/calicoctl
   ```

3. Launch `calico/node`:

   ```
   sudo ETCD_ENDPOINTS=http://$ETCD_IP:$ETCD_PORT calicoctl node run
   ```

   >Note: Ensure you've set or replaced `$ETCD_IP` and `$ETCD_PORT` to point to
   [your etcd cluster](prerequisites).

   Check that `calico/node` is now running:

   ```
   vagrant@calico-01:~$ docker ps
   CONTAINER ID        IMAGE                        COMMAND             CREATED             STATUS              PORTS               NAMES
   408bd2b9ba53        quay.io/calico/node:{{site.data.versions[page.version].first.components["calico/node"].version}}   "start_runit"       3 seconds ago       Up 2 seconds                            calico-node
   ```

   Furthermore, check that the `calico/node` container is functioning properly
   with the following command:

   ```
   sudo calicoctl node status
   ```

4. Download the Calico CNI plugin to the
   [`$NETWORK_CNI_PLUGINS_DIR` you configured for Mesos](prerequisites).
   You may skip this step if you do not plan on using the Unified Containerizer.

   ```shell
   curl -L -o $NETWORK_CNI_PLUGINS_DIR/calico \
       {{site.data.versions[page.version].first.components["calico/cni"].download_calico_url}}
   curl -L -o $NETWORK_CNI_PLUGINS_DIR/calico-ipam \
       {{site.data.versions[page.version].first.components["calico/cni"].download_calico_ipam_url}}
   chmod +x $NETWORK_CNI_PLUGINS_DIR/calico
   chmod +x $NETWORK_CNI_PLUGINS_DIR/calico-ipam
   ```

## Next Steps

With Calico Installed, you're now ready to launch Calico-networked tasks.
View the guide relevant to your workloads:

- [Docker Containerizer Tutorial]({{site.baseurl}}/{{page.version}}/getting-started/mesos/tutorials/docker)
- [Unified Containerizer Tutorial]({{site.baseurl}}/{{page.version}}/getting-started/mesos/tutorials/unified)
