---
title: Integration Guide
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/mesos/installation/integration'
---

This guide explains how to integrate {{site.prodname}} networking and policy on an existing
Mesos cluster. These instructions should be followed on each **Agent**.

Ensure you've met the [prerequisites](prerequisites) before continuing, namely that
you have etcd running.

{{site.prodname}} runs as a Docker container on each host. The `calicoctl` command line tool can be used to launch the `{{site.nodecontainer}}` container.

1. Download the calicoctl binary:

   ```
   sudo wget -O /usr/local/bin/calicoctl {{site.data.versions[page.version].first.components.calicoctl.download_url}}
   sudo chmod +x /usr/local/bin/calicoctl
   ```

1. Launch `{{site.nodecontainer}}`:

   ```
   sudo ETCD_ENDPOINTS=http://$ETCD_IP:$ETCD_PORT calicoctl node run --node-image={{site.imageNames["node"]}}:{{site.data.versions[page.version].first.title}}
   ```

   > **Note**: Ensure you've set or replaced `$ETCD_IP` and `$ETCD_PORT` to point to
   [your etcd cluster](prerequisites).
   {: .alert .alert-info}

   Check that `{{site.nodecontainer}}` is now running:

   ```
   vagrant@calico-01:~$ docker ps
   CONTAINER ID        IMAGE                        COMMAND             CREATED             STATUS              PORTS               NAMES
   408bd2b9ba53        {{site.imageNames["node"]}}:{{site.data.versions[page.version].first.title}}   "start_runit"       3 seconds ago       Up 2 seconds                            {{site.noderunning}}
   ```

   Furthermore, check that the `{{site.nodecontainer}}` container is functioning properly
   with the following command:

   ```
   sudo calicoctl node status
   ```

1. Download the {{site.prodname}} CNI plugin to the
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

1. Create a {{site.prodname}} CNI configuration in the [`$NETWORK_CNI_CONF_DIR` you configured for Mesos](prerequisites), replacing `http://master.mesos:2379` with
   etcd's address:

   ```shell
   cat > $NETWORK_CNI_CONF_DIR/calico.conf <<EOF
   {
      "name": "calico",
      "cniVersion": "0.1.0",
      "type": "calico",
      "ipam": {
          "type": "calico-ipam"
      },
      "etcd_endpoints": "http://master.mesos:2379"
   }
   EOF
   ```



## Next Steps

With {{site.prodname}} installed, you're now ready to launch {{site.prodname}}-networked tasks.
View the [guides on using {{site.prodname}} with Mesos]({{site.baseurl}}/{{page.version}}/getting-started/mesos#tutorials)
