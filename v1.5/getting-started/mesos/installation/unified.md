---
title: Installing Calico-CNI for the Unified Containerizer
sitemap: false 
---

This guide details how to add Calico networking to a Mesos Agent with CNI enabled.

- If you're looking for information on installing Calico with the Docker Containerizer, see [Docker Containerizer Manual Install Guide]({{site.baseurl}}/{{page.version}}/getting-started/mesos/installation/docker)
- If you're not sure the difference between the Unified and Docker Containerizers, see  [Mesos' information on Containerizers](http://mesos.apache.org/documentation/latest/containerizer/) and [Our Readme on Calico's integration for each]({{site.baseurl}}/{{page.version}}/getting-started/mesos/).

### Prerequisites
- **A Running Mesos v1.0.0+ cluster**  [with CNI enabled on each agent](http://mesos.apache.org/documentation/latest/cni/#usage).

  When enabling CNI in Mesos, you will have specified a `network_cni_config_dir` and `network_cni_plugins_dir`. We'll refer to these going forward as `$NETWORK_CNI_CONFIG_DIR` and `$NETWORK_CNI_PLUGINS_DIR`, respectively.

- **Docker** must be installed and running on each agent in order to run `calico/node`. Follow the relevant [docker installation guide](https://docs.docker.com/engine/installation/).
- **etcd** is used by Calico to store network configurations. See [etcd's docker standalone guide](https://coreos.com/etcd/docs/latest/docker_guide.html) for information on how to quickly get an instance running.

## Installation
Run the following steps on **each agent**.

1. Download the Calico CNI plugin to the `$NETWORK_CNI_PLUGINS_DIR` you configured for Mesos:

```shell
curl -L -o $NETWORK_CNI_PLUGINS_DIR/calico \
    https://github.com/projectcalico/calico-cni/releases/download/v1.3.0/calico
chmod +x $NETWORK_CNI_PLUGINS_DIR/calico
ln -s $NETWORK_CNI_PLUGINS_DIR/calico $NETWORK_CNI_PLUGINS_DIR/calico-ipam
```

2. Run `calico/node`, a Docker container with calico's core routing processes.
The `calico/node` container can easily be launched using
`calicoctl`, Calico's command line tool. When doing so,
we must provide the location of the running etcd instance
by setting the `ECTD_AUTHORITY` environment variable.

```shell
curl -L -O \
    https://github.com/projectcalico/calico-containers/releases/download/v0.18.0/calicoctl
chmod +x ./calicoctl
sudo ETCD_AUTHORITY=<etcd-ip:port> ./calicoctl node
```

## Next Steps
Now that you have all the necessary components in place, its time to configure a network and launch tasks. See [Calico's Mesos-CNI Usage Guide]({{site.baseurl}}/{{page.version}}/getting-started/mesos/tutorials/unified).
