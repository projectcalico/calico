<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.19.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Calico-CNI with the Unified Containerizer - Manual Install Guide
This guide explains how to add Calico networking to a Mesos Agent using CNI.
Specifically, we will add the Calico plugin to perform networking
for the **Unified Containerizer**.
- If you're looking for information on installing Calico with the Docker Containerizer, see [Docker Containerizer Manual Install Guide](./ManualInstallCalicoDockerContainerizer.md)
- If you're not sure the difference between the Unified and Docker Containerizers, see  [Mesos' information on Containerizers](http://mesos.apache.org/documentation/latest/containerizer/) and [Our Readme on Calico's integration for each](./README.md).

## Prerequisites
- **Mesos Cluster with v0.29.0+:** You must have an [agent with CNI enabled](https://github.com/apache/mesos/blob/master/docs/cni.md#configuring-cni-networks) that is apart of a running Mesos Cluster. 
    > Note: During configuration, you will have specified a `network_cni_config_dir` and `network_cni_plugins_dir`. We'll refer to these going forward as `$NETWORK_CNI_CONFIG_DIR` and `$NETWORK_CNI_PLUGINS_DIR`, respectively.
- **Docker:** Calico's core services are run from within a Docker container on each agent, so you'll need to follow the relevant [docker installation guide](https://docs.docker.com/v1.8/installation/) on each.
- **Etcd:** Calico uses etcd as its datastore. See the [Cluser Preparation guide](MesosClusterPreparation.md#etcd) for information on how to quickly get one running.

## Install Calico
1. Download Calico's CNI plugin:
    ```
    curl -L -o $NETWORK_CNI_PLUGINS_DIR/calico \
    https://github.com/projectcalico/calico-cni/releases/download/v1.3.0/calico
    chmod +x $NETWORK_CNI_PLUGINS_DIR/calico
    ```

2. Run Calico Node, a Docker container with calico's core routing processes. 
  The `calico-node` container can easily be launched using
  `calicoctl`, Calico's command line tool. When doing so,
  we must provide the location of the running etcd instance
  by setting the `ECTD_AUTHORITY` environment variable.
    ```
    curl -L -o ./calicoctl https://github.com/projectcalico/calico-containers/releases/download/v0.18.0/calicoctl
    chmod +x calicoctl
    sudo ETCD_AUTHORITY=<etcd-ip:port> ./calicoctl node
    ```
