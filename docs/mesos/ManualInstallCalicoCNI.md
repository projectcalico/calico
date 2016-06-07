<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.19.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Installing Calico-CNI for use by the Unified Containerizer
This guide explains how to add Calico networking to a Mesos Agent with CNI enabled.

- If you're looking for information on installing Calico with the Docker Containerizer, see [Docker Containerizer Manual Install Guide](./ManualInstallCalicoDockerContainerizer.md)
- If you're not sure the difference between the Unified and Docker Containerizers, see  [Mesos' information on Containerizers](http://mesos.apache.org/documentation/latest/containerizer/) and [Our Readme on Calico's integration for each](./README.md).

## Prerequisites
- **A Running Mesos v0.29.0+ cluster**  [with CNI enabled on each agent](https://github.com/apache/mesos/blob/master/docs/cni.md#configuring-cni-networks).

> Note: When enabling CNI in Mesos, you will have specified a `network_cni_config_dir` and `network_cni_plugins_dir`. We'll refaer to these going forward as `$NETWORK_CNI_CONFIG_DIR` and `$NETWORK_CNI_PLUGINS_DIR`, respectively.

- **Docker** must be installed and running on each agent in order to run `calico/node`. Follow the relevant [docker installation guide](https://docs.docker.com/engine/installation/).
- **etcd** is used by Calico to store network configurations. See [etcd's docker standalone guide](https://coreos.com/etcd/docs/latest/docker_guide.html) for information on how to quickly get an instance running.

## Install Calico
Run the following steps on each agent.

1. Download the Calico CNI plugin:
    ```
    curl -L -o $NETWORK_CNI_PLUGINS_DIR/calico \
        https://github.com/projectcalico/calico-cni/releases/download/v1.3.0/calico
    chmod +x $NETWORK_CNI_PLUGINS_DIR/calico
    ```

2. Run `calico/node`, a Docker container with calico's core routing processes.
The `calico/node` container can easily be launched using
`calicoctl`, Calico's command line tool. When doing so,
we must provide the location of the running etcd instance
by setting the `ECTD_AUTHORITY` environment variable.
    ```
    curl -L -o ./calicoctl \
        https://github.com/projectcalico/calico-containers/releases/download/v0.18.0/calicoctl
    chmod +x calicoctl
    sudo ETCD_AUTHORITY=<etcd-ip:port> ./calicoctl node
    ```

## Configuring a Calico CNI Network
Before we can start launching tasks, we must first define our CNI network definition in the configured  `--network_cni_config_dir`:
```
cat <<EOF > $NETWORK_CNI_CONFIG_DIR/my-net-1.conf
{
    "name": "my-net-1",
    "type": "calico",
    "ipam": {
        "type": "calico-ipam"
    },
    "etcd_authority": "<etcd-ip:port>:2379"
}
```

Mesos will actively scan that directory when launching containers, so without needing to restart the Agent process, you are now ready to launch calico-CNI Mesos tasks.

## Launching Tasks
With our network configured, we can use `mesos-execute` to launch a task on the CNI network you just configured by setting `--networks` to the name of the network you just configured:
```
mesos-execute --containerizer=mesos \
              --name=cni \
              --master=172.17.0.4:5050 \
              --networks=my-net-1 \
              --command=ifconfig
```
This will launch a simple task that prints its Calico-assigned IP address and then exit.

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/mesos/ManualInstallCalicoCNI.md?pixel)](https://github.com/igrigorik/ga-beacon)
