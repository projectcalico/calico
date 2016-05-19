<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.19.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Calico-CNI Usage Guide with the Unified Containerizer
These instructions outline how to configure and launch containers on a
Calico CNI network in Mesos.

This assumes a running Mesos cluster that meets the following specifications:

- Mesos-Master v0.29.0+
- etcd
- zookeeper
- Mesos-Slave v0.29.0+ with the following true for each agent:
    - Docker installed
    - calico-node running
    - calico-cni binary installed
    - calico-ipam binary installed

If your Slave does not meet these specifications simply follow the [CNI Manual Installation guide for Mesos](ManualInstallCalicoCNI.md) before continuing.

## Configuring a Calico CNI Network
Before we can start launching tasks, we must first create a CNI network definition on each Agent in the directory that was specified as `--network_cni_config_dir` during setup:
```
cat <<EOF > $NETWORK_CNI_CONFIG_DIR/my-net-1.conf
{
    "name": "my-net-1",
    "type": "calico",
    "ipam": {
        "type": "calico-ipam"
    },
    "etcd_authority": "etcd:2379"
}
```

Mesos will actively scan that directory when launching containers, so without needing to restart the Agent process, you are now ready to launch calico-CNI Mesos tasks.

## Launching Containers
With our network configured, we can launch containers using `mesos-execute`: 
```
mesos-execute --containerizer=mesos --docker_image=busybox --name=cni --master=172.17.0.4:5050 --networks=my-net-1 --command=ifconfig
```
