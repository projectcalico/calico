---
title: Networking Mesos Tasks with Calico-CNI
---

## Prerequisites
This guide assumes you have a running Mesos Cluster whereby each Agent has
CNI enabled, and Calico services and binaries are installed. See [Adding Calico-CNI to an existing Mesos Cluster](ManualInstallCalicoCNI.md), or use the [Docker-Compose Demo Cluster](cni-compose-demo/) to meet these requirements.

## Getting started

#### 1. Configure a Calico CNI Network
Before we can start launching tasks, we must first define our CNI network definition in the configured  `--network_cni_config_dir`:

```shell
cat <<EOF > $NETWORK_CNI_CONFIG_DIR/calico-net-1.conf
{
    "name": "calico-net-1",
    "type": "calico",
    "ipam": {
        "type": "calico-ipam"
    },
    "etcd_authority": "<etcd-ip:port>:2379"
}
EOF
```

> Note: If you have used the Docker-Compose demo to launch a cluster, this network configuration has already been created for you.

Mesos will actively scan that directory when launching containers, so without needing to restart the Agent process, you are now ready to launch Calico-CNI Mesos tasks.

## 2. Launch a Calico-Networked Task
#### Using Mesos-Execute
With our network configured, we can use `mesos-execute` to launch a task on the CNI network you just configured by setting `--networks` to the name of the network you just configured:

```shell
mesos-execute --containerizer=mesos \
              --name=cni \
              --master=172.17.0.4:5050 \
              --networks=calico-net-1 \
              --command="ifconfig"
```

#### Using Marathon
Create `app.json` with `ipAddress.networkName` set to the CNI network:

```shell
{
    "id": "frontend",
    "cmd": "ifconfig && sleep 1000",
    "cpus": 0.1,
    "mem": 64.0,
    "ipAddress": {
        "networkName": "calico-net-1",
        "labels": {
          "app": "frontend",
          "group": "production"
        }
    }
}
```

You can curl `app.json` using Marathon's REST API to launch
the application:

```shell
curl -X POST -H "Content-Type: application/json" http://localhost:8080/v2/apps -d @app.json
```

The application should show a Calico IP when viewed in the Marathon UI.

[calico-slack]: https://slack.projectcalico.org/
[marathon-ip-per-task-doc]: https://github.com/mesosphere/marathon/blob/v0.14.0/docs/docs/ip-per-task.md
