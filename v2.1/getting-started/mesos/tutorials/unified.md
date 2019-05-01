---
title: Networking Mesos Tasks with Calico
canonical_url: 'https://docs.projectcalico.org/v2.1/getting-started/mesos/tutorials/unified'
---

## Prerequisites

This guide assumes you have a running Mesos Cluster whereby each Agent has
CNI enabled, and Calico services and binaries are installed. See the [Integration Guide]({{site.baseurl}}/{{page.version}}/getting-started/mesos/installation/integration)
for information on how to meet these requirements.

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
    "etcd_endpoints": "http://<etcd-ip:port>:2379"
}
EOF
```

Mesos-Agent loads these network configurations into memory at launch, so you will need to restart the Agent process for your new configuration to take effect.

## 2. Launch a Calico-Networked Task

With your CNI network configured, you are now ready to launch tasks on it. There are several common methods you can use to do so.

#### a.) Using Mesos-Execute

To test that Calico's network is functioning correctly, use `mesos-execute` and set `--networks` to launch a task on your Calico CNI network:

```shell
mesos-execute --containerizer=mesos \
              --name=calico-cni-base-test \
              --master=172.17.0.4:5050 \
              --networks=calico-net-1 \
              --command="ifconfig"
```

The task will have been successfully networked by Calico if its return code is `0`. Additionally, the task's `stdout` log should show an IP address from the default Calico pool: `192.168.0.0/16`

#### b.) Using Marathon

In Marathon v1.2.0+, set the task's `ipAddress.networkName` to the name of the CNI network:

```shell
curl -X POST -H "Content-Type: application/json" http://localhost:8080/v2/apps -d '
{
    "id": "calico-cni-marathon-test",
    "cmd": "ifconfig && sleep 1000",
    "cpus": 0.1,
    "mem": 64.0,
    "ipAddress": {
        "networkName": "calico-net-1",
        "labels": {
          "app": "test",
          "group": "development"
        }
    }
}'
```
Again, this task should show a Calico IP in the Marathon UI.

#### c.) Using Marathon - Unified Containerizer

With the release of Mesos-1.0, the Unified Containerizer can now launch Docker Images using the Mesos Containerizer. Calico can perform networking for these tasks.

> To make use of this feature, ensure you are using Mesos 1.0.0+ with agents [configured to use the Unified Containerizer](http://mesos.apache.org/documentation/latest/container-image/). Also ensure you are using Marathon v1.3.0+.

Our `app.json` looks similar to the one above, but with a few extra settings (and some more practical use):

```shell
curl -X POST -H "Content-Type: application/json" http://localhost:8080/v2/apps -d '
{
    "id": "frontend",
    "container": {
      "type": "MESOS",
      "docker": {
        "image": "nginx"
      }
    },
    "cpus": 0.1,
    "mem": 64.0,
    "ipAddress": {
        "networkName": "calico-net-1",
        "labels": {
          "app": "frontend",
          "group": "production"
        }
    }
}'
```

The application will show its Calico IP when viewed using the Marathon UI, however it will be unreachable until Calico policy is configured to allow traffic.

## 3. Configuring Policy

Calico CNI v1.4.1+ supports selector-based policy for Mesos v1.0.0+.

The above Marathon Application Definition has assigned the labels `app=frontend` and `group=production` to the task's NetworkInfo. The Calico CNI plugin automatically reads these labels and assign them to the endpoint, allowing us to enforce policy based on them.

The following YAML policy spec describes rules based on these labels:

```yaml
apiVersion: v1
kind: policy
metadata:
  name: frontend-policy
spec:
  order: 50
  selector: app == 'frontend'
  ingress:
  - action: allow
    protocol: tcp
    destination:
      ports:
      - 80
  egress:
  - action: allow
    protocol: tcp
    destination:
      selector: app == 'database'
      ports:
      - 6379
```

Use [`calicoctl`]({{site.baseurl}}/{{page.version}}/releases) to create the policy resource.

```shell
calicoctl create -f frontend-policy.yaml
```

[calico-slack]: https://slack.projectcalico.org/
[marathon-ip-per-task-doc]: https://github.com/mesosphere/marathon/blob/v0.14.0/docs/ip-per-task.md
