<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.14.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Mesos with Calico Networking
**Calico provides IP-Per-Container networking for Mesos clusters.** The following collection of tutorials will walk through the steps necessary for installation and use.

Questions? Contact us on the #Mesos channel of [Calico's Slack](https://calicousers-slackin.herokuapp.com/).

### Mesos Version Compatability
Calico support is actively being developed. Use the following information to ensure you choose the right version:
- **Mesos 0.26:** Recommended. Full Calico Support for the future.
- **Mesos 0.25:** Deprecated. Calico works with Mesos 0.25, but we recommend against using it as there aren't any Frameworks (including Marathon) which support the Networkinfo specs from 0.25 (which were modified for 0.26)
- **Mesos 0.24:** Unsupported. Calico works as a proof of concept, but is no longer supported.

### Support for Adding Calico to an Existing Mesos Cluster
The following tutorials cover installing Netmodules on a fresh machine which does not yet have Mesos installed.
At this time, we do not support adding netmodules to an existing mesos 
cluster.

###  Launching Tasks with Calico + Mesos
IP-Per-Container Networking with Calico is an opt-in feature for Mesos Frameworks that launch tasks with [Networkinfo](https://github.com/apache/mesos/blob/0.26.0-rc3/include/mesos/mesos.proto#L1383). This means that your favorite Mesos Frameworks will not work with Calico until they have opted to include Networkinfo when launching tasks. Currently, this is limited to Mesos tasks launched via Marathon, with support for more frameworks growing. 

Since the Mesos Docker Containerizer does not support Module hooks, external networking is incompatible with docker containers in 0.26. Modifications are being made to the Mesos Containerizer to launch docker containers in future versions of Mesos, which will work with Calico out of the box going forward.

## 1. Prepare Master and Set Up External Services
In general, adding Calico to your Mesos Cluster doesn't require any 
modifications to the Mesos Master. However, in this guide, we use the 
Master to run dockerized versions of etcd, ZooKeeper, and Marathon.

Follow the [Mesos Master and Cluster Preparation Guide]
(MesosClusterPreparation.md) for information on configuring these 
services to run on your Mesos Master.

## 2. Install Mesos Slave, Netmodules, and Calico
Choose one of the following guides to install Mesos with Calico:

### a.) RPM
The [Calico-Mesos RPM Installation Guide](RpmInstallCalicoMesos.md) serves as the fastest way to get up and running, by installing Mesos, Netmodules, and Calico onto your system.

### b.) Manual
For an in-depth walkthrough of the full installation procedure performed by the RPMs, see the [Calico-Mesos Manual Install Guide](ManualInstallCalicoMesos.md).

### c.) Dockerized Deployment
For those of you that don't want to install mesos onto your hosts, 
we've dockerized the services and already included Calico in them. 
See the [Dockerized Mesos Guide](DockerizedDeployment.md) for info on how to get up and running, fast.

## 3. Launching Tasks
Calico is compatible with all frameworks which use the new NetworkInfo protobuf when launching tasks. Marathon has introduced limited support for this. For an early peek at using this , use `mesosphere/marathon:v0.14.0-RC2`.

But first, you'll need to open tcp port 8080 on your firewall 
Marathon port on your firewall to connect to Marathon. 
Here's an example `firewalld` config command to do this:

```
sudo firewall-cmd --zone=public --add-port=8080/tcp --permanent
sudo systemctl restart firewalld
```

Now you can run a task with Marathon:

```
docker run \
-e MARATHON_MASTER=zk://<ZOOKEEPER-IP>:2181/mesos \
-e MARATHON_ZK=zk://<ZOOKEEPER-IP>:2181/marathon \
-p 8080:8080 \
mesosphere/marathon:v0.14.0-RC2
```
This version of Marathon supports two new fields in an application's JSON file:

- `ipAddress`: Specifiying this field grants the application an IP Address networked by Calico.
- `group`: Groups are roughly equivalent to Calico Profiles. The default implementation isolates applications so they can only communicate with other applications in the same group. Assign a task the static `public` group to allow it to communicate with any other application.
 
> See [Marathon's IP-Per-Task documentation][marathon-ip-per-task-doc] for more information.

The Marathon UI has does not yet include a field for specifiying NetworkInfo, so we'll use the command line to launch an app with Marathon's REST API. Below is a sample `app.json` file that is configured to receive an address from Calico:
```
{
    "id":"/calico-apps",
    "apps": [
        {
            "id": "hello-world-1",
            "cmd": "ifconfig && sleep 30",
            "cpus": 0.1,
            "mem": 64.0,
            "ipAddress": {
                "groups": ["my-group-1"]
            }
        }
    ]
}
```

Send the `app.json` to marathon to launch it:
```
curl -X PUT -H "Content-Type: application/json" http://localhost:8080/v2/groups/calico-apps  -d @app.json
```

[calico]: http://projectcalico.org
[mesos]: https://mesos.apache.org/
[net-modules]: https://github.com/mesosphere/net-modules
[docker]: https://www.docker.com/
[marathon-ip-per-task-doc]: https://github.com/mesosphere/marathon/blob/v0.14.0-RC1/docs/docs/ip-per-task.md
[![Analytics](https://ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/mesos/README.md?pixel)](https://github.com/igrigorik/ga-beacon)
