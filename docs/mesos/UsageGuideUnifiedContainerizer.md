<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.19.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Using Calico Mesos and the Unified Containerizer
The following information includes application json and information on launching tasks in a Mesos Cluster with Calico.

## Prerequisites
This guide assumes you have a cluster configured with a Mesos Master and at least
one Mesos Agent running Calico Mesos.

Your cluster must have the following components installed:

- On Master
   	- Mesos Master
- On each Agent
   	- Mesos Slave
   	- Netmodules
- Anywhere
   	- Marathon
    - Zookeeper
    - Etcd

You can start a cluster in one of the following ways:

- [Vagrant](./Vagrant.md) - easily set up a cluster with all base requirements.
- Manual Install:
	- [Mesos Cluster Preparation guide](MesosClusterPreparation.md) - install
	  required components for a Calico-Mesos Cluster.
	- [Install Calico](ManualInstallCalicoUnifiedContainerizer.md) - install Calico
      on each agent for use with the Unified Containerizer.



## Launching Tasks with Marathon
Calico is compatible with all frameworks which use the new NetworkInfo protobuf when
launching tasks. Marathon has introduced limited support for this in v0.14.0.

### Launching Marathon
If you have not installed Marathon, you can run Marathon directly by running
the commands [here](MesosClusterPreparation.md#marathon), or you can quickly
start it as a Docker container like the following:

```
docker run \
-e MARATHON_MASTER=zk://<ZOOKEEPER_IP>:2181/mesos \
-e MARATHON_ZK=zk://<ZOOKEEPER_IP>:2181/marathon \
-p 8080:8080 \
mesosphere/marathon:v0.14.0
```

### Launching Tasks
Marathon-v0.14.0 supports two new fields in an application's JSON file:

- `ipAddress`: Specifiying this field grants the application an IP Address
networked by Calico.
- `groups`: Groups are roughly equivalent to Calico Profiles. The default
implementation isolates applications so they can only communicate with
other applications in the same group. Assign the static `public` group
to a task to allow it to communicate with any other application.
 
> See [Marathon's IP-Per-Task documentation][marathon-ip-per-task-doc] for more information.

The Marathon UI does not yet include a field for specifiying NetworkInfo,
so we'll use the command line to launch an app with Marathon's REST API.

#### Create a JSON file

Below is a sample JSON application that is configured to receive an address
from Calico. Copy this into a file called `app.json`:

```
{
    "id": "hello-world-1",
    "cmd": "ip addr && sleep 360000",
    "cpus": 0.1,
    "mem": 64.0,
    "ipAddress": {
        "groups": ["my-group-1"]
    }
}
```

This JSON application will start a task that:
 - Prints the container's IP address information to stdout
 - Sleeps for 100 hours

#### Launch the Task
You can curl `app.json` using Marathon's REST API to launch
the application:

```
curl -X POST -H "Content-Type: application/json" http://localhost:8080/v2/apps -d @app.json
```

#### View Marathon UI
You can view the Marathon UI by visiting `http://<MARATHON_HOST>:8080`
from a browser, where `<MARATHON_HOST>` is the IP address or hostname
of the machine that is running Marathon.

In the browser, you will see your list of applications, which will contain
your `hello-world-1` app. Your app should be in the `Running` state.
Click on the application to see its list of running tasks.

You should now see a `hello-world-1.#####...` task in the application's
task list, along with a Calico-assigned IP address just below the Task
ID!

[calico-slack]: https://calicousers-slackin.herokuapp.com/
[marathon-ip-per-task-doc]: https://github.com/mesosphere/marathon/blob/v0.14.0/docs/docs/ip-per-task.md
[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/mesos/UsageGuideUnifiedContainerizer.md?pixel)](https://github.com/igrigorik/ga-beacon)
