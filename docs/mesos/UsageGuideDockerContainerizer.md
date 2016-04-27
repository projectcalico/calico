<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.19.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Calico-Mesos Usage Guide with the Docker Containerizer

The following instructions outline the steps required to enable and manage 
Calico networked containers launched from Marathon using the Mesos Docker
containerizer.  This guide covers:
-  Installing and configuring Calico
-  Creating a Docker network and managing network policy
-  Launching a container

## Prerequisites

You can easily configure a mesos cluster by running through
the [Calico Mesos Vagrant guide](./Vagrant.md). If you do this, you can skip
directly to [Launching Containers](#launching-containers).

To utilize the Docker libnetwork plugin feature of Docker, it is necessary to 
run with a Docker version 1.9 or higher, and to configure Docker to use a
cluster store.  

#### Required Machines 

The cluster must contain the following machines:

- Mesos Master
- Mesos Agent(s)
	- Docker 1.9+ (see below)

#### Required Services

You will also need to run the following services somewhere in your cluster:

- Marathon
- Etcd

It is easiest to just run these services on the Mesos Master machine.
Each machine in the cluster must have access to these services.

#### Run Calico

You will need Calico running on each of your agents.  Follow our [Manual Install
Calico with Docker Containerizer guide](./ManualInstallCalicoDockerContainerizer.md)
to do this.

## Creating a Docker network and managing network policy

Before we can start launching tasks, we must first create a docker network with Calico.

With Calico, a Docker network represents a logical set of rules that defines the 
allowed traffic in and out of containers assigned to that network.  The rules
are encapsulated in a Calico "profile".  Each Docker network is assigned its 
own Calico profile.

To create a Docker network using Calico, run the `docker network create`
command specifying "calico" as both the network and IPAM driver.

```
docker network create --driver calico --ipam-driver calico databases 
```

#### View the policy associated with the network

You can use the `calicoctl profile <profile> rule show` to display the
rules in the profile associated with the `databases` network.

The network name can be supplied as the profile name and the `calicoctl` tool
will look up the profile associated with that network.

```
$ ETCD_AUTHORITY=<IP address>:4001
$ calicoctl profile databases rule show
Inbound rules:
   1 allow from tag databases
Outbound rules:
   1 allow
```

As you can see, the default rules allow all outbound traffic and accept inbound
traffic only from containers attached the "databases" network.

> Note that when managing profiles created by the Calico network driver, the
> profile tag and network name can be regarded as the same thing.

For more information no how to configure your Calico profiles, check out
the section on [Configuring the network policy in our Advanced Policy guide]
(../calico-with-docker/docker-network-plugin/AdvancedPolicy.md#configuring-the-network-policy).

## Launching Containers

With your networks configured, it is trivial to launch a Docker container 
through Mesos using the standard Marathon UI and API.

#### Launching a container through the UI

You can launch Docker task through the Marathon UI at `MARATHON_IP:8080`.
Select an arbitrary(*) network (Bridge or Host), and then provide the
following additional parameter (under the Docker options):

```
Key = net
Value = <network name>
```

Where `<network name>` is the name of the network, for example "databases".

> (*) The selection is arbitrary because the additional net parameter overrides
> the selected network type.

#### Launching a container with a JSON blob

To launch a Calico-networked application using the Marathon API
with a JSON blob, simply include the net parameter in the request.
For example:

```
{
    "id": "docker-task",
    "cmd": "ip addr && sleep 30",
    "cpus": 0.1,
    "mem": 64.0,
    "ipAddress": {},
    "container": {
        "type": "DOCKER",
        "docker": {
            "image": "busybox",
            "parameters": [
                {"key": "net", "value": "databases"}
            ]
        }
    }
}
```

This JSON application will start a task that:
 - Prints the container's IP address information to stdout
 - Sleeps for 30 seconds

When the application is running, it will start a task that runs
until the command in the `cmd` field has terminated (in this
case ~30 seconds with the sleep command). At that point, the
task will be completed and the task's container will be removed.
The application will then start a new task with the same criteria.

You can launch this JSON blob task by calling into the Marathon REST API
with a command like the following:

	curl -X POST -H "Content-Type: application/json" http://<MARATHON_IP>:8080/v2/apps -d @blob.json

You can view the Marathon UI by visiting `http://<MARATHON_HOST>:8080`
from a browser, where `<MARATHON_HOST>` is the IP address or hostname
of the machine that is running Marathon.

In the browser, you will see your list of applications, which will contain
your `docker-task` app. Your app should be in the `Running` state.
Click on the application to see its list of running tasks.

You should now see a `docker-task.#####...` task in the application's
task list, along with a Calico-assigned IP address just below the Task
ID!

Remember that this task will disappear and reappear every 30 seconds.
You should see the IP address change each time the task starts.


[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/mesos/UsageGuideDockerContainerizer.md?pixel)](https://github.com/igrigorik/ga-beacon)
