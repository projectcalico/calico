# Calico on docker
This project demonstrates Calico running in a docker environment. If you do try using it, let us know how you get on by email (or just add a comment to the wiki).


## What it covers

+ Calico components running in Docker containers
+ Calico can provide network connectivity with security policy enforcement to Docker containers.


## Getting started 

To get started follow the instruction here [Getting Started](docs/GettingStarted.md). It covers setting up a couple of CoreOS servers using Vagrant to use as docker hosts.

## How does it work?

It's well worth getting a good feel for what Calico is, and what the various
components are. There's a lot of general background in the
[Project Calico website](http://www.projectcalico.org), and for Docker in the
[Docker website](https://www.docker.com/), but this section explains what the
various component pieces are and how they work.

First, let's run through what the demo covers in a bit more detail. Calico's
job is to network endpoints (which in this context means "containers", but
elsewhere could mean VMs). When an endpoint is created by the orchestrator, it
tells Calico to configure networking and security policies for the endpoint. To
do that, there are several major components.

1. There is the orchestrator itself - responsible for creating and destroying
   endpoints, assigning them to security groups and generally managing the
   whole process. In the demo, there is no orchestrator, and this function is
   performed by the `calico` command.

2. To configure endpoint networks, the orchestrator calls into a "plugin" (a
   Calico component that is specific to the orchestrator in use). In the demo,
   the plugin is simply a python process that reads information from text files
   (and so the "interface" is just writing those text files).  The plugin
   can then offer the information it reads to the other components.

3. Next there is the ACL Manager. This is a production Calico
   component, whose job it is to figure out the ACL configuration that the Felix component (see below)
   must apply based on which security groups are in use and which rules
   apply; Felix asks for that information as it needs it.

4. Felix (a production Calico component) and BIRD (a standard open source BGP protocol stack) work together to configure Linux forwarding and to signal reachability to the rest of the network. Felix's job is to
   configure endpoints, creating routes to them, configuring rules that enforce
   security, and generally doing the local configuration based on the data
   provided by the dummy orchestrator plugin and BIRD replicates those routes to other compute hosts.


Apart from the "orchestrator" which is just represented by the `calico` command, the
above components are all implemented in privileged containers, running in the
network namespace of the host. These containers are as follows.

* `felix` contains Felix. Although this is production code, the configuration
  has been changed so Felix polls for a complete resync of endpoint data every
  few seconds (instead of being notified of changes).

* `aclmgr` contains the ACL Manager.

* The dummy orchestrator plugin has two containers, `plugin_ep` and `plugin_net`, implementing the
  Endpoint API to Felix and the Network API to the ACL Manager
  respectively. There is no profound reason for that split; it just simplifies
  the demo code.

    As noted, the plugin code relies on Felix polling it for data; it also just
    reports all configuration (whether changed or not) to the ACL Manager every
    15 seconds.
    
* `bird` contains the BIRD BGP protocol stack.

The containers use four different images, each with configuration set (through
the Dockerfile) for the environment in question.

* `calico:bird` contains a BIRD image, with configuration files for each host.

* `calico:plugin` contains code for the dummy orchestrator plugin (both containers).

* `calico:felix` contains code for both Felix and the ACL Manager.

All of the privileged containers use some or other of the host directories to
allow logging and reading of data files.

When an endpoint is added, the flow of events is as follows.

* The container for that endpoint is manually created using the `docker`
  command line, and the `network_container` script is run both to create the
  relevant interface and to set up the text files for the dummy orchestrator plugin to read.

* The two dummy orchestrator plugin containers are being polled for changes to endpoint
  configuration, and so repeatedly reading these files. They therefore
  propagate the new state to Felix and the ACL Manager.

* Felix configures routes and rules. As part of this process, it sends a
  request to the ACL Manager asking for updated security rules to apply.

* Finally, as soon as the route comes into existence, BIRD propagates the route
  to the other host (or hosts).


