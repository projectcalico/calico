# Calico on docker
This project demonstrates Calico running in a docker environment. If you do try using it, let us know how you get on by email (or just add a comment to the wiki).


## What it covers

Currently, this is a demonstration / proof of concept of Calico deployed in a Docker environment.

+ It shows that Felix and the ACL Manager can run in Docker containers on the
  host (using standard production code).

+ It shows that BIRD (BGP) servers can be installed and run on a Docker
  container on the host, and can configure routing between endpoints
  (containers in this case).

+ It shows that it is possible to write a plugin that interoperates
  successfully with Felix and the ACL Manager to report status and program
  endpoints (though the plugin is not production code, and is therefore quite
  basic).

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
elsewhere could mean VMs). When an endpoint is created by the orchestration, it
tells Calico to configure networking and security policies for the endpoint. To
do that, there are several major components.

1. There is the orchestration itself - responsible for creating and destroying
   endpoints, assigning them to security groups and generally managing the
   whole process. In the demo, there is no orchestration, and this function is
   performed by the `calico` command.


2. To configure endpoint networks, the orchestration calls into a "plugin" (a
   Calico component that is specific to the orchestration in use). In the demo,
   the plugin is simply a python process that reads information from text files
   (and so the "interface" is just writing those text files).  The demo plugin
   can then offer the information it reads to the other components.

3. Felix is the first production component in the demo. Felix's job is to
   configure endpoints, creating routes to them, configuring rules that enforce
   security, and generally doing the local configuration based on the data
   provided by the plugin.

4. Once Felix has configured routes, those routes need to be replicated to
   other compute hosts. That is the job of BIRD, a standard open source BGP
   server.

5. Finally, there is the ACL Manager. This is another production Calico
   component, whose job it is to figure out the ACL configuration that Felix
   must apply based on which security groups are in use and which rules
   apply; Felix asks for that information as it needs it.

Apart from the "orchestration" which is just represented by the `calico` command, the
above components are all implemented in privileged containers, running in the
network namespace of the host. These containers are as follows.

* `felix` contains Felix. Although this is production code, the configuration
  has been changed so Felix polls for a complete resync of endpoint data every
  few seconds (instead of being notified of changes).

* `aclmgr` contains the ACL Manager.

* The plugin has two containers, `plugin_ep` and `plugin_net`, implementing the
  Endpoint API to Felix and the Network API to the ACL Manager
  respectively. There is no profound reason for that split; it just simplifies
  the demo code.

    As noted, the plugin code relies on Felix polling it for data; it also just
    reports all configuration (whether changed or not) to the ACL Manager every
    15 seconds.
    
* `bird` contains the BIRD BGP server.

The containers use four different images, each with configuration set (through
the Dockerfile) for the environment in question.

* `calico:bird` contains a BIRD image, with configuration files for each host.

* `calico:plugin` contains code for the demo plugin (both containers).

* `calico:felix` contains code for both Felix and the ACL Manager.

All of the privileged containers use some or other of the host directories to
allow logging and reading of data files.

When an endpoint is added, the flow of events is as follows.

* The container for that endpoint is manually created using the `docker`
  command line, and the `network_container` script is run both to create the
  relevant interface and to set up the text files for the plugin to read.

* The two plugin containers are being polled for changes to endpoint
  configuration, and so repeatedly reading these files. They therefore
  propagate the new state to Felix and the ACL Manager.

* Felix configures routes and rules. As part of this process, it sends a
  request to the ACL Manager asking for updated security rules to apply.

* Finally, as soon as the route comes into existence, BIRD propagates the route
  to the other host (or hosts).


