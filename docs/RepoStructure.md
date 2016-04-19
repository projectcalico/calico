<!--- master only -->
> ![warning](images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.19.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Calico Repositories

## The calico-containers repository

This respository contains the following:

- `calico/node`: the Docker image used to run the Calico Felix agent 
  (responsible for IP routing and ACL programming) and a BIRD BGP agent (for 
  distributing routes between hosts).  See [`calico_node` directory](../calico_node)
  for details.
- `calicoctl`: the command line tool used for starting a `calico/node`
  container, configuring Calico policy, adding and removing containers in a 
  Calico network via orchestration tools, and managing certain network and 
  diagnostic administration.  See [`calicoctl` directory](../calicoctl) for
  implementation of calicoctl.  This directory also contains a `calico/build` 
  Docker image which is used to build the `calicoctl` binary.
- `calico/test`: the Docker image used for running both UTs and STs testing
  Calico with Docker.  The [`calico_test` directory](../calico_test) contains 
  the Docker file and associated files for the `calico/test image`.  This 
  includes a set of utility Python files for running STs.  This image is used 
  by the calico-containers STs and UTs.
- UTs testing calicoctl, STs testing single host and multihost systems
  using calicoctl and calico/node to create Calico networked containers.  These
  tests run within the `calico/test` Docker image.  See the [`tests` directory](../tests)
  for the UT and ST codebase.  Also see the [`Makefile`](../Makefile) for
  details on how the STs (`make st`) and UTs (`make ut`) are run using the 
  `calico/test` image.
- Documentation for using Calico in a containerized environment.  See 
  main [README.md](../README.md), and [`docs` directory](../docs).
- Release scripts used to validate our documentation and to cut a new branch
  for a specific release.  See [`release-scripts` directory](../release-scripts)
  for details.

It pulls together a number of related repositories that provide subsets of
function for running Calico in a containerized environment.  These related 
respositories are listed below.

## Calico Libraries

 - [calico](https://github.com/projectcalico/calico): This repo contains the
   implementation of Felix which is the heart of Calico networking.  Felix 
   interfaces with the Linux kernel to configure routes and ACLs 
   that control network policy connectivity. In `calico/node`, Felix runs as a 
   separate process.  It is installed directly into the `calico/node` image.

 - [libcalico](https://github.com/projectcalico/libcalico): Contains a variety
   of helper methods and classes for manipulating the Calico data in an etcd
   datastore, IP address management and useful namespace utilities to 
   manipulating container interfaces.  The libcalico library is used by
   `calicoctl`.  It is imported as a standard Python library into the 
   `calicoctl` Python codebase.

## Calico Orchestrator Integration Plugins

There are several integrations available for Calico in a containerized 
environment.  The repositories below hold the plugin code for these 
integrations.

 - [calico-mesos](https://github.com/projectcalico/calico-mesos): Implements
   the Calico plugin for running Calico with the [mesos](https://github.com/apache/mesos) 
   orchestrator.  This plugin may be installed manually (from a binary attached
   to a relase), or as an RPM which can be created.

 - [calico-cni](https://github.com/projectcalico/calico-cni): Implements the 
   Calico plugin for running Calico with any orchestrator that uses the 
   [Container Network Interface](https://github.com/appc/cni), including [rkt](https://github.com/coreos/rkt)
   and [Kubernetes](https://github.com/kubernetes/kubernetes)

 - [libnetwork-plugin](https://github.com/projectcalico/libnetwork-plugin): 
   Implements Calico plugin support for the (libnetwork based) Docker 
   networking plugin.  It provides both network and IPAM drivers which may
   be used when creating networks through Docker.  The driver is built as a
   Docker image (available on DockerHub).  When Calico node is started with the
   `--libnetwork` flag, a separate container is launched running the driver.

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/RepoStructure.md?pixel)](https://github.com/igrigorik/ga-beacon)
