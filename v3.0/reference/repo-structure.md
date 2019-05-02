---
title: Calico Repositories
canonical_url: 'https://docs.projectcalico.org/v3.2/reference/repo-structure'
---

The following information details which artifacts are built from which
repositories.

## Core Components

### [Felix](https://github.com/projectcalico/felix)

| Artifact | Type | Description |
|---------|-------|-----------|
| felix | Binary | Felix interfaces with the Linux kernel to configure routes and ACLs that control network policy and connectivity. |


### [calicoctl](https://github.com/projectcalico/calicoctl)

| Artifact | Type | Description |
|---------|-------|-----------|
| calico/node | Docker Image |  The Docker image used to run Felix and the BIRD BGP agent (for distributing routes between hosts).  See [calico/node reference]({{site.baseurl}}/{{page.version}}/reference/architecture/components) for details. |
| calicoctl | Binary | The command line tool for interacting with the Calico API.  See [calicoctl reference]({{site.baseurl}}/{{page.version}}/reference/calicoctl) for more info. |

## Libraries

### [libcalico](https://github.com/projectcalico/libcalico)

| Artifact | Type | Description |
|---------|-------|-----------|
| libcalico | pypi library | Contains a variety of helper methods and classes for manipulating the Calico data in an etcd datastore, IP address management and useful namespace utilities to manipulating container interfaces. |
| calico/test | Docker Image | Contains useful shared testing framework code and dependencies for running unit and system tests of Calico in Docker. |
| calico/build | Docker Image | Build image which includes libcalico and the necessary python tooling to produce binaries from python source code. |

## [libcalico-go](https://github.com/projectcalico/libcalico-go)

| Artifact | Type | Description |
|---------|-------|-----------|
| libcalico-go | golang library | Contains a variety of helper methods and classes for interacting with the Calico API. |

## Orchestrator Plugins

There are several integrations available for Calico in a containerized
environment.  The repositories below hold the plugin code for these
integrations.

## [cni-plugin](https://github.com/projectcalico/cni-plugin)

| Artifact | Type | Description |
|---------|-------|-----------|
| calico | binary | Calico networking plugin for any orchestrator that uses the [Container Network Interface](https://github.com/appc/cni), e.g. [rkt](https://github.com/coreos/rkt), [Kubernetes](https://github.com/kubernetes/kubernetes), and [Mesos](https://github.com/apache/mesos). |
| calico-ipam | binary | Calico CNI IP address management plugin. |

## [libnetwork-plugin](https://github.com/projectcalico/libnetwork-plugin)

| Artifact | Type | Description |
|---------|-------|-----------|
| libnetwork-plugin | binary | Docker networking plugin for use with Docker and Docker Swarm. It provides both network and IPAM drivers which may be used when creating networks through Docker. |


## [kube-controllers](https://github.com/projectcalico/kube-controllers)

| Artifact | Type | Description |
|----------|-----|-------------|
| calico/kube-controllers | Docker Image | Integrates with the Kubernetes API for additional features. |
