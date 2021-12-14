[![Build Status](https://semaphoreci.com/api/v1/calico/libcalico-go/branches/master/shields_badge.svg)](https://semaphoreci.com/calico/libcalico-go)
[![Slack Status](https://slack.projectcalico.org/badge.svg)](https://slack.projectcalico.org)
[![IRC Channel](https://img.shields.io/badge/irc-%23calico-blue.svg)](https://kiwiirc.com/client/irc.freenode.net/#calico) [
![GoDoc](https://godoc.org/github.com/golang/gddo?status.svg)](http://godoc.org/github.com/projectcalico/libcalico-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/projectcalico/libcalico-go)](https://goreportcard.com/report/github.com/projectcalico/libcalico-go)

# libcalico-go

<img src="http://docs.projectcalico.org/images/felix.png" width="100" height="100">

**Note: This library is intended for internal use only. See [github.com/projectcalico/api](https://github.com/projectcalico/api) for the officially supported API
definition and golang clients.**

This repository contains the internal library for interacting with the Calico data store as well as common source code used across Calico components. Note that the APIs defined in this library are not guaranteed to be forwards or backwards compatible and may change at any time without notice.

Calico is a Tigera open source project, and is primarily maintained by the Tigera team. However any members of the community – individuals or organizations – are welcome to get involved and contribute to the project.

## Get Started Using Calico

For users who want to learn more about the project or get started with Calico, see the documentation on [docs.projectcalico.org](https://docs.projectcalico.org).

## Get Started Developing Calico

### Making changes to libcalico-go

Contributions to this code are welcome!  The code in this repository can be built and tested using the Makefile.

To run the fast set of unit tests within a containerized environment (requires a [functioning Docker installation](https://docs.docker.com/engine/installation/)):

    make ut

For more information on available targets, see `make help`.

### Developing against libcalico-go

If you wish to use libcalico for integrating with Calico networking and
policy, the main entry point to managing Calico configuration is through
the client.

-  Documentation for the client is in [lib/client GoDoc](https://godoc.org/github.com/projectcalico/libcalico-go/lib/client).
-  The resource structure definitions are defined in [lib/apis](https://godoc.org/github.com/projectcalico/libcalico-go/lib/apis), this
   includes detailed per-resource and per-field level descriptions.
