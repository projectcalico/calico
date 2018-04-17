# calico/node
<img src="http://docs.projectcalico.org/images/felix.png" width="100" height="100">

This repository contains the source for the `calico/node` container.

## Get Started Using Calico

For users who want to learn more about the project or get started with Calico, see the documentation on [docs.projectcalico.org](https://docs.projectcalico.org).

## Get Started Developing Calico

Contributions to this code are welcome! Before starting, make sure you've read [the Calico contributor guide][contrib].

### Dependencies

The entire build can be run within a container, which means the only dependencies you'll need are a [functioning Docker installation](https://docs.docker.com/engine/installation/).

### Building

The code in this repository can be built and tested using the Makefile.

- `make calico/node` will produce the `calico/node` docker image.

For more information, see `make help`.

[contrib]: https://github.com/projectcalico/calico/blob/master/CONTRIBUTING_CODE.md
