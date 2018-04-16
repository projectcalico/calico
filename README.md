# calico/node
<img src="http://docs.projectcalico.org/images/felix.png" width="100" height="100">

This repository contains the source for the `calico/node` container.

## Get Started Using Calico

For users who want to learn more about the project or get started with Calico, see the documentation on [docs.projectcalico.org](https://docs.projectcalico.org).

## Get Started Developing Calico

### Dependencies

The entire build can be run within a container, which means the only dependencies you'll need are a [functioning Docker installation](https://docs.docker.com/engine/installation/).

If you'd like to run the build and tests locally outside of a container, you'll need the following dependencies:

- [go v1.8+](https://golang.org/doc/install)
- [glide](https://github.com/Masterminds/glide/)

### Building

Contributions to this code are welcome!  The code in this repository can be built and tested using the Makefile.

- `make calico/node` will produce a docker image containing the artifacts suitable for deploying to kubernetes.

For more information, see `make help`.

[kdd]: http://docs.projectcalico.org/v2.0/getting-started/kubernetes/installation/hosted/k8s-backend/
