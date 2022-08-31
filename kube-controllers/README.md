# Calico Controllers for Kubernetes
<img src="http://docs.projectcalico.org/images/felix.png" width="100" height="100">

This repository contains a collection of kubernetes controllers for Calico. There are several controllers, each of which monitors
the resources in the Kubernetes API and performs a specific job in response to events. The source for each controller can be found
in the [pkg/controllers][controllers-src] directory.

For more information on what each does, see [the Calico documentation][calico-docs].

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

- `make docker-image` will produce a docker image containing the artifacts suitable for deploying to kubernetes.
- `make binary` will build just the controller binary so it can be run locally.

For more information, see `make help`.

[controllers-src]: https://github.com/projectcalico/calico/tree/master/kube-controllers/pkg/controllers
[calico-docs]: https://docs.projectcalico.org/latest/reference/kube-controllers/configuration
