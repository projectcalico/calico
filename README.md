# Calico Networking for CNI 

This repository contains the Project Calico network plugin for CNI.  This plugin allows you to use Calico networking for
any orchestrator which makes use of the CNI networking specification.

This plugin allows you to use Project Calico networking with:
- [Kubernetes](docs/kubernetes.md)
- [rkt](docs/rkt.md)

This repository also includes a CNI IPAM plugin which uses Calico IPAM.

To learn more about CNI, visit the [appc/cni](https://github.com/appc/cni) repo.

## Building the plugin
To build the Calico Networking Plugin for CNI locally, clone this repository and run `make`.  This will build the binary, as well as run the unit tests.  To just build the binary, with no tests, run `make binary`.  To only run the unit tests, simply run `make ut`.

[![Analytics](https://ga-beacon.appspot.com/UA-52125893-3/calico-rkt/README.md?pixel)](https://github.com/igrigorik/ga-beacon)
