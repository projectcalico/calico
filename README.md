[![CircleCI branch](https://img.shields.io/circleci/project/projectcalico/calico-cni/master.svg)](https://circleci.com/gh/projectcalico/calico-cni/tree/master)
[![Coverage Status](https://coveralls.io/repos/projectcalico/calico-cni/badge.svg?branch=master&service=github)](https://coveralls.io/github/projectcalico/calico-cni?branch=master)
[![Slack Status](https://calicousers-slackin.herokuapp.com/badge.svg)](https://calicousers-slackin.herokuapp.com)
[![IRC Channel](https://img.shields.io/badge/irc-%23calico-blue.svg)](https://kiwiirc.com/client/irc.freenode.net/#calico)

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

[![Analytics](https://ga-beacon.appspot.com/UA-52125893-3/calico-cni/README.md?pixel)](https://github.com/igrigorik/ga-beacon)
