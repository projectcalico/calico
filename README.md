[![CircleCI branch](https://img.shields.io/circleci/project/projectcalico/calico-cni/master.svg)](https://circleci.com/gh/projectcalico/calico-cni/tree/master)
[![Coverage Status](https://coveralls.io/repos/projectcalico/calico-cni/badge.svg?branch=master&service=github)](https://coveralls.io/github/projectcalico/calico-cni?branch=master)
[![Slack Status](https://slack.projectcalico.org/badge.svg)](https://slack.projectcalico.org)
[![IRC Channel](https://img.shields.io/badge/irc-%23calico-blue.svg)](https://kiwiirc.com/client/irc.freenode.net/#calico)

# Calico Networking for CNI 

This repository contains the Project Calico network plugin for CNI.  This plugin allows you to use Calico networking for
any orchestrator which makes use of the [CNI networking specification][cni].

This repository includes a top-level CNI networking plugin, as well as a CNI IPAM plugin which makes use of Calico IPAM.

For details of configuration, see the [configuration.md][config] file.

The [calico-containers repository][calico-containers] contains getting started guides for a number of scenarios, as well as more detailed documentation regarding our CNI integration.

To learn more about CNI, visit the [appc/cni][cni] repo.

## Building the plugins and running tests
To build the Calico Networking Plugin for CNI locally, clone this repository and run `make`.  This will build both CNI plugin binaries and run the unit and fv tests.

- To just build the binaries, with no tests, run `make binary`. This will produce `dist/calico` and `dist/calico-ipam`.
- To only run the unit tests, simply run `make ut`.
- To only run the fv tests, simply run `make fv`.

[cni]: https://github.com/appc/cni
[config]: configuration.md
[calico-containers]: https://github.com/projectcalico/calico-containers/blob/master/docs/cni/kubernetes/README.md

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-cni/README.md?pixel)](https://github.com/igrigorik/ga-beacon)
