[![CircleCI branch](https://img.shields.io/circleci/project/projectcalico/calico-cni/master.svg)](https://circleci.com/gh/projectcalico/calico-cni/tree/master)
[![Build Status](https://semaphoreci.com/api/v1/calico/calico-cni-2/branches/master/badge.svg)](https://semaphoreci.com/calico/calico-cni-2)
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
To build the Calico Networking Plugin for CNI locally, clone this repository and run `make`.  This will build both CNI plugin binaries and run the tests.

- To just build the binaries, with no tests, run `make binary`. This will produce `dist/calico` and `dist/calico-ipam`.
- To only run the tests, simply run `make test`.

## Release process
* Create a release on Github and use it to create a tag
* Check the tag out locally and run
    * `make release`
* Attach `dist/calico` and `dist/calico-ipam` to the Github release

[cni]: https://github.com/appc/cni
[config]: configuration.md
[calico-containers]: https://github.com/projectcalico/calico-containers/blob/master/docs/cni/kubernetes/README.md

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-cni/README.md?pixel)](https://github.com/igrigorik/ga-beacon)
