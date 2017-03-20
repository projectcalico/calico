[![Build Status](https://semaphoreci.com/api/v1/calico/calico-cni-2/branches/master/badge.svg)](https://semaphoreci.com/calico/calico-cni-2)
[![Slack Status](https://slack.projectcalico.org/badge.svg)](https://slack.projectcalico.org)
[![IRC Channel](https://img.shields.io/badge/irc-%23calico-blue.svg)](https://kiwiirc.com/client/irc.freenode.net/#calico)

# Calico Networking for CNI 

<blockquote>
Note that the documentation in this repo is targeted at Calico contributors.
<h1>Documentation for Calico users is here:<br><a href="http://docs.projectcalico.org">http://docs.projectcalico.org</a></h1>
</blockquote>

This repository contains the Project Calico network plugin for CNI.  This plugin allows you to use Calico networking for
any orchestrator which makes use of the [CNI networking specification][cni].

This repository includes a top-level CNI networking plugin, as well as a CNI IPAM plugin which makes use of Calico IPAM.

To learn more about CNI, visit the [appc/cni][cni] repo.

## Building the plugins and running tests
To build the Calico Networking Plugin for CNI locally, clone this repository and run `make`.  This will build both CNI plugin binaries and run the tests. This requires a recent version of Docker.

- To just build the binaries, with no tests, run `make binary`. This will produce `dist/calico` and `dist/calico-ipam`.
- To only run the tests, simply run `make test`.
- To run a non-containerized build (i.e. not inside a docker container) you need to have Go 1.7+ and glide installed. 
[cni]: https://github.com/appc/cni

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-cni/README.md?pixel)](https://github.com/igrigorik/ga-beacon)
