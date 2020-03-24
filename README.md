[![Build Status](https://semaphoreci.com/api/v1/calico/cni-plugin/branches/master/shields_badge.svg)](https://semaphoreci.com/calico/cni-plugin)
[![Slack Status](https://slack.projectcalico.org/badge.svg)](https://slack.projectcalico.org)
[![IRC Channel](https://img.shields.io/badge/irc-%23calico-blue.svg)](https://kiwiirc.com/client/irc.freenode.net/#calico)

# Calico Networking for CNI

<blockquote>
Note that the documentation in this repo is targeted at Calico contributors.
<h1>Documentation for Calico users is here:<br><a href="http://docs.projectcalico.org">http://docs.projectcalico.org</a></h1>
</blockquote>

This repository contains the Project Calico network plugin for CNI.  This plugin allows you to use Calico networking for
any orchestrator which makes use of the [CNI networking specification][cni specification].

This repository includes a top-level CNI networking plugin, as well as a CNI IPAM plugin which makes use of Calico IPAM.

To learn more about CNI, visit the [containernetworking/cni][cni] repo.

## Building the plugins and running tests
To build the Calico Networking Plugin for CNI locally, clone this repository and run `make`.  This will build both CNI plugin binaries and run the tests. This requires a recent version of Docker.

- To just build the binaries, with no tests, run `make build`. This will produce `bin/$ARCH/calico` and `bin/$ARCH/calico-ipam`.
- To only run the tests, simply run `make test`.
- To run a non-containerized build (i.e. not inside a docker container) you need to have Go 1.7+ and glide installed.

[cni]: https://github.com/containernetworking/cni
[cni specification]: https://github.com/containernetworking/cni/blob/master/SPEC.md
[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-cni/README.md?pixel)](https://github.com/igrigorik/ga-beacon)

## License

Calico binaries are licensed under the [Apache v2.0 license](LICENSE), with the exception of some [GPL licensed eBPF programs](https://github.com/projectcalico/felix/tree/master/bpf-gpl).

Calico imports packages with a number of apache-compatible licenses. For more information, see [filesystem/licenses](./filesystem/licenses). In addition, the base container image contains
pre-packaged software with a variety of licenses.
