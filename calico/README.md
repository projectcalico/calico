[![Slack Status](https://slack.projectcalico.org/badge.svg)](https://slack.projectcalico.org)
[![IRC Channel](https://img.shields.io/badge/irc-%23calico-blue.svg)](https://kiwiirc.com/client/irc.freenode.net/#calico)
[![Docker Pulls](https://img.shields.io/docker/pulls/calico/node.svg)](https://hub.docker.com/r/calico/node/)

# Calico
<img src="http://docs.projectcalico.org/images/felix.png" width="100" height="100">

Calico is an open source networking and network security solution for containers, virtual machines, and bare-metal workloads.
Calico uses standard Linux networking tools to provide two major services for Cloud Native applications:

- Network connectivity between workloads.
- Network security policy enforcement between workloads.

Calico’s flexible architecture supports a wide range of deployment options, using modular components, including:

- [CNI](https://github.com/projectcalico/cni-plugin) plugins for Kubernetes to provide highly efficient pod networking and IP
  Address Management (IPAM).
- A [Neutron ML2](https://github.com/projectcalico/networking-calico) plugin to provide VM networking for OpenStack.
- A policy engine, [Felix](https://github.com/projectcalico/felix), to provide enforcement of the full set of Kubernetes
  network policy features, plus for those needing a richer set of policy features, Calico network policies.
- Both non-overlay and [overlay (via IPIP or VXLAN)](https://docs.projectcalico.org/networking/vxlan-ipip) networking options
  in either public cloud or on-prem deployments.
- A [BGP routing stack](https://docs.projectcalico.org/networking/bgp) that can advertise routes for workload and service IP
  addresses to physical network infrastructure such as Top of Rack routers (ToRs).
- A simple command line interface, [calicoctl](https://github.com/projectcalico/calicoctl), for managing Calico configuration
and Calico network policies.

## Getting Started Running Calico

There are many avenues to get started with Calico depending on your situation.

- Trying out Kubernetes on a single host or on your own hardware? The
  [Quick Start Guide](https://docs.projectcalico.org/getting-started/kubernetes/quickstart) will have you up and running in
  about fifteen minutes.
- Running a managed public cloud? Use our
  [guides for enabling Calico Network Policies](https://docs.projectcalico.org/getting-started/kubernetes/managed-public-cloud/).
- Want to go deeper? Visit [https://docs.projectcalico.org](https://docs.projectcalico.org) for full documentation.

## Getting Started Developing Calico

Calico is an open source project, and welcomes your contribution, be it through code, a bug report, a feature request, or user
feedback.

- [The Contribution Guidelines](CONTRIBUTING_CODE.md) document will get you started on submitting changes to the project.
- [The Developer Guide](DEVELOPER_GUIDE.md) will walk you through how to set up a development environment, build the code,
  and run tests.
- [The Calico Documentation Guide](CONTRIBUTING_DOCS.md) will get you started on making changes to
  [https://docs.projectcalico.org](https://docs.projectcalico.org).

## Join the Calico Community!

The Calico community is committed to fostering an open and welcoming environment, with several ways to engage with other users
and developers. You can find out more about our monthly meetings, Slack group, and Discourse by visiting our
[Community Repository](https://github.com/projectcalico/community).

## License

Calico is open source, with most code and documentation available under the Apache 2.0 license (see the [LICENSE](LICENSE)), though some elements are necessarily licensed under different open source licenses for compatibility with upstream licensing or code linking. For example, some Calico BPF programs are licensed under GPL v2.0 for compatibility with Linux kernel helper functions.

## Calico Enterprise

Calico Enterprise is a commercial product that builds on top of and around the Calico open source project to provide additional capabilities beyond the core Calico feature set. You can learn more [here](https://docs.projectcalico.org/calico-enterprise/). Calico Enterprise is available under commercial license from Tigera.

