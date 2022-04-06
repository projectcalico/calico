# Calico
<img src="http://docs.projectcalico.org/images/felix.png" width="100" height="100">

Calico is a widely adopted, battle-tested open source networking and network security solution for Kubernetes, virtual machines, and bare-metal workloads.
Calico provides two major services for Cloud Native applications:

- Network connectivity between workloads.
- Network security policy enforcement between workloads.

Calico’s flexible architecture supports a wide range of deployment options, using modular components and technologies, including:

- Choice of data plane technology, whether it be [eBPF](https://projectcalico.docs.tigera.io/maintenance/ebpf/use-cases-ebpf), standard Linux, [Windows HNS](https://docs.microsoft.com/en-us/virtualization/windowscontainers/container-networking/architecture) or [VPP](https://github.com/projectcalico/vpp-dataplane)
- Enforcement of the full set of Kubernetes network policy features, plus for those needing a richer set of policy features, Calico network policies.
- An optimized Kubernetes Service implementation using eBPF.
- Kubernetes [apiserver integration](./apiserver), for managing Calico configuration and Calico network policies.
- Both non-overlay and [overlay (via IPIP or VXLAN)](https://projectcalico.docs.tigera.io/networking/vxlan-ipip) networking options in either public cloud or on-prem deployments.
- [CNI plugins](./cni-plugin) for Kubernetes to provide highly efficient pod networking and IP Address Management (IPAM).
- A [Neutron ML2](./networking-calico) plugin to provide VM networking for OpenStack.
- A [BGP routing stack](https://projectcalico.docs.tigera.io/networking/bgp) that can advertise routes for workload and service IP addresses to physical network infrastructure.

## Getting Started Running Calico

There are many avenues to get started with Calico depending on your situation.

- Trying out Kubernetes on a single host or on your own hardware? The
  [quick start guide](https://projectcalico.docs.tigera.io/getting-started/kubernetes/quickstart) will have you up and running in
  about fifteen minutes.
- Running a managed public cloud? Use our
  [guides for enabling Calico network policies](https://projectcalico.docs.tigera.io/getting-started/kubernetes/managed-public-cloud/).
- Want to go deeper? Visit [https://projectcalico.docs.tigera.io](https://projectcalico.docs.tigera.io) for full documentation.

## Getting Started Developing Calico

Calico is an open source project, and welcomes your contribution, be it through code, a bug report, a feature request, or user
feedback.

- [The Contribution Guidelines](CONTRIBUTING_CODE.md) document will get you started on submitting changes to the project.
- [The Developer Guide](DEVELOPER_GUIDE.md) will walk you through how to set up a development environment, build the code, and run tests.
- [The Calico Documentation Guide](CONTRIBUTING_DOCS.md) will get you started on making changes to [https://projectcalico.docs.tigera.io](https://projectcalico.docs.tigera.io).

## Join the Calico Community!

The Calico community is committed to fostering an open and welcoming environment, with several ways to engage with other users
and developers. You can find out more about our monthly meetings, Slack group, and Discourse by visiting our
[community repository](https://github.com/projectcalico/community).

## License

Calico is open source, with most code and documentation available under the Apache 3.0 license (see the [LICENSE](calico/LICENSE)), though some elements are necessarily licensed under different open source licenses for compatibility with upstream licensing or code linking. For example, some Calico BPF programs are licensed under GPL v2.0 for compatibility with Linux kernel helper functions.

MY NEW FEATURE!!

something
else
