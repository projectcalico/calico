---
title: Releases
sitemap: false 
---

The following table shows component versioning for Calico  **{{ page.version }}**.

Use the version selector at the top-right of this page to view a different release.


## v2.0.2 - Release Notes

This is a bug fix release.  A summary of the major fixes:

- Various fixes to the Kubernetes datastore driver.
- Fix leaked IPs in Calico CNI plugin when using host-local IPAM with usePodCidr.

View release notes for the following components below for more information:

| Component                     | Version                                                                                    |
|-------------------------------|--------------------------------------------------------------------------------------------|
| felix                         | [2.0.3](https://github.com/projectcalico/felix/releases/tag/2.0.3)                         |
| calicoctl                     | [v1.0.2](https://github.com/projectcalico/calicoctl/releases/tag/v1.0.2)                   |
| calico/node                   | [v1.0.2](https://github.com/projectcalico/calicoctl/releases/tag/v1.0.2)                   |
| calico/cni                    | [v1.5.6](https://github.com/projectcalico/cni-plugin/releases/tag/v1.5.6)                  |
| libcalico                     | [v0.19.0](https://github.com/projectcalico/libcalico/releases/tag/v0.19.0)                 |
| libcalico-go                  | [v1.0.2](https://github.com/projectcalico/libcalico-go/releases/tag/v1.0.2)                |
| calico-bird                   | [v0.2.0](https://github.com/projectcalico/calico-bird/releases/tag/v0.2.0)                 |
| calico-bgp-daemon             | [v0.1.1](https://github.com/projectcalico/calico-bgp-daemon/releases/tag/v0.1.1)           |
| libnetwork-plugin             | [v1.0.0](https://github.com/projectcalico/libnetwork-plugin/releases/tag/v1.0.0)           |
| calico/kube-policy-controller | [v0.5.2](https://github.com/projectcalico/k8s-policy/releases/tag/v0.5.2)                  |
| networking-calico             | [889cfff](http://git.openstack.org/cgit/openstack/networking-calico/tree/?id=889cfff)      |


## v2.0.1 - Release Notes

This is a bug fix release.  A summary of the major fixes:

- Fix issue where labels with multiple slashes were not respected.
- Fix log spam in policy controller when no NetworkPolicies are defined.
- Fix graceful restart behavior when IPIP is enabled.
- Fix ipv4_nat not working for floating IPs.
- Fix log spam when we fail to remove routes from a deleted interface.

View release notes for the following components below for more information:

| Component                     | Version                                                                                    |
|-------------------------------|--------------------------------------------------------------------------------------------|
| felix                         | [2.0.2](https://github.com/projectcalico/felix/releases/tag/2.0.2)                         |
| calicoctl                     | [v1.0.1](https://github.com/projectcalico/calicoctl/releases/tag/v1.0.1)           |
| calico/node                   | [v1.0.1](https://github.com/projectcalico/calicoctl/releases/tag/v1.0.1)           |
| calico/cni                    | [v1.5.5](https://github.com/projectcalico/cni-plugin/releases/tag/v1.5.5)                  |
| libcalico                     | [v0.19.0](https://github.com/projectcalico/libcalico/releases/tag/v0.19.0)                 |
| libcalico-go                  | [v1.0.1](https://github.com/projectcalico/libcalico-go/releases/tag/v1.0.1)                |
| calico-bird                   | [v0.2.0](https://github.com/projectcalico/calico-bird/releases/tag/v0.2.0)                 |
| calico-bgp-daemon             | [v0.1.1](https://github.com/projectcalico/calico-bgp-daemon/releases/tag/v0.1.1)           |
| libnetwork-plugin             | [v1.0.0](https://github.com/projectcalico/libnetwork-plugin/releases/tag/v1.0.0)           |
| calico/kube-policy-controller | [v0.5.2](https://github.com/projectcalico/k8s-policy/releases/tag/v0.5.2)                  |
| networking-calico             | [889cfff](http://git.openstack.org/cgit/openstack/networking-calico/tree/?id=889cfff)      |


## v2.0.0 - Release Notes

- The calicoctl command line tool has been updated to provide an
[object-oriented resource focused UX]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands).
- For Kubernetes deployments, Calico now has the option of
[using the Kubernetes API server as its backend datastore]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/hosted/k8s-backend/) instead of etcd. Under the covers, this is
implemented using a new pluggable datastore API introduced in libcalico-go.
- Improved Felix startup performance, particularly around resync, graceful restart, and catch-up behavior.
- Improved packaging that now vendors our dependencies; removes potential Python dependency issues such as incompatible urllib3/requests versions
- Felix introduces a new dataplane driver API, which will allow for non-iptables
dataplanes in the future.
- For pure Go enthusiasts, Calico now has experimental support for swapping out
the C++ based BIRD BGP implementation with GoBGP instead.
- Many of Calico's components have been ported from Python to Go, including:
calicoctl, libcalico (as libcalico-go), calico-cni, libnetwork-plugin, most of
Felix, and parts of calico/node. This port brings with it improved performance
and better alignment with many of the projects within the container ecosystem
(e.g. Calico now uses the native APIs for kubernetes, etcd, and Prometheus directly).

And more! View release notes for the following components below for more information:

| Component                     | Version                                                                                    |
|-------------------------------|--------------------------------------------------------------------------------------------|
| felix                         | [2.0.0](https://github.com/projectcalico/felix/releases/tag/2.0.0)                         |
| calicoctl                     | [v1.0.0](https://github.com/projectcalico/calicoctl/releases/tag/v1.0.0)                   |
| calico/node                   | [v1.0.0](https://github.com/projectcalico/calicoctl/releases/tag/v1.0.0)                   |
| calico/cni                    | [v1.5.5](https://github.com/projectcalico/calico-cni/releases/tag/v1.5.5)                  |
| libcalico                     | [v0.19.0](https://github.com/projectcalico/libcalico/releases/tag/v0.19.0)                 |
| libcalico-go                  | [v1.0.0](https://github.com/projectcalico/libcalico-go/releases/tag/v1.0.0)                |
| calico-bird                   | [v0.2.0](https://github.com/projectcalico/calico-bird/releases/tag/v0.2.0)                 |
| calico-bgp-daemon             | [v0.1.1](https://github.com/projectcalico/calico-bgp-daemon/releases/tag/v0.1.1)           |
| libnetwork-plugin             | [v1.0.0](https://github.com/projectcalico/libnetwork-plugin/releases/tag/v1.0.0)           |
| calico/kube-policy-controller | [v0.5.1](https://github.com/projectcalico/k8s-policy/releases/tag/v0.5.1)                  |
| networking-calico             | [889cfff](http://git.openstack.org/cgit/openstack/networking-calico/tree/?id=889cfff)      |


## v2.0.0-rc3

| Component                     | Version                                                                                    |
|-------------------------------|--------------------------------------------------------------------------------------------|
| felix                         | [2.0.0-rc7](https://github.com/projectcalico/felix/releases/tag/2.0.0-rc7)                 |
| calicoctl                     | [v1.0.0-rc4](https://github.com/projectcalico/calicoctl/releases/tag/v1.0.0-rc2)           |
| calico/node                   | [v1.0.0-rc4](https://github.com/projectcalico/calicoctl/releases/tag/v1.0.0-rc2)           |
| calico/cni                    | [v1.5.4](https://github.com/projectcalico/calico-cni/releases/tag/v1.5.4)                  |
| libcalico                     | [v0.19.0](https://github.com/projectcalico/libcalico/releases/tag/v0.19.0)                 |
| libcalico-go                  | [v1.0.0-rc6](https://github.com/projectcalico/libcalico-go/releases/tag/v1.0.0-rc6)        |
| calico-bird                   | [v0.2.0](https://github.com/projectcalico/calico-bird/releases/tag/v0.2.0)                 |
| calico-bgp-daemon             | [v0.1.1-rc3](https://github.com/projectcalico/calico-bgp-daemon/releases/tag/v0.1.1-rc3)   |
| libnetwork-plugin             | [v1.0.0-rc4](https://github.com/projectcalico/libnetwork-plugin/releases/tag/v1.0.0-rc4)   |
| calico/kube-policy-controller | [v0.5.1](https://github.com/projectcalico/k8s-policy/releases/tag/v0.5.1)                  |
| networking-calico             | [889cfff](http://git.openstack.org/cgit/openstack/networking-calico/tree/?id=889cfff)      |

## v2.0.0-rc2

| Component                     | Version                                                                                    |
|-------------------------------|--------------------------------------------------------------------------------------------|
| felix                         | [2.0.0-rc4](https://github.com/projectcalico/felix/releases/tag/2.0.0-rc4)                 |
| calicoctl                     | [v1.0.0-rc2](https://github.com/projectcalico/calicoctl/releases/tag/v1.0.0-rc2)           |
| calico/node                   | [v1.0.0-rc2](https://github.com/projectcalico/calicoctl/releases/tag/v1.0.0-rc2)           |
| calico/cni                    | [v1.5.3](https://github.com/projectcalico/calico-cni/releases/tag/v1.5.3)                  |
| libcalico                     | [v0.19.0](https://github.com/projectcalico/libcalico/releases/tag/v0.19.0)                 |
| libcalico-go                  | [v1.0.0-rc4](https://github.com/projectcalico/libcalico-go/releases/tag/v1.0.0-rc4)        |
| calico-bird                   | [v0.2.0-rc1](https://github.com/projectcalico/calico-bird/releases/tag/v0.2.0-rc1)         |
| calico-bgp-daemon             | [v0.1.1-rc2](https://github.com/projectcalico/calico-bgp-daemon/releases/tag/v0.1.1-rc2)   |
| libnetwork-plugin             | [v1.0.0-rc3](https://github.com/projectcalico/libnetwork-plugin/releases/tag/v1.0.0-rc3)   |
| calico/kube-policy-controller | [v0.5.1](https://github.com/projectcalico/k8s-policy/releases/tag/v0.5.1)                  |
| networking-calico             | [889cfff](http://git.openstack.org/cgit/openstack/networking-calico/tree/?id=889cfff)      |

## v2.0.0-beta

| Component                     | Version                                                                                    |
|-------------------------------|--------------------------------------------------------------------------------------------|
| felix                         | [2.0.0-beta.3](https://github.com/projectcalico/felix/releases/tag/2.0.0-beta.3)           |
| calicoctl                     | [v1.0.0-beta](https://github.com/projectcalico/calicoctl/releases/tag/v1.0.0-beta)         |
| calico/node                   | [v1.0.0-beta](https://github.com/projectcalico/calicoctl/releases/tag/v1.0.0-beta)         |
| calico/cni                    | [v1.5.0](https://github.com/projectcalico/calico-cni/releases/tag/v1.5.0)                  |
| libcalico                     | [v0.18.0](https://github.com/projectcalico/libcalico/releases/tag/v0.18.0)                 |
| libcalico-go                  | [v1.0.0-beta](https://github.com/projectcalico/libcalico-go/releases/tag/v1.0.0-beta)      |
| calico-bird                   | [v0.1.0](https://github.com/projectcalico/calico-bird/releases/tag/v0.1.0)                 |
| calico-bgp-daemon             | [v0.1.0](https://github.com/projectcalico/calico-bgp-daemon/releases/tag/v0.1.0)           |
| libnetwork-plugin             | [v1.0.0-beta](https://github.com/projectcalico/libnetwork-plugin/releases/tag/v1.0.0-beta) |
| calico/kube-policy-controller | [v0.5.0](https://github.com/projectcalico/k8s-policy/releases/tag/v0.5.0)                  |
| networking-calico             | [889cfff](http://git.openstack.org/cgit/openstack/networking-calico/tree/?id=889cfff)      |

To see detailed release notes for each component, please click on the relevant
version just above.
