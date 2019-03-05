---
title: Releases
---

The following table shows component versioning for Calico  **{{ page.version }}**.

Use the version selector at the top-right of this page to view a different release.

## v1.6.1

This release includes the following bugfixes:

- Felix ([v1.4.6](https://github.com/projectcalico/felix/releases/tag/1.4.6)):
  - Fix that packets weren't properly policed when there were multiple interface prefixes.
  - If an interface is down, make sure we remove its routes.
  - Do floating IP DNATs from OUTPUT as well as from PREROUTING
- Calico CNI ([v1.4.4](https://github.com/projectcalico/cni-plugin/releases/tag/v1.4.4))
  - This includes libcalico-go ([v1.0.0-alpha.2](https://github.com/projectcalico/libcalico-go/releases/tag/v1.0.0-alpha.2)) for various IPAM related bugfixes:
  - Hashing IP block allocation based on hostname (https://github.com/projectcalico/libcalico-go/pull/295)
  - Fix for "failed to unmarshal" errors (https://github.com/projectcalico/libcalico-go/pull/301)
  - Few IP block affinity related bugsfixes (https://github.com/projectcalico/libcalico-go/pull/211)

| Component                     | Version                                                                         |
|-------------------------------+---------------------------------------------------------------------------------|
| felix                         | [v1.4.6](https://github.com/projectcalico/felix/releases/tag/1.4.6)             |
| calicoctl                     | [v0.23.1](https://github.com/projectcalico/calicoctl/releases/tag/v0.23.1)      |
| calico/node                   | [v0.23.1](https://github.com/projectcalico/calicoctl/releases/tag/v0.23.1)      |
| calico/cni                    | [v1.4.4](https://github.com/projectcalico/calico-cni/releases/tag/v1.4.4)       |
| libcalico                     | [v0.18.0](https://github.com/projectcalico/libcalico/releases/tag/v0.18.0)      |
| calico-bird                   | [v0.1.0](https://github.com/projectcalico/calico-bird/releases/tag/v0.1.0)      |
| libnetwork-plugin             | [v0.10.0](https://github.com/projectcalico/libnetwork-plugin/releases/tag/v0.10.0)|
| calico/kube-policy-controller | [v0.4.0](https://github.com/projectcalico/k8s-policy/releases/tag/v0.4.0)       |
| networking-calico             | [1.3.1](http://git.openstack.org/cgit/openstack/networking-calico/tag/?h=1.3.1) |


## v1.6.0

| Component                     | Version                                                                         |
|-------------------------------+---------------------------------------------------------------------------------|
| felix                         | [v1.4.4](https://github.com/projectcalico/felix/releases/tag/1.4.4)             |
| calicoctl                     | [v0.23.0](https://github.com/projectcalico/calicoctl/releases/tag/v0.23.0)      |
| calico/node                   | [v0.23.0](https://github.com/projectcalico/calicoctl/releases/tag/v0.23.0)      |
| calico/cni                    | [v1.4.3](https://github.com/projectcalico/calico-cni/releases/tag/v1.4.3)       |
| libcalico                     | [v0.18.0](https://github.com/projectcalico/libcalico/releases/tag/v0.18.0)      |
| calico-bird                   | [v0.1.0](https://github.com/projectcalico/calico-bird/releases/tag/v0.1.0)      |
| libnetwork-plugin             | [v0.10.0](https://github.com/projectcalico/libnetwork-plugin/releases/tag/v0.10.0)|
| calico/kube-policy-controller | [v0.4.0](https://github.com/projectcalico/k8s-policy/releases/tag/v0.4.0)       |
| networking-calico             | [1.3.1](http://git.openstack.org/cgit/openstack/networking-calico/tag/?h=1.3.1) |
