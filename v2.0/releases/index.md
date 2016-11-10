---
title: Releases
---

The following table shows component versioning for Calico  **{{ page.version }}**.

Use the version selector at the top-right of this page to view a different release.

## v2.0.0-beta

| Component                     | Version                                                                                    |
|-------------------------------+--------------------------------------------------------------------------------------------|
| felix                         | [2.0.0-beta.3](https://github.com/projectcalico/felix/releases/tag/2.0.0-beta.3)           |
| calicoctl                     | [v1.0.0-beta](https://github.com/projectcalico/calico-containers/releases/tag/v1.0.0-beta) |
| calico/node                   | [v1.0.0-beta](https://github.com/projectcalico/calico-containers/releases/tag/v1.0.0-beta) |
| calico/cni                    | [v1.5.0](https://github.com/projectcalico/calico-cni/releases/tag/v1.5.0)                  |
| libcalico                     | [v0.18.0](https://github.com/projectcalico/libcalico/releases/tag/v0.18.0)                 |
| libcalico-go                  | [v1.0.0-beta](https://github.com/projectcalico/libcalico-go/releases/tag/v1.0.0-beta)      |
| calico-bird                   | [v0.1.0](https://github.com/projectcalico/calico-bird/releases/tag/v0.1.0)                 |
| libnetwork-plugin             | [v1.0.0-beta](https://github.com/projectcalico/libnetwork-plugin/releases/tag/v1.0.0-beta) |
| calico/kube-policy-controller | [v0.5.0](https://github.com/projectcalico/k8s-policy/releases/tag/v0.5.0)                  |

To see detailed release notes for each component, please click on the relevant
version just above.

### Calico with OpenStack

For Calico with OpenStack we provide Debian packages for Ubuntu Trusty and
Xenial, and RPM packages for Centos 7 or RHEL 7.

For Calico 2.0.0-beta the PPA for Ubuntu packages is
`ppa:project-calico/calico-2.0.0-beta` and you can see the packages in that PPA
at
[https://launchpad.net/~project-calico/+archive/ubuntu/calico-2.0.0-beta](https://launchpad.net/~project-calico/+archive/ubuntu/calico-2.0.0-beta).
RPM packages are provided by an exactly corresponding RPM repository at
http://binaries.projectcalico.org/rpm/calico-2.0.0-beta/.
