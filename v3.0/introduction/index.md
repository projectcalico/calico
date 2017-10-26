---
title: About Calico
---

Calico provides secure network connectivity for 
containers and virtual machine workloads.

Calico creates and manages a flat layer 3 network, 
assigning each workload a fully routable IP address. 
Workloads can communicate without IP encapsulation 
or network address translation for bare metal 
performance, easier troubleshooting, and better 
interoperability. In environments that require an 
overlay, Calico uses IP-in-IP tunneling or can work 
with other overlay networking such as flannel.

Calico also provides dynamic enforcement of network 
security rules. Using Calico's simple policy language, 
you can achieve fine-grained control over communications 
between containers, virtual machine workloads, and 
bare metal host endpoints.

Proven in production at scale, Calico v3.0 features 
integration with Kubernetes.

> **Note**: For integrations with the OpenShift, OpenStack, 
> Mesos, DC/OS, and Docker orchestrators, use
> [Calico v2.6](/v2.6/introduction/). We plan 
> to resume support for these orchestrators in a future 
> v3.x release.
{: .alert .alert-info}

<a href="/{{page.version}}/getting-started/" class="btn btn-primary btn-lg">Get started</a>