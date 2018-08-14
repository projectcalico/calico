---
title: About Calico
canonical_url: 'https://docs.projectcalico.org/v3.2/introduction/'
---

{{site.prodname}} provides secure network connectivity for
containers and virtual machine workloads.

{{site.prodname}} creates and manages a flat layer 3 network,
assigning each workload a fully routable IP address.
Workloads can communicate without IP encapsulation
or network address translation for bare metal
performance, easier troubleshooting, and better
interoperability. In environments that require an
overlay, {{site.prodname}} uses IP-in-IP tunneling or can work
with other overlay networking such as flannel.

{{site.prodname}} also provides dynamic enforcement of network
security rules. Using {{site.prodname}}'s simple policy language,
you can achieve fine-grained control over communications
between containers, virtual machine workloads, and
bare metal host endpoints.

Proven in production at scale, {{site.prodname}} {{page.version}} features
integrations with Kubernetes, OpenShift, and OpenStack.

> **Note**: For integrations with the  Mesos, DC/OS, and Docker
> orchestrators, use [Calico v2.6](/v2.6/introduction/). We plan
> to resume support for these orchestrators in a future
> v3.x release.
{: .alert .alert-info}

# Get started

<div class="row">
  <div class="col-xs-6 col-md-3">
    <a href="/{{page.version}}/getting-started/kubernetes/" class="thumbnail">
      <img src="{{site.baseurl}}/images/kubernetes-button.svg" alt="Kubernetes" width="40%">
    </a>
  </div>
  <div class="col-xs-6 col-md-3">
    <a href="/{{page.version}}/getting-started/openshift/installation" class="thumbnail">
      <img src="{{site.baseurl}}/images/openshift-button.svg" alt="OpenShift" width="35%">
    </a>
  </div>
  <div class="col-xs-6 col-md-3">
    <a href="/{{page.version}}/getting-started/openstack/" class="thumbnail">
      <img src="{{site.baseurl}}/images/openstack-button.svg" alt="OpenStack" width="40%">
    </a>
  </div>
</div>


# How it works

![{{site.prodname}} overview diagram]({{site.baseurl}}/images/calico-arch-gen-v3.2.svg){: width="65%" }

<br>
{{site.prodname}} leverages the routing and iptables firewall capabilities native to the Linux kernel. All traffic to and from individual containers, virtual machines, and hosts traverses these in-kernel rules before being routed to its destination.

- **`calicoctl`**: allows you to achieve advanced policies and networking from a simple, command-line interface.

- **orchestrator plugins**: provide close integration and synchronization with a variety of popular orchestrators.

- **key/value store**: holds {{site.prodname}}'s policy and network configuration state.

- **``{{site.nodecontainer}}``**: runs on each host, reads relevant policy and network configuration information from the key/value store, and implements it in the Linux kernel.

- **Dikastes/Envoy**: optional Kubernetes sidecars that secure workload-to-workload communications with mutual TLS authentication and enforce application layer policy.
